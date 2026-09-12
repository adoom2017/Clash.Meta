//! TLS record I/O without socket read-ahead. Vision can switch each direction
//! independently after a padding block, without losing prefetched raw bytes.
use std::{
    io::{self, Read, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct RecordStream<S> {
    socket: S,
    tls: Option<rustls::ClientConnection>,
    incoming: Vec<u8>,
    need: usize,
    outgoing: Vec<u8>,
    sent: usize,
    read_direct: bool,
    write_direct: bool,
    eof: bool,
}
impl<S: AsyncRead + AsyncWrite + Unpin> RecordStream<S> {
    pub fn plain(socket: S) -> Self {
        Self {
            socket,
            tls: None,
            incoming: vec![],
            need: 5,
            outgoing: vec![],
            sent: 0,
            read_direct: true,
            write_direct: true,
            eof: false,
        }
    }
    pub async fn handshake(
        socket: S,
        config: Arc<rustls::ClientConfig>,
        name: rustls::pki_types::ServerName<'static>,
    ) -> anyhow::Result<Self> {
        let mut stream = Self {
            socket,
            tls: Some(rustls::ClientConnection::new(config, name)?),
            incoming: Vec::with_capacity(18437),
            need: 5,
            outgoing: vec![],
            sent: 0,
            read_direct: false,
            write_direct: false,
            eof: false,
        };
        std::future::poll_fn(|cx| {
            loop {
                ready!(stream.flush_records(cx))?;
                if !stream.tls.as_ref().unwrap().is_handshaking() {
                    return Poll::Ready(Ok::<_, io::Error>(()));
                }
                if !ready!(stream.read_record(cx))? {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
            }
        })
        .await?;
        Ok(stream)
    }
    pub fn tls13(&self) -> bool {
        self.tls
            .as_ref()
            .is_some_and(|c| c.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3))
    }
    pub fn read_direct(&mut self) {
        self.read_direct = true;
    }
    /// Call only after flushing the final encrypted write.
    pub fn write_direct(&mut self) {
        self.write_direct = true;
    }
    fn flush_records(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            while self.sent < self.outgoing.len() {
                let n =
                    ready!(Pin::new(&mut self.socket).poll_write(cx, &self.outgoing[self.sent..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                self.sent += n;
            }
            self.outgoing.clear();
            self.sent = 0;
            if let Some(tls) = &mut self.tls
                && tls.wants_write()
            {
                tls.write_tls(&mut self.outgoing)?;
                continue;
            }
            return Pin::new(&mut self.socket).poll_flush(cx);
        }
    }
    fn read_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            while self.incoming.len() < self.need {
                let start = self.incoming.len();
                self.incoming.resize(self.need, 0);
                let mut buf = ReadBuf::new(&mut self.incoming[start..]);
                let result = Pin::new(&mut self.socket).poll_read(cx, &mut buf);
                let n = buf.filled().len();
                self.incoming.truncate(start + n);
                ready!(result)?;
                if n == 0 {
                    self.eof = true;
                    if start != 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    return Poll::Ready(Ok(false));
                }
            }
            if self.need == 5 {
                let payload = u16::from_be_bytes([self.incoming[3], self.incoming[4]]) as usize;
                if payload > 18432 {
                    return Poll::Ready(Err(io::Error::other("oversized TLS record")));
                }
                self.need = 5 + payload;
                if self.incoming.len() < self.need {
                    continue;
                }
            }
            let tls = self.tls.as_mut().unwrap();
            let mut record = self.incoming.as_slice();
            // rustls may consume only part of a record while growing its
            // deframer buffer. Preserve and feed the unconsumed ciphertext.
            while !record.is_empty() {
                if tls.read_tls(&mut record)? == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                tls.process_new_packets().map_err(io::Error::other)?;
            }
            self.incoming.clear();
            self.need = 5;
            return Poll::Ready(Ok(true));
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RecordStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            // Drain all plaintext in the last TLS record before switching raw.
            if let Some(tls) = &mut this.tls {
                match tls.reader().read(buf.initialize_unfilled()) {
                    Ok(n) if n > 0 => {
                        buf.advance(n);
                        return Poll::Ready(Ok(()));
                    }
                    Ok(_) => {
                        if !this.read_direct {
                            return Poll::Ready(Ok(()));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
            if this.read_direct {
                return Pin::new(&mut this.socket).poll_read(cx, buf);
            }
            if this.eof {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            // A peer may be blocked writing while our write buffer is full.
            // Keep reads progressing when flushing yields Pending.
            if let Poll::Ready(Err(error)) = this.flush_records(cx) {
                return Poll::Ready(Err(error));
            }
            if !ready!(this.read_record(cx))? {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RecordStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.flush_records(cx))?;
        if this.write_direct {
            return Pin::new(&mut this.socket).poll_write(cx, bytes);
        }
        Poll::Ready(
            this.tls
                .as_mut()
                .unwrap()
                .writer()
                .write(&bytes[..bytes.len().min(16384)]),
        )
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().flush_records(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_direct {
            if let Some(tls) = &mut this.tls {
                tls.send_close_notify();
            }
            this.write_direct = true;
        }
        ready!(this.flush_records(cx))?;
        Pin::new(&mut this.socket).poll_shutdown(cx)
    }
}
