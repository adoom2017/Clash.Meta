//! VLESS v0 wire encoding, owned by this repository.
use crate::{BoxStream, Datagram, Target};
use anyhow::{Result, ensure};
use async_trait::async_trait;
use std::{
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub async fn connect<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    socket: S,
    proxy: &meta_config::Proxy,
    target: &Target,
    command: u8,
) -> Result<BoxStream> {
    connect_with_options(
        socket,
        proxy,
        target,
        command,
        "chrome",
        std::sync::Arc::new(crate::tls::Clock::default()),
    )
    .await
}
pub async fn connect_with_options<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    socket: S,
    proxy: &meta_config::Proxy,
    target: &Target,
    command: u8,
    default_profile: &str,
    clock: std::sync::Arc<crate::tls::Clock>,
) -> Result<BoxStream> {
    use anyhow::Context as _;
    ensure!(
        proxy.kind == meta_config::ProxyKind::Vless,
        "expected VLESS proxy"
    );
    ensure!(
        proxy.flow.is_empty() || proxy.flow == "xtls-rprx-vision",
        "unsupported VLESS flow"
    );
    ensure!(
        proxy.flow.is_empty() || command != 2,
        "Vision UDP requires XUDP command 3"
    );
    let id = proxy.uuid.context("VLESS uuid missing")?;
    let header = request(id, target, command, &proxy.flow)?;
    let socket: BoxStream = Box::new(socket);
    let secure = proxy.tls || proxy.reality_opts.is_some();
    let name = proxy
        .servername
        .as_deref()
        .or(proxy.sni.as_deref())
        .unwrap_or(&proxy.server)
        .to_owned();
    let fingerprint = crate::tls::TlsFingerprint::parse(
        proxy
            .client_fingerprint
            .as_deref()
            .unwrap_or(default_profile),
    )?;
    let alpn = match proxy.network.as_str() {
        "ws" => vec!["http/1.1".into()],
        "grpc" => vec!["h2".into()],
        _ => proxy.alpn.clone(),
    };
    let tls = crate::tls::TlsConnectConfig {
        server_name: name,
        alpn,
        verify_cert: !proxy.skip_cert_verify,
        fingerprint,
        reality: proxy.reality_opts.clone(),
    };
    tracing::debug!(
        transport = proxy.network,
        flow = proxy.flow,
        tls = proxy.tls,
        reality = proxy.reality_opts.is_some(),
        skip_cert_verify = proxy.skip_cert_verify,
        "connecting VLESS transport"
    );
    if proxy.flow == "xtls-rprx-vision" {
        ensure!(
            proxy.network == "tcp" && secure,
            "Vision requires TCP with TLS 1.3"
        );
        let mut stream = crate::tls::SecureConnector::new(clock)
            .connect_xtls(socket, &tls)
            .await?;
        ensure!(stream.tls13(), "Vision requires outer TLS 1.3");
        stream.write_all(&header).await?;
        stream.flush().await?;
        return Ok(Box::new(crate::vision::VisionStream::new(stream, id)?));
    }
    let connector = crate::tls::SecureConnector::new(clock);
    let mut stream = if secure {
        connector.connect(socket, &tls).await?
    } else {
        socket
    };
    let authority = Target::new(&proxy.server, proxy.port)?.to_string();
    let mut consumed = 0;
    match proxy.network.as_str() {
        "tcp" => {}
        "ws" => {
            let connected =
                crate::websocket::connect(stream, &authority, &proxy.ws_opts, &header).await?;
            stream = connected.0;
            consumed = connected.1;
        }
        "grpc" => {
            stream = crate::grpc::connect(stream, &authority, &proxy.grpc_opts, secure).await?;
        }
        _ => anyhow::bail!("unsupported VLESS network: {}", proxy.network),
    }
    stream.write_all(&header[consumed..]).await?;
    stream.flush().await?;
    Ok(Box::new(ResponseStream::new(stream)))
}

pub fn request(id: uuid::Uuid, target: &Target, command: u8, flow: &str) -> Result<Vec<u8>> {
    ensure!([1, 2, 3].contains(&command), "invalid VLESS command");
    let mut out = vec![0];
    out.extend_from_slice(id.as_bytes());
    if flow.is_empty() {
        out.push(0);
    } else {
        ensure!(flow.len() <= 127, "VLESS flow too long");
        out.extend_from_slice(&[(flow.len() + 2) as u8, 0x0a, flow.len() as u8]);
        out.extend_from_slice(flow.as_bytes());
    }
    out.push(command);
    if command != 3 {
        encode_address(target, &mut out)?;
    }
    Ok(out)
}

pub(crate) fn encode_address(target: &Target, out: &mut Vec<u8>) -> Result<()> {
    Target::new(&target.host, target.port)?;
    out.extend_from_slice(&target.port.to_be_bytes());
    match target.ip() {
        Some(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            out.push(3);
            out.extend_from_slice(&ip.octets());
        }
        None => {
            out.extend_from_slice(&[2, target.host.len() as u8]);
            out.extend_from_slice(target.host.as_bytes());
        }
    }
    Ok(())
}

pub(crate) fn decode_address(bytes: &[u8]) -> Result<(Target, usize)> {
    ensure!(bytes.len() >= 3, "truncated VLESS address");
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let (host, end) = match bytes[2] {
        1 => {
            ensure!(bytes.len() >= 7, "truncated IPv4 address");
            (
                std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[3..7])?).to_string(),
                7,
            )
        }
        3 => {
            ensure!(bytes.len() >= 19, "truncated IPv6 address");
            (
                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[3..19])?).to_string(),
                19,
            )
        }
        2 => {
            ensure!(bytes.len() >= 4, "truncated domain length");
            let end = 4 + bytes[3] as usize;
            ensure!(bytes.len() >= end, "truncated domain");
            (std::str::from_utf8(&bytes[4..end])?.to_owned(), end)
        }
        _ => anyhow::bail!("invalid VLESS address type"),
    };
    Ok((Target::new(host, port)?, end))
}

/// Lazily read the response: a server may wait for application data before replying.
pub struct ResponseStream<S> {
    inner: S,
    header: [u8; 2],
    header_read: usize,
    discard: usize,
    ready: bool,
    failed: bool,
}
impl<S> ResponseStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; 2],
            header_read: 0,
            discard: 0,
            ready: false,
            failed: false,
        }
    }
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for ResponseStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.failed {
            return Poll::Ready(Err(std::io::Error::other("invalid VLESS response")));
        }
        while this.header_read < 2 {
            let mut b = ReadBuf::new(&mut this.header[this.header_read..]);
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut b))?;
            if b.filled().is_empty() {
                return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
            }
            this.header_read += b.filled().len();
            if this.header_read == 2 {
                if this.header[0] != 0 {
                    this.failed = true;
                    return Poll::Ready(Err(std::io::Error::other(
                        "unsupported VLESS response version",
                    )));
                }
                this.discard = this.header[1] as usize;
            }
        }
        while !this.ready && this.discard != 0 {
            let mut scratch = [0; 255];
            let mut b = ReadBuf::new(&mut scratch[..this.discard]);
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut b))?;
            if b.filled().is_empty() {
                return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
            }
            this.discard -= b.filled().len();
        }
        this.ready = true;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ResponseStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct UdpSession {
    target: Target,
    reader: tokio::sync::Mutex<(tokio::io::ReadHalf<BoxStream>, bool)>,
    writer: tokio::sync::Mutex<(tokio::io::WriteHalf<BoxStream>, bool)>,
}
impl UdpSession {
    pub fn new(stream: BoxStream, target: Target) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            target,
            reader: (reader, true).into(),
            writer: (writer, true).into(),
        }
    }
}
#[async_trait]
impl Datagram for UdpSession {
    async fn send(&self, target: &Target, bytes: &[u8]) -> Result<()> {
        ensure!(target == &self.target, "VLESS UDP session target changed");
        ensure!(bytes.len() <= 65507, "UDP payload exceeds limit");
        let mut writer = self.writer.lock().await;
        ensure!(writer.1, "VLESS UDP writer interrupted or closed");
        writer.1 = false;
        let w = &mut writer.0;
        w.write_u16(bytes.len() as u16).await?;
        w.write_all(bytes).await?;
        w.flush().await?;
        writer.1 = true;
        Ok(())
    }
    async fn recv(&self) -> Result<(Target, Vec<u8>)> {
        let mut reader = self.reader.lock().await;
        ensure!(reader.1, "VLESS UDP reader interrupted or closed");
        reader.1 = false;
        let r = &mut reader.0;
        let n = r.read_u16().await? as usize;
        ensure!(n <= 65507, "UDP payload exceeds limit");
        let mut b = vec![0; n];
        r.read_exact(&mut b).await?;
        reader.1 = true;
        Ok((self.target.clone(), b))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn golden_request() {
        let req = request(
            uuid::Uuid::nil(),
            &Target::new("1.2.3.4", 443).unwrap(),
            1,
            "",
        )
        .unwrap();
        assert_eq!(&req[17..], &[0, 1, 1, 187, 1, 1, 2, 3, 4]);
    }
    #[tokio::test]
    async fn fragmented_response_and_eof() {
        let (mut tx, rx) = tokio::io::duplex(1);
        let task = tokio::spawn(async move {
            tx.write_all(&[0, 2, 9, 9, 42]).await.unwrap();
        });
        let mut stream = ResponseStream::new(rx);
        assert_eq!(stream.read_u8().await.unwrap(), 42);
        task.await.unwrap();
    }
    #[test]
    fn address_roundtrips_and_truncated_input() {
        for host in ["1.2.3.4", "2001:db8::1", "example.com"] {
            let target = Target::new(host, 443).unwrap();
            let mut encoded = vec![];
            encode_address(&target, &mut encoded).unwrap();
            assert_eq!(decode_address(&encoded).unwrap(), (target, encoded.len()));
            for end in 0..encoded.len() {
                assert!(decode_address(&encoded[..end]).is_err());
            }
        }
        for bytes in [
            vec![0, 0, 1, 1, 2, 3, 4],
            vec![0, 53, 9],
            vec![0, 53, 2, 0],
            vec![0, 53, 2, 1, 255],
        ] {
            assert!(decode_address(&bytes).is_err());
        }
        let request = request(
            uuid::Uuid::nil(),
            &Target::new("example.com", 53).unwrap(),
            3,
            "xtls-rprx-vision",
        )
        .unwrap();
        assert_eq!(&request[17..], b"\x12\x0a\x10xtls-rprx-vision\x03");
    }
    #[tokio::test]
    async fn malformed_response_cannot_be_retried_as_payload() {
        for bytes in [vec![], vec![0], vec![0, 2, 9], vec![1, 0, 42]] {
            let mut stream = ResponseStream::new(bytes.as_slice());
            assert!(stream.read_u8().await.is_err());
            assert!(stream.read_u8().await.is_err());
        }
    }
}
