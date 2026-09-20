//! Mihomo gRPC Gun transport over HTTP/2.
use crate::BoxStream;
use anyhow::{Result, ensure};
use bytes::{Buf, Bytes};
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

fn varint(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn decode_varint(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    for (i, byte) in bytes.iter().copied().take(10).enumerate() {
        value |= usize::from(byte & 0x7f) << (i * 7);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

fn gun_frame(payload: &[u8]) -> Bytes {
    let mut proto = Vec::with_capacity(payload.len() + 10);
    proto.push(0x0a);
    varint(payload.len(), &mut proto);
    proto.extend_from_slice(payload);
    let mut frame = Vec::with_capacity(proto.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(proto.len() as u32).to_be_bytes());
    frame.extend(proto);
    Bytes::from(frame)
}

#[derive(Clone)]
struct Physical {
    sender: h2::client::SendRequest<Bytes>,
    active: Arc<AtomicUsize>,
}
static POOL: OnceLock<Mutex<HashMap<String, Vec<Physical>>>> = OnceLock::new();

fn key(authority: &str, options: &meta_config::GrpcOptions, secure: bool) -> String {
    format!(
        "{secure}|{authority}|{}|{}|{}",
        options.grpc_service_name, options.grpc_user_agent, options.ping_interval
    )
}

fn pooled(key: &str, options: &meta_config::GrpcOptions) -> Option<Physical> {
    let pool = POOL.get_or_init(Default::default);
    let mut map = pool.lock().unwrap();
    let list = map.get_mut(key)?;
    let least = list
        .iter()
        .min_by_key(|entry| entry.active.load(Ordering::Relaxed))?;
    let load = least.active.load(Ordering::Relaxed);
    let default_single =
        options.max_connections == 0 && options.min_streams == 0 && options.max_streams == 0;
    let create = if default_single {
        false
    } else if options.max_connections > 0 {
        load >= options.min_streams && list.len() < options.max_connections
    } else {
        options.max_streams > 0 && load >= options.max_streams
    };
    (!create).then(|| least.clone())
}

pub async fn connect(
    stream: BoxStream,
    authority: &str,
    options: &meta_config::GrpcOptions,
    secure: bool,
) -> Result<BoxStream> {
    let pool_key = key(authority, options, secure);
    let (mut sender, active) = if let Some(physical) = pooled(&pool_key, options) {
        drop(stream);
        (physical.sender, physical.active)
    } else {
        let (sender, mut connection) = h2::client::handshake(stream).await?;
        let active = Arc::new(AtomicUsize::new(0));
        POOL.get_or_init(Default::default)
            .lock()
            .unwrap()
            .entry(pool_key)
            .or_default()
            .push(Physical {
                sender: sender.clone(),
                active: active.clone(),
            });
        if options.ping_interval > 0
            && let Some(mut ping) = connection.ping_pong()
        {
            let interval = options.ping_interval;
            tokio::spawn(async move {
                let mut timer = tokio::time::interval(Duration::from_secs(interval));
                loop {
                    timer.tick().await;
                    if ping.ping(h2::Ping::opaque()).await.is_err() {
                        break;
                    }
                }
            });
        }
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "gRPC HTTP/2 connection closed");
            }
        });
        (sender, active)
    };
    active.fetch_add(1, Ordering::Relaxed);
    sender = sender.ready().await?;
    let path = if options.grpc_service_name.starts_with('/') {
        options.grpc_service_name.clone()
    } else {
        format!(
            "/{}/Tun",
            if options.grpc_service_name.is_empty() {
                "GunService"
            } else {
                &options.grpc_service_name
            }
        )
    };
    let scheme = if secure { "https" } else { "http" };
    let request = http::Request::post(format!("{scheme}://{authority}{path}"))
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(
            http::header::USER_AGENT,
            if options.grpc_user_agent.is_empty() {
                "grpc-go/1.36.0"
            } else {
                &options.grpc_user_agent
            },
        )
        .header("te", "trailers")
        .body(())?;
    let (response, send) = sender.send_request(request, false)?;
    let response = response.await?;
    ensure!(
        response.status().is_success(),
        "gRPC transport rejected: {}",
        response.status()
    );
    Ok(Box::new(GrpcStream {
        send,
        recv: response.into_body(),
        incoming: vec![],
        payload: vec![],
        payload_at: 0,
        closed: false,
        active,
    }))
}

pub struct GrpcStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    incoming: Vec<u8>,
    payload: Vec<u8>,
    payload_at: usize,
    closed: bool,
    active: Arc<AtomicUsize>,
}

impl Drop for GrpcStream {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl GrpcStream {
    fn parse(&mut self) -> io::Result<bool> {
        if self.incoming.len() < 5 {
            return Ok(false);
        }
        if self.incoming[0] != 0 {
            return Err(io::Error::other("compressed gRPC messages are unsupported"));
        }
        let length = u32::from_be_bytes(self.incoming[1..5].try_into().unwrap()) as usize;
        if length > 16 * 1024 * 1024 {
            return Err(io::Error::other("oversized gRPC message"));
        }
        if self.incoming.len() < 5 + length {
            return Ok(false);
        }
        let proto = &self.incoming[5..5 + length];
        if proto.first() != Some(&0x0a) {
            return Err(io::Error::other("invalid Gun protobuf message"));
        }
        let (payload_len, prefix) = decode_varint(&proto[1..])
            .ok_or_else(|| io::Error::other("invalid Gun protobuf length"))?;
        let start = 1 + prefix;
        if start + payload_len != proto.len() {
            return Err(io::Error::other("invalid Gun protobuf payload"));
        }
        self.payload = proto[start..].to_vec();
        self.payload_at = 0;
        self.incoming.drain(..5 + length);
        Ok(true)
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.payload_at < self.payload.len() {
            let n = out.remaining().min(self.payload.len() - self.payload_at);
            out.put_slice(&self.payload[self.payload_at..self.payload_at + n]);
            self.payload_at += n;
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.parse()? {
                return self.poll_read(cx, out);
            }
            if self.closed {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.recv).poll_data(cx)) {
                Some(Ok(mut data)) => {
                    let n = data.remaining();
                    self.incoming.extend_from_slice(data.chunk());
                    data.advance(n);
                    let _ = self.recv.flow_control().release_capacity(n);
                }
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                None => self.closed = true,
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = bytes.len().min(16 * 1024);
        self.send
            .send_data(gun_frame(&bytes[..n]), false)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send
            .send_data(Bytes::new(), true)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[test]
    fn gun_framing_roundtrip_shape() {
        let frame = gun_frame(b"hello");
        assert_eq!(&frame[..7], &[0, 0, 0, 0, 7, 0x0a, 5]);
        assert_eq!(&frame[7..], b"hello");
    }

    #[tokio::test]
    async fn gun_stream_uses_expected_path_headers_and_frames() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), "/custom/Tun");
            assert_eq!(
                request.headers()[http::header::CONTENT_TYPE],
                "application/grpc"
            );
            assert_eq!(request.headers()[http::header::USER_AGENT], "test-agent");
            let handler = tokio::spawn(async move {
                let mut body = request.into_body();
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    let size = chunk.len();
                    send.send_data(chunk, false).unwrap();
                    body.flow_control().release_capacity(size).unwrap();
                }
                send.send_data(Bytes::new(), true).unwrap();
            });
            tokio::pin!(handler);
            loop {
                tokio::select! {
                    result = &mut handler => { result.unwrap(); break; }
                    incoming = connection.accept() => {
                        assert!(incoming.is_none(), "unexpected second gRPC stream");
                    }
                }
            }
        });
        let options = meta_config::GrpcOptions {
            grpc_service_name: "custom".into(),
            grpc_user_agent: "test-agent".into(),
            ..Default::default()
        };
        let mut stream = connect(Box::new(client), "unit.example:443", &options, true)
            .await
            .unwrap();
        stream.write_all(b"hello grpc").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0u8; 10];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello grpc");
        stream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }
}
