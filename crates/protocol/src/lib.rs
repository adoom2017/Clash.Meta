#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
pub mod hysteria2;
pub mod reality;
pub mod record;
pub mod tls;
pub mod vision;
pub mod vless;
pub mod wire;
pub mod xudp;

use anyhow::{Result, ensure};
use async_trait::async_trait;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    pin::Pin,
};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
}
impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self> {
        let host = host.into();
        ensure!(
            !host.is_empty()
                && host.len() <= 253
                && port != 0
                && !host.chars().any(|c| c.is_control() || c.is_whitespace()),
            "invalid target"
        );
        Ok(Self { host, port })
    }
    pub fn parse(authority: &str) -> Result<Self> {
        if let Ok(addr) = authority.parse::<SocketAddr>() {
            return Self::new(addr.ip().to_string(), addr.port());
        }
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("target must be host:port"))?;
        Self::new(
            host.trim_start_matches('[').trim_end_matches(']'),
            port.parse()?,
        )
    }
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }
}
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}
pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}
pub type BoxStream = Box<dyn IoStream>;

#[async_trait]
pub trait Datagram: Send + Sync {
    async fn send(&self, target: &Target, bytes: &[u8]) -> Result<()>;
    async fn recv(&self) -> Result<(Target, Vec<u8>)>;
}

/// Combine independently owned QUIC stream halves without an intermediary task.
pub struct SplitStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}
impl AsyncRead for SplitStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}
impl AsyncWrite for SplitStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, bytes)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
