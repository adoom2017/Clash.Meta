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
        let host = if let Ok(ip) = host.parse::<IpAddr>() {
            ip.to_string()
        } else {
            ensure!(
                !host
                    .chars()
                    .any(|c| matches!(c, ':' | '[' | ']' | '/' | '?' | '#' | '@')),
                "invalid target host"
            );
            host
        };
        Ok(Self { host, port })
    }
    pub fn parse(authority: &str) -> Result<Self> {
        if let Ok(addr) = authority.parse::<SocketAddr>() {
            return Self::new(addr.ip().to_string(), addr.port());
        }
        ensure!(
            !authority.contains('@'),
            "target cannot contain user information"
        );
        let authority: http::uri::Authority = authority.parse()?;
        let port = authority
            .port_u16()
            .ok_or_else(|| anyhow::anyhow!("target must be host:port"))?;
        let host = authority.host();
        ensure!(
            !host.starts_with('['),
            "bracketed target must be an IPv6 address"
        );
        Self::new(host, port)
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

#[cfg(test)]
mod target_tests {
    use super::*;
    #[test]
    fn authorities_are_unambiguous_and_ips_canonical() {
        assert_eq!(
            Target::new("a::0", 54).unwrap(),
            Target::parse("[a::]:54").unwrap()
        );
        for malformed in [
            "a::0:54",
            "host:0",
            "user@host:80",
            "host/path:80",
            "[not-an-ip]:80",
            "[::1]:65536",
        ] {
            assert!(Target::parse(malformed).is_err(), "{malformed}");
        }
        assert!(
            crate::hysteria2::UdpMessage::decode(&[
                1, 15, 4, 0, 4, 4, 5, 32, 6, 97, 58, 58, 48, 58, 53, 52, 58, 32, 1
            ])
            .is_err()
        );
    }
}
