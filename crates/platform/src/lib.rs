//! Host-owned networking. Embedded cores never change routes or process state.
use anyhow::Result;
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};

pub trait PlatformHooks: Send + Sync + std::fmt::Debug {
    /// Called before connect/send. Android hosts protect this socket from VPN
    /// capture; desktop hosts may bind the physical interface. Failure is fatal.
    fn protect_socket(&self, socket: &socket2::Socket) -> Result<()>;
}
#[derive(Debug, Default)]
pub struct DefaultHooks;
impl PlatformHooks for DefaultHooks {
    fn protect_socket(&self, _: &socket2::Socket) -> Result<()> {
        Ok(())
    }
}
pub type Hooks = Arc<dyn PlatformHooks>;

pub async fn tcp_connect(
    addr: SocketAddr,
    hooks: &dyn PlatformHooks,
) -> Result<tokio::net::TcpStream> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_nonblocking(true)?;
    hooks.protect_socket(&socket)?;
    let stream: std::net::TcpStream = socket.into();
    let socket = tokio::net::TcpSocket::from_std_stream(stream);
    let stream = socket.connect(addr).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}
pub fn udp_bind(addr: SocketAddr, hooks: &dyn PlatformHooks) -> Result<tokio::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_nonblocking(true)?;
    hooks.protect_socket(&socket)?;
    socket.bind(&addr.into())?;
    Ok(tokio::net::UdpSocket::from_std(socket.into())?)
}

#[async_trait]
pub trait PacketIo: Send + Sync {
    /// Exactly one raw IP packet, without a Darwin address-family prefix.
    async fn recv(&self, packet: &mut [u8]) -> Result<usize>;
    async fn send(&self, packet: &[u8]) -> Result<()>;
}
