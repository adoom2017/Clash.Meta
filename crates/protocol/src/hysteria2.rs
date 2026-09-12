//! Hysteria 2 client. Wire layout follows the public protocol specification;
//! QUIC/HTTP3 are generic libraries, not an external proxy implementation.
use crate::{
    Datagram, SplitStream, Target,
    wire::{put_varint, read_sized, take_varint},
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use blake2::{Blake2b, Digest, digest::consts::U32};
use bytes::Bytes;
use meta_config::{Proxy, bandwidth, duration_seconds, port_list};
use rand::RngCore;
use std::{
    collections::HashMap,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};

pub fn salamander_encode(key: &[u8], salt: [u8; 8], bytes: &[u8]) -> Vec<u8> {
    let mut hash = Blake2b::<U32>::new();
    hash.update(key);
    hash.update(salt);
    let mask = hash.finalize();
    let mut output = Vec::with_capacity(bytes.len() + 8);
    output.extend_from_slice(&salt);
    output.extend(bytes.iter().enumerate().map(|(i, b)| b ^ mask[i % 32]));
    output
}
pub fn salamander_decode(key: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(bytes.len() > 8, "short Salamander packet");
    let salt: [u8; 8] = bytes[..8].try_into()?;
    Ok(salamander_encode(key, salt, &bytes[8..])[8..].to_vec())
}

struct SendBudget {
    next: Instant,
}
struct HySocket {
    io: tokio::net::UdpSocket,
    canonical: SocketAddr,
    ports: Vec<u16>,
    started: Instant,
    hop: Duration,
    obfs: Option<Vec<u8>>,
    rate: Arc<AtomicU64>,
    budget: Mutex<SendBudget>,
}
impl std::fmt::Debug for HySocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HySocket")
            .field("ports", &self.ports.len())
            .finish_non_exhaustive()
    }
}
struct Poller {
    socket: Arc<HySocket>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}
impl std::fmt::Debug for Poller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HySocketPoller")
    }
}
impl quinn::UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let due = this.socket.budget.lock().unwrap().next;
        if due > Instant::now() {
            if this
                .sleep
                .as_ref()
                .is_none_or(|s| s.deadline() != tokio::time::Instant::from_std(due))
            {
                this.sleep = Some(Box::pin(tokio::time::sleep_until(due.into())));
            }
            std::task::ready!(std::future::Future::poll(
                this.sleep.as_mut().unwrap().as_mut(),
                cx
            ));
        }
        this.sleep = None;
        this.socket.io.poll_send_ready(cx)
    }
}
impl quinn::AsyncUdpSocket for HySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(Poller {
            socket: self,
            sleep: None,
        })
    }
    fn try_send(&self, tx: &quinn::udp::Transmit) -> io::Result<()> {
        let mut budget = self.budget.lock().unwrap();
        let now = Instant::now();
        if budget.next > now {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut destination = tx.destination;
        if destination.ip() == self.canonical.ip() {
            let index =
                (self.started.elapsed().as_secs() / self.hop.as_secs()) as usize % self.ports.len();
            destination.set_port(self.ports[index]);
        }
        let encoded;
        let bytes = if let Some(key) = &self.obfs {
            let mut salt = [0; 8];
            rand::thread_rng().fill_bytes(&mut salt);
            encoded = salamander_encode(key, salt, tx.contents);
            encoded.as_slice()
        } else {
            tx.contents
        };
        let written = self.io.try_send_to(bytes, destination)?;
        if written != bytes.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let rate = self.rate.load(Ordering::Relaxed);
        if rate > 0 {
            budget.next = now + Duration::from_secs_f64(bytes.len() as f64 / rate as f64);
        }
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Bound work per poll so hostile packets cannot monopolize the executor.
        for _ in 0..32 {
            let mut packet = vec![0; 65535];
            let mut read = tokio::io::ReadBuf::new(&mut packet);
            let addr = std::task::ready!(self.io.poll_recv_from(cx, &mut read))?;
            if addr.ip() != self.canonical.ip() || !self.ports.contains(&addr.port()) {
                continue;
            }
            let bytes = if let Some(key) = &self.obfs {
                match salamander_decode(key, read.filled()) {
                    Ok(b) => b,
                    Err(_) => continue,
                }
            } else {
                read.filled().to_vec()
            };
            if bytes.len() > bufs[0].len() {
                continue;
            }
            bufs[0][..bytes.len()].copy_from_slice(&bytes);
            meta[0] = quinn::udp::RecvMeta {
                addr: self.canonical,
                len: bytes.len(),
                stride: bytes.len(),
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

#[derive(Debug, Clone)]
pub struct UdpMessage {
    pub session: u32,
    pub packet: u16,
    pub fragment: u8,
    pub count: u8,
    pub target: Target,
    pub payload: Vec<u8>,
}
impl UdpMessage {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.count > 0 && self.fragment < self.count,
            "invalid HY2 fragments"
        );
        let mut out = vec![];
        out.extend_from_slice(&self.session.to_be_bytes());
        out.extend_from_slice(&self.packet.to_be_bytes());
        out.extend_from_slice(&[self.fragment, self.count]);
        let target = self.target.to_string();
        put_varint(target.len() as u64, &mut out)?;
        out.extend_from_slice(target.as_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() >= 9, "short HY2 datagram");
        let mut input = &bytes[8..];
        let n = take_varint(&mut input)? as usize;
        ensure!(n <= 512 && input.len() >= n, "bad HY2 address length");
        let target = Target::parse(std::str::from_utf8(&input[..n])?)?;
        let message = Self {
            session: u32::from_be_bytes(bytes[..4].try_into()?),
            packet: u16::from_be_bytes(bytes[4..6].try_into()?),
            fragment: bytes[6],
            count: bytes[7],
            target,
            payload: input[n..].to_vec(),
        };
        ensure!(
            message.count > 0 && (message.count == 1 || message.fragment < message.count),
            "bad HY2 fragment index"
        );
        Ok(message)
    }
}
struct Pending {
    created: Instant,
    target: Target,
    fragments: Vec<Option<Vec<u8>>>,
    size: usize,
}
#[derive(Default)]
pub struct Reassembler {
    pending: HashMap<(u32, u16), Pending>,
}
impl Reassembler {
    pub fn push(&mut self, message: UdpMessage) -> Result<Option<(Target, Vec<u8>)>> {
        if message.count == 1 {
            ensure!(message.payload.len() <= 65507, "oversized UDP packet");
            return Ok(Some((message.target, message.payload)));
        }
        self.pending
            .retain(|_, p| p.created.elapsed() < Duration::from_secs(5));
        let key = (message.session, message.packet);
        ensure!(
            self.pending.contains_key(&key) || self.pending.len() < 64,
            "fragment table full"
        );
        let pending = self.pending.entry(key).or_insert_with(|| Pending {
            created: Instant::now(),
            target: message.target.clone(),
            fragments: vec![None; message.count as usize],
            size: 0,
        });
        ensure!(
            pending.target == message.target && pending.fragments.len() == message.count as usize,
            "inconsistent fragments"
        );
        let slot = &mut pending.fragments[message.fragment as usize];
        if slot.is_none() {
            pending.size += message.payload.len();
            *slot = Some(message.payload);
        }
        if pending.size > 65507 {
            self.pending.remove(&key);
            anyhow::bail!("oversized fragmented packet");
        }
        if pending.fragments.iter().all(Option::is_some) {
            let pending = self.pending.remove(&key).unwrap();
            let mut output = Vec::with_capacity(pending.size);
            for fragment in pending.fragments {
                output.extend(fragment.unwrap());
            }
            return Ok(Some((pending.target, output)));
        }
        Ok(None)
    }
}

type SessionSenders = Arc<Mutex<HashMap<u32, tokio::sync::mpsc::Sender<Bytes>>>>;
pub struct Client {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    driver: tokio::task::JoinHandle<()>,
    receiver: tokio::task::JoinHandle<()>,
    sessions: SessionSenders,
    next_session: AtomicU32,
    udp: bool,
}
impl Drop for Client {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"shutdown");
        self.endpoint.close(0u32.into(), b"shutdown");
        self.driver.abort();
        self.receiver.abort();
    }
}
impl Client {
    pub async fn connect(
        proxy: &Proxy,
        remote: SocketAddr,
        hooks: &dyn meta_platform::PlatformHooks,
    ) -> Result<Arc<Self>> {
        let bind = if remote.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()?;
        let rate = Arc::new(AtomicU64::new(0));
        let socket = Arc::new(HySocket {
            io: meta_platform::udp_bind(bind, hooks)?,
            canonical: remote,
            ports: port_list(proxy)?,
            started: Instant::now(),
            hop: Duration::from_secs(duration_seconds(&proxy.hop_interval)?),
            obfs: proxy
                .obfs
                .as_ref()
                .map(|_| proxy.obfs_password.as_bytes().to_vec()),
            rate: rate.clone(),
            budget: Mutex::new(SendBudget {
                next: Instant::now(),
            }),
        });
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let tls = crate::tls::config(&["h3".into()], proxy.skip_cert_verify)?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .max_idle_timeout(Some(Duration::from_secs(30).try_into()?))
            .datagram_receive_buffer_size(Some(2 * 1024 * 1024))
            .max_concurrent_bidi_streams(0u32.into())
            .initial_mtu(1200)
            .mtu_discovery_config(None);
        config.transport_config(Arc::new(transport));
        endpoint.set_default_client_config(config);
        let server_name = proxy
            .sni
            .as_deref()
            .or(proxy.servername.as_deref())
            .unwrap_or(&proxy.server);
        let connection = tokio::time::timeout(
            Duration::from_secs(15),
            endpoint.connect(remote, server_name)?,
        )
        .await??;
        let (mut h3_connection, mut requests) =
            h3::client::new(h3_quinn::Connection::new(connection.clone())).await?;
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| h3_connection.poll_close(cx)).await;
        });
        // Abort the HTTP/3 driver on any authentication failure.
        let authentication = async {
            let request = http::Request::builder()
                .method("POST")
                .uri("https://hysteria/auth")
                .header("Hysteria-Auth", &proxy.password)
                .header(
                    "Hysteria-CC-RX",
                    proxy
                        .down
                        .as_deref()
                        .map(bandwidth)
                        .transpose()?
                        .unwrap_or(0),
                )
                .header("Hysteria-Padding", "00000000000000000000000000000000")
                .body(())?;
            let mut stream = requests.send_request(request).await?;
            stream.finish().await?;
            let response = stream.recv_response().await?;
            ensure!(
                response.status().as_u16() == 233,
                "HY2 authentication rejected"
            );
            let udp = response
                .headers()
                .get("Hysteria-UDP")
                .is_some_and(|v| v == "true");
            let server_rate = response
                .headers()
                .get("Hysteria-CC-RX")
                .context("missing HY2 bandwidth negotiation")?
                .to_str()?;
            let user_rate = proxy.up.as_deref().map(bandwidth).transpose()?.unwrap_or(0);
            let cap = if server_rate == "auto" {
                user_rate
            } else {
                let server_rate = server_rate.parse::<u64>()?;
                match (user_rate, server_rate) {
                    (0, b) => b,
                    (a, 0) => a,
                    (a, b) => a.min(b),
                }
            };
            rate.store(cap, Ordering::Relaxed);
            Ok::<_, anyhow::Error>(udp)
        };
        let udp = match tokio::time::timeout(Duration::from_secs(15), authentication).await {
            Ok(Ok(udp)) => udp,
            result => {
                driver.abort();
                connection.close(0u32.into(), b"auth failed");
                return Err(match result {
                    Ok(Err(err)) => err,
                    Err(err) => err.into(),
                    _ => unreachable!(),
                });
            }
        };
        // Keep the request sender alive in the driver guard: dropping the last
        // HTTP/3 sender initiates graceful close on some h3 versions.
        let old_driver = driver;
        let driver = tokio::spawn(async move {
            let _requests = requests;
            let _ = old_driver.await;
        });
        let sessions: SessionSenders = Arc::new(Mutex::new(HashMap::new()));
        let table = sessions.clone();
        let conn = connection.clone();
        let receiver = tokio::spawn(async move {
            while let Ok(packet) = conn.read_datagram().await {
                if packet.len() < 4 {
                    continue;
                }
                let id = u32::from_be_bytes(packet[..4].try_into().unwrap());
                if let Some(sender) = table.lock().unwrap().get(&id) {
                    let _ = sender.try_send(packet);
                }
            }
            table.lock().unwrap().clear();
        });
        Ok(Arc::new(Self {
            endpoint,
            connection,
            driver,
            receiver,
            sessions,
            next_session: AtomicU32::new(rand::random()),
            udp,
        }))
    }
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
    pub async fn tcp(&self, target: &Target) -> Result<SplitStream> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        let mut header = vec![];
        put_varint(0x401, &mut header)?;
        let addr = target.to_string();
        put_varint(addr.len() as u64, &mut header)?;
        header.extend_from_slice(addr.as_bytes());
        put_varint(0, &mut header)?;
        send.write_all(&header).await?;
        let mut status = [0];
        recv.read_exact(&mut status).await?;
        let _message = read_sized(&mut recv, 4096).await?;
        let _padding = read_sized(&mut recv, 4096).await?;
        ensure!(status[0] == 0, "HY2 target connection rejected");
        Ok(SplitStream { send, recv })
    }
    pub fn udp(self: &Arc<Self>) -> Result<Arc<dyn Datagram>> {
        ensure!(self.udp, "HY2 server disabled UDP");
        let mut table = self.sessions.lock().unwrap();
        ensure!(table.len() < 4096, "HY2 session limit");
        let mut id = self.next_session.fetch_add(1, Ordering::Relaxed);
        while table.contains_key(&id) {
            id = self.next_session.fetch_add(1, Ordering::Relaxed);
        }
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        table.insert(id, tx);
        Ok(Arc::new(UdpSession {
            client: self.clone(),
            id,
            packet: AtomicU32::new(0),
            receive: tokio::sync::Mutex::new((rx, Reassembler::default())),
        }))
    }
}
struct UdpSession {
    client: Arc<Client>,
    id: u32,
    packet: AtomicU32,
    receive: tokio::sync::Mutex<(tokio::sync::mpsc::Receiver<Bytes>, Reassembler)>,
}
impl Drop for UdpSession {
    fn drop(&mut self) {
        self.client.sessions.lock().unwrap().remove(&self.id);
    }
}
#[async_trait]
impl Datagram for UdpSession {
    async fn send(&self, target: &Target, bytes: &[u8]) -> Result<()> {
        ensure!(bytes.len() <= 65507, "UDP payload too large");
        let max = self
            .client
            .connection
            .max_datagram_size()
            .context("QUIC datagrams unavailable")?;
        let overhead = 10 + target.to_string().len();
        ensure!(max > overhead, "QUIC datagram size too small");
        let chunk = max - overhead;
        let count = bytes.len().max(1).div_ceil(chunk);
        ensure!(count <= 255, "too many UDP fragments");
        let packet = self.packet.fetch_add(1, Ordering::Relaxed) as u16;
        for fragment in 0..count {
            let payload = bytes
                [(fragment * chunk).min(bytes.len())..((fragment + 1) * chunk).min(bytes.len())]
                .to_vec();
            let message = UdpMessage {
                session: self.id,
                packet,
                fragment: fragment as u8,
                count: count as u8,
                target: target.clone(),
                payload,
            };
            self.client
                .connection
                .send_datagram_wait(message.encode()?.into())
                .await?;
        }
        Ok(())
    }
    async fn recv(&self) -> Result<(Target, Vec<u8>)> {
        let mut guard = self.receive.lock().await;
        loop {
            let packet = guard.0.recv().await.context("HY2 session closed")?;
            if let Ok(message) = UdpMessage::decode(&packet)
                && let Ok(Some(result)) = guard.1.push(message)
            {
                return Ok(result);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn obfs_roundtrip() {
        let b = salamander_encode(b"password", [1; 8], b"QUIC data");
        assert_eq!(salamander_decode(b"password", &b).unwrap(), b"QUIC data");
        assert!(salamander_decode(b"p", b"short").is_err());
    }
    #[test]
    fn udp_reassembly_reordered() {
        let target = Target::new("example.org", 53).unwrap();
        let mut r = Reassembler::default();
        for index in [1, 0] {
            let m = UdpMessage {
                session: 7,
                packet: 9,
                fragment: index,
                count: 2,
                target: target.clone(),
                payload: vec![index],
            };
            let decoded = UdpMessage::decode(&m.encode().unwrap()).unwrap();
            let got = r.push(decoded).unwrap();
            if index == 0 {
                assert_eq!(got.unwrap().1, vec![0, 1]);
            } else {
                assert!(got.is_none());
            }
        }
    }
}
