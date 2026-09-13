//! Embeddable proxy core. Runtime and OS policy belong to the host.
mod api;
pub mod dns;
mod inbound;
mod packet;
#[cfg(test)]
mod tests;
mod traffic;

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use meta_config::{
    Config, GroupKind, Mode, ProxyKind,
    rule::{Matcher, Rule},
};
use meta_platform::Hooks;
use meta_protocol::{BoxStream, Datagram, Target};
use serde::Serialize;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock, atomic::AtomicU64},
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, task::JoinSet};
use tokio_util::sync::CancellationToken;

pub struct Core {
    pub config: Config,
    pub resolver: Arc<dns::Resolver>,
    hooks: Hooks,
    policy: RwLock<Policy>,
    hy2: HashMap<String, tokio::sync::Mutex<Option<Hy2Connection>>>,
    network: Mutex<CancellationToken>,
    pub stop: CancellationToken,
    connections: Mutex<HashMap<String, Arc<traffic::State>>>,
    pub upload: AtomicU64,
    pub download: AtomicU64,
    slots: Arc<tokio::sync::Semaphore>,
    lifecycle: Mutex<bool>,
    pub events: tokio::sync::broadcast::Sender<String>,
}
struct Hy2Connection {
    client: Arc<meta_protocol::hysteria2::Client>,
    network: CancellationToken,
}
struct Policy {
    mode: Mode,
    rules: Vec<Rule>,
    raw_rules: Vec<String>,
    selection: HashMap<String, String>,
    delay: HashMap<String, u64>,
}
#[derive(Clone, Serialize)]
pub struct Connection {
    pub id: String,
    pub metadata: Target,
    pub network: String,
    pub chains: Vec<String>,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    #[serde(skip)]
    pub cancel: CancellationToken,
}
pub struct Running {
    core: Arc<Core>,
    tasks: JoinSet<()>,
    pub addresses: Vec<SocketAddr>,
}
impl Running {
    pub async fn shutdown(mut self) {
        self.core.stop.cancel();
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        for client in self.core.hy2.values() {
            client.lock().await.take();
        }
        *self.core.lifecycle.lock().unwrap() = false;
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.core.stop.cancel();
        self.tasks.abort_all();
    }
}
impl Core {
    pub fn new(config: Config, hooks: Hooks) -> Result<Arc<Self>> {
        config.validate()?;
        let mut dns = config.dns.clone();
        dns.ipv6 &= config.ipv6;
        let resolver = Arc::new(dns::Resolver::new(dns, hooks.clone()));
        let mut selection = HashMap::new();
        for group in &config.proxy_groups {
            selection.insert(group.name.clone(), group.proxies[0].clone());
        }
        let rules = config
            .rules
            .iter()
            .map(|r| Rule::parse(r))
            .collect::<Result<Vec<_>>>()?;
        let policy = Policy {
            mode: config.mode.clone(),
            raw_rules: config.rules.clone(),
            rules,
            selection,
            delay: HashMap::new(),
        };
        let (events, _) = tokio::sync::broadcast::channel(256);
        let hy2 = config
            .proxies
            .iter()
            .filter(|p| p.kind == ProxyKind::Hysteria2)
            .map(|p| (p.name.clone(), tokio::sync::Mutex::new(None)))
            .collect();
        Ok(Arc::new(Self {
            config,
            resolver,
            hooks,
            policy: RwLock::new(policy),
            hy2,
            network: Mutex::new(CancellationToken::new()),
            stop: CancellationToken::new(),
            connections: Default::default(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            slots: Arc::new(tokio::sync::Semaphore::new(4096)),
            lifecycle: Mutex::new(false),
            events,
        }))
    }
    pub async fn start(self: &Arc<Self>) -> Result<Running> {
        self.start_with_packets(None).await
    }
    pub async fn start_with_packets(
        self: &Arc<Self>,
        packets: Option<Arc<dyn meta_platform::PacketIo>>,
    ) -> Result<Running> {
        ensure!(
            self.config.tun.enable == packets.is_some(),
            "tun.enable requires a host PacketIo; disable TUN for listener-only operation"
        );
        {
            let mut started = self.lifecycle.lock().unwrap();
            ensure!(
                !*started && !self.stop.is_cancelled(),
                "core cannot be started twice; create a new core"
            );
            *started = true;
        }
        let result = self.start_inner(packets).await;
        if result.is_err() {
            self.stop.cancel();
            *self.lifecycle.lock().unwrap() = false;
        }
        result
    }
    async fn start_inner(
        self: &Arc<Self>,
        packets: Option<Arc<dyn meta_platform::PacketIo>>,
    ) -> Result<Running> {
        let mut tasks = JoinSet::new();
        let mut addresses = vec![];
        if let Some(packets) = packets {
            let core = self.clone();
            tasks.spawn(async move {
                if let Err(error) = packet::run(core.clone(), packets).await {
                    tracing::error!(%error, "packet interface stopped");
                }
                core.stop.cancel();
            });
        }
        let ip = if self.config.allow_lan {
            self.config.bind_address.parse()?
        } else {
            "127.0.0.1".parse()?
        };
        for (port, kind) in [
            (self.config.port, inbound::Kind::Http),
            (self.config.socks_port, inbound::Kind::Socks),
            (self.config.mixed_port, inbound::Kind::Mixed),
        ] {
            if port == 0 {
                continue;
            }
            let listener = tokio::net::TcpListener::bind(SocketAddr::new(ip, port)).await?;
            addresses.push(listener.local_addr()?);
            let core = self.clone();
            tasks.spawn(async move {
                inbound::serve(core, listener, kind).await;
            });
        }
        if self.config.dns.enable {
            let udp = tokio::net::UdpSocket::bind(&self.config.dns.listen).await?;
            let tcp = tokio::net::TcpListener::bind(&self.config.dns.listen).await?;
            let core = self.clone();
            tasks.spawn(async move {
                inbound::dns_udp(core, udp).await;
            });
            let core = self.clone();
            tasks.spawn(async move {
                inbound::dns_tcp(core, tcp).await;
            });
        }
        if let Some(addr) = &self.config.external_controller {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            let core = self.clone();
            let stop = self.stop.clone();
            tasks.spawn(async move {
                let _ = axum::serve(listener, api::router(core))
                    .with_graceful_shutdown(stop.cancelled_owned())
                    .await;
            });
        }
        for group in self
            .config
            .proxy_groups
            .iter()
            .filter(|g| g.kind == GroupKind::UrlTest)
        {
            let group = group.clone();
            let core = self.clone();
            tasks.spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(group.interval));
                loop {
                    tokio::select! {_=core.stop.cancelled()=>break,_=interval.tick()=>{}}
                    let mut best = None;
                    for target in &group.proxies {
                        if let Ok(delay) =
                            core.probe(target, &group.url, Duration::from_secs(5)).await
                            && best.as_ref().is_none_or(|(_, d)| delay < *d)
                        {
                            best = Some((target.clone(), delay));
                        }
                    }
                    if let Some((target, delay)) = best {
                        let mut policy = core.policy.write().unwrap();
                        let old = policy
                            .selection
                            .get(&group.name)
                            .and_then(|n| policy.delay.get(n))
                            .copied()
                            .unwrap_or(u64::MAX);
                        if delay.saturating_add(group.tolerance) < old {
                            policy.selection.insert(group.name.clone(), target);
                        }
                    }
                }
            });
        }
        Ok(Running {
            core: self.clone(),
            tasks,
            addresses,
        })
    }
    pub fn restore_target(&self, target: &Target) -> Target {
        if let Some(name) = target.ip().and_then(|ip| self.resolver.original(ip)) {
            Target {
                host: name,
                port: target.port,
            }
        } else {
            target.clone()
        }
    }
    async fn route(&self, target: &Target, network: &str) -> Result<String> {
        let (mode, rules) = {
            let p = self.policy.read().unwrap();
            (p.mode.clone(), p.rules.clone())
        };
        if mode == Mode::Direct {
            return Ok("DIRECT".into());
        }
        if mode == Mode::Global {
            return self.leaf("GLOBAL");
        }
        let mut ip = target.ip();
        let mut resolved = ip.is_some();
        for rule in rules {
            if matches!(rule.matcher, Matcher::Net(_)) && !rule.no_resolve && !resolved {
                ip = self
                    .resolver
                    .lookup(&target.host, target.port)
                    .await
                    .ok()
                    .and_then(|v| v.first().map(SocketAddr::ip));
                resolved = true;
            }
            if rule.matches(&target.host, ip, target.port, network) {
                return self.leaf(&rule.target);
            }
        }
        Ok("DIRECT".into())
    }
    fn leaf(&self, name: &str) -> Result<String> {
        let policy = self.policy.read().unwrap();
        let mut name = name.to_owned();
        if name == "GLOBAL" {
            name = self
                .config
                .proxy_groups
                .first()
                .map(|g| g.name.clone())
                .or_else(|| self.config.proxies.first().map(|p| p.name.clone()))
                .unwrap_or("DIRECT".into());
        }
        for _ in 0..=self.config.proxy_groups.len() {
            if let Some(selected) = policy.selection.get(&name) {
                name = selected.clone();
            } else {
                return Ok(name);
            }
        }
        bail!("group cycle")
    }
    pub fn select(&self, group: &str, name: &str) -> Result<()> {
        let config = self
            .config
            .proxy_groups
            .iter()
            .find(|g| g.name == group)
            .context("group not found")?;
        ensure!(
            config.proxies.iter().any(|p| p == name),
            "node not in group"
        );
        self.policy
            .write()
            .unwrap()
            .selection
            .insert(group.into(), name.into());
        Ok(())
    }
    pub fn set_mode(&self, mode: Mode) {
        self.policy.write().unwrap().mode = mode;
    }
    pub fn replace_rules(&self, rules: Vec<String>) -> Result<()> {
        self.update_policy(None, Some(rules))
    }
    pub fn update_policy(&self, mode: Option<Mode>, rules: Option<Vec<String>>) -> Result<()> {
        let update_rules = rules.is_some();
        let mut cfg = self.config.clone();
        if let Some(rules) = rules {
            cfg.rules = rules;
        } else {
            cfg.rules = self.policy.read().unwrap().raw_rules.clone();
        }
        if let Some(mode) = &mode {
            cfg.mode = mode.clone();
        }
        cfg.validate()?;
        let rules = cfg
            .rules
            .iter()
            .map(|r| Rule::parse(r))
            .collect::<Result<_>>()?;
        let mut policy = self.policy.write().unwrap();
        if update_rules {
            policy.rules = rules;
            policy.raw_rules = cfg.rules;
        }
        if let Some(mode) = mode {
            policy.mode = mode;
        }
        Ok(())
    }
    pub fn configuration(&self) -> serde_json::Value {
        let mut config = serde_json::to_value(&self.config).unwrap();
        let policy = self.policy.read().unwrap();
        config["mode"] = serde_json::to_value(&policy.mode).unwrap();
        config["rules"] = serde_json::to_value(&policy.raw_rules).unwrap();
        config
    }
    async fn raw_tcp(&self, target: &Target) -> Result<tokio::net::TcpStream> {
        let addresses = self.resolver.lookup(&target.host, target.port).await?;
        let mut last = anyhow::anyhow!("no destination address");
        for addr in addresses {
            match tokio::time::timeout(
                Duration::from_secs(5),
                meta_platform::tcp_connect(addr, &*self.hooks),
            )
            .await
            {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(e)) => last = e,
                Err(e) => last = e.into(),
            }
        }
        Err(last)
    }
    async fn hy2(
        &self,
        proxy: &meta_config::Proxy,
    ) -> Result<Arc<meta_protocol::hysteria2::Client>> {
        let network = self.network.lock().unwrap().clone();
        tokio::select! {
            biased;
            _ = self.stop.cancelled() => bail!("core stopped"),
            _ = network.cancelled() => bail!("network changed during HY2 connection"),
            result = self.hy2_on_network(proxy, network.clone()) => result,
        }
    }
    async fn hy2_on_network(
        &self,
        proxy: &meta_config::Proxy,
        network: CancellationToken,
    ) -> Result<Arc<meta_protocol::hysteria2::Client>> {
        let mut cached = self
            .hy2
            .get(&proxy.name)
            .context("HY2 proxy not found")?
            .lock()
            .await;
        if let Some(client) = cached.as_ref()
            && !client.network.is_cancelled()
            && !client.client.is_closed()
        {
            return Ok(client.client.clone());
        }
        cached.take();
        let remote = self
            .resolver
            .lookup(&proxy.server, proxy.port)
            .await?
            .into_iter()
            .next()
            .context("no HY2 server address")?;
        let client = meta_protocol::hysteria2::Client::connect(proxy, remote, &*self.hooks).await?;
        ensure!(
            !network.is_cancelled(),
            "network changed during HY2 connection"
        );
        *cached = Some(Hy2Connection {
            client: client.clone(),
            network,
        });
        Ok(client)
    }
    async fn vless_stream(
        &self,
        proxy: &meta_config::Proxy,
        target: &Target,
        command: u8,
    ) -> Result<BoxStream> {
        let socket = self
            .raw_tcp(&Target::new(&proxy.server, proxy.port)?)
            .await?;
        meta_protocol::vless::connect(socket, proxy, target, command).await
    }
    pub async fn dial(
        &self,
        target: &Target,
        selected: Option<&str>,
    ) -> Result<(BoxStream, String)> {
        tokio::select! {
            biased;
            _ = self.stop.cancelled() => bail!("core stopped"),
            result = tokio::time::timeout(Duration::from_secs(20), self.dial_inner(target, selected)) => result?,
        }
    }
    async fn dial_inner(
        &self,
        target: &Target,
        selected: Option<&str>,
    ) -> Result<(BoxStream, String)> {
        let target = self.restore_target(target);
        let name = match selected {
            Some(n) => self.leaf(n)?,
            None => self.route(&target, "tcp").await?,
        };
        let stream = tokio::time::timeout(Duration::from_secs(20), async {
            if name == "DIRECT" {
                return Ok::<BoxStream, anyhow::Error>(Box::new(self.raw_tcp(&target).await?));
            }
            if name == "REJECT" {
                bail!("connection rejected");
            }
            let p = self
                .config
                .proxies
                .iter()
                .find(|p| p.name == name)
                .context("proxy not found")?;
            match p.kind {
                ProxyKind::Vless => self.vless_stream(p, &target, 1).await,
                ProxyKind::Hysteria2 => {
                    Ok(Box::new(self.hy2(p).await?.tcp(&target).await?) as BoxStream)
                }
            }
        })
        .await??;
        Ok((stream, name))
    }
    pub async fn datagram(self: &Arc<Self>, target: &Target) -> Result<Arc<dyn Datagram>> {
        let target = self.restore_target(target);
        tokio::select! {
            biased;
            _=self.stop.cancelled()=>bail!("core stopped"),
            result=tokio::time::timeout(Duration::from_secs(20),async {
                let name=self.route(&target,"udp").await?;
                let inner=self.datagram_inner(&target,&name).await?;
                Ok::<Arc<dyn Datagram>,anyhow::Error>(Arc::new(traffic::PacketSession {
                    inner,tracker:traffic::Tracker::new(self.clone(),target,name,"udp")?
                }))
            })=>result?,
        }
    }
    async fn datagram_inner(&self, target: &Target, name: &str) -> Result<Arc<dyn Datagram>> {
        if name == "REJECT" {
            bail!("UDP rejected");
        }
        if name == "DIRECT" {
            let remote = self
                .resolver
                .lookup(&target.host, target.port)
                .await?
                .into_iter()
                .next()
                .context("no UDP address")?;
            let bind = if remote.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()?;
            let socket = meta_platform::udp_bind_for(bind, Some(remote), &*self.hooks)?;
            socket.connect(remote).await?;
            return Ok(Arc::new(DirectUdp {
                socket,
                target: target.clone(),
            }));
        }
        let proxy = self
            .config
            .proxies
            .iter()
            .find(|p| p.name == name)
            .context("proxy not found")?;
        ensure!(proxy.udp, "UDP disabled");
        match proxy.kind {
            ProxyKind::Vless => {
                let xudp = proxy.xudp
                    || proxy.packet_encoding.as_deref() == Some("xudp")
                    || proxy.flow == "xtls-rprx-vision";
                let stream = self
                    .vless_stream(proxy, target, if xudp { 3 } else { 2 })
                    .await?;
                if xudp {
                    Ok(Arc::new(meta_protocol::xudp::Session::new(
                        stream,
                        target.clone(),
                    )))
                } else {
                    Ok(Arc::new(meta_protocol::vless::UdpSession::new(
                        stream,
                        target.clone(),
                    )))
                }
            }
            ProxyKind::Hysteria2 => self.hy2(proxy).await?.udp(),
        }
    }
    pub async fn relay(
        self: &Arc<Self>,
        inbound: BoxStream,
        target: Target,
        outbound: BoxStream,
        node: String,
    ) -> Result<()> {
        self.relay_io(inbound, target, outbound, node).await
    }
    pub(crate) async fn relay_io<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        self: &Arc<Self>,
        mut inbound: S,
        target: Target,
        outbound: BoxStream,
        node: String,
    ) -> Result<()> {
        let tracker = traffic::Tracker::new(self.clone(), target, node, "tcp")?;
        let cancel = tracker.cancel();
        let mut outbound = traffic::Stream {
            inner: outbound,
            tracker,
        };
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let state = outbound.tracker.state.clone();
        let idle = async {
            loop {
                interval.tick().await;
                if state.idle() >= Duration::from_secs(300) {
                    break;
                }
            }
        };
        tokio::select! {
            _=cancel.cancelled()=>{},
            _=idle=>{},
            result=tokio::io::copy_bidirectional(&mut inbound,&mut outbound)=>{result?;},
        }
        Ok(())
    }
    pub fn connections(&self) -> Vec<Connection> {
        self.connections
            .lock()
            .unwrap()
            .values()
            .map(|s| s.snapshot())
            .collect()
    }
    pub fn close_connection(&self, id: &str) {
        if let Some(c) = self.connections.lock().unwrap().get(id) {
            c.snapshot().cancel.cancel();
        }
    }
    pub async fn network_changed(&self) {
        {
            let mut network = self.network.lock().unwrap();
            network.cancel();
            *network = CancellationToken::new();
        }
        for connection in self.connections() {
            connection.cancel.cancel();
        }
        for client in self.hy2.values() {
            // Establishment owns this lock until cancellation is observed. Do not
            // wait for it, or discard a connection made on the new network.
            if let Ok(mut cached) = client.try_lock()
                && cached.as_ref().is_some_and(|c| c.network.is_cancelled())
            {
                cached.take();
            }
        }
        self.resolver.clear_cache();
    }
    pub async fn probe(&self, name: &str, url: &str, timeout: Duration) -> Result<u64> {
        let start = Instant::now();
        let operation = async {
            let uri: http::Uri = url.parse()?;
            let secure = uri.scheme_str() == Some("https");
            ensure!(
                secure || uri.scheme_str() == Some("http"),
                "test URL must use HTTP(S)"
            );
            let target = Target::from_uri(&uri, if secure { 443 } else { 80 })?;
            let (stream, _) = self.dial(&target, Some(name)).await?;
            let mut stream: BoxStream = if secure {
                let cfg = meta_protocol::tls::config(&["http/1.1".into()], false)?;
                Box::new(
                    tokio_rustls::TlsConnector::from(Arc::new(cfg))
                        .connect(
                            rustls::pki_types::ServerName::try_from(target.host.clone())?,
                            stream,
                        )
                        .await?,
                )
            } else {
                stream
            };
            let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
            stream
                .write_all(
                    format!("GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await?;
            let mut byte = [0; 12];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut byte).await?;
            ensure!(&byte[..5] == b"HTTP/", "invalid health response");
            Ok::<_, anyhow::Error>(())
        };
        tokio::select! {
            biased;
            _ = self.stop.cancelled() => bail!("core stopped"),
            result = tokio::time::timeout(timeout, operation) => result??,
        }
        let elapsed = start.elapsed().as_millis() as u64;
        self.policy
            .write()
            .unwrap()
            .delay
            .insert(name.into(), elapsed);
        Ok(elapsed)
    }
}
struct DirectUdp {
    socket: tokio::net::UdpSocket,
    target: Target,
}
#[async_trait]
impl Datagram for DirectUdp {
    async fn send(&self, target: &Target, bytes: &[u8]) -> Result<()> {
        ensure!(target == &self.target, "UDP target changed");
        self.socket.send(bytes).await?;
        Ok(())
    }
    async fn recv(&self) -> Result<(Target, Vec<u8>)> {
        let mut bytes = vec![0; 65535];
        let n = self.socket.recv(&mut bytes).await?;
        bytes.truncate(n);
        Ok((self.target.clone(), bytes))
    }
}
