use anyhow::{Context, Result, ensure};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use meta_config::Dns;
use meta_platform::Hooks;
use meta_protocol::Target;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct CacheEntry {
    records: Vec<Record>,
    expires: Instant,
}
struct FakeMap {
    by_name: HashMap<(String, bool), IpAddr>,
    by_ip: HashMap<IpAddr, String>,
    next4: u32,
    next6: u128,
}
pub struct Resolver {
    pub config: Dns,
    hooks: Hooks,
    cache: Mutex<HashMap<(String, RecordType), CacheEntry>>,
    fake: Mutex<FakeMap>,
}
impl Resolver {
    pub fn new(config: Dns, hooks: Hooks) -> Self {
        Self {
            config,
            hooks,
            cache: Mutex::new(HashMap::new()),
            fake: Mutex::new(FakeMap {
                by_name: HashMap::new(),
                by_ip: HashMap::new(),
                next4: 2,
                next6: 2,
            }),
        }
    }
    pub fn original(&self, ip: IpAddr) -> Option<String> {
        self.fake.lock().unwrap().by_ip.get(&ip).cloned()
    }
    pub async fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let (a, aaaa) = tokio::join!(self.records(host, RecordType::A), async {
            if self.config.ipv6 {
                self.records(host, RecordType::AAAA).await
            } else {
                Ok(vec![])
            }
        });
        let mut addresses = vec![];
        for r in a.into_iter().chain(aaaa).flatten() {
            match r.data() {
                RData::A(ip) => addresses.push(SocketAddr::new(IpAddr::V4(ip.0), port)),
                RData::AAAA(ip) => addresses.push(SocketAddr::new(IpAddr::V6(ip.0), port)),
                _ => {}
            }
        }
        ensure!(!addresses.is_empty(), "DNS lookup returned no addresses");
        Ok(addresses)
    }
    async fn records(&self, host: &str, kind: RecordType) -> Result<Vec<Record>> {
        let key = (host.trim_end_matches('.').to_ascii_lowercase(), kind);
        if let Some(entry) = self.cache.lock().unwrap().get(&key)
            && entry.expires > Instant::now()
        {
            let ttl = entry
                .expires
                .saturating_duration_since(Instant::now())
                .as_secs() as u32;
            let mut records = entry.records.clone();
            for r in &mut records {
                r.set_ttl(r.ttl().min(ttl));
            }
            return Ok(records);
        }
        let query = Query::query(Name::from_ascii(host)?, kind);
        let mut request = Message::new();
        request
            .set_id(uuid::Uuid::new_v4().as_u128() as u16)
            .set_recursion_desired(true)
            .add_query(query);
        let response = self.exchange(&request).await?;
        ensure!(
            response.response_code() == ResponseCode::NoError
                || response.response_code() == ResponseCode::NXDomain,
            "DNS server rejected query"
        );
        let records = response.answers().to_vec();
        let ttl = records
            .iter()
            .map(Record::ttl)
            .min()
            .unwrap_or(30)
            .min(3600);
        if ttl > 0 {
            let mut cache = self.cache.lock().unwrap();
            cache.retain(|_, v| v.expires > Instant::now());
            if cache.len() >= 4096
                && let Some(k) = cache.keys().next().cloned()
            {
                cache.remove(&k);
            }
            cache.insert(
                key,
                CacheEntry {
                    records: records.clone(),
                    expires: Instant::now() + Duration::from_secs(ttl as u64),
                },
            );
        }
        Ok(records)
    }
    async fn exchange(&self, request: &Message) -> Result<Message> {
        let mut error = anyhow::anyhow!("no DNS upstream");
        for upstream in &self.config.nameserver {
            match tokio::time::timeout(
                Duration::from_secs(5),
                self.query_upstream(upstream, request),
            )
            .await
            {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(e)) => error = e,
                Err(e) => error = e.into(),
            }
        }
        Err(error)
    }
    async fn bootstrap(&self, host: &str, port: u16) -> Result<SocketAddr> {
        if let Ok(ip) = host.parse() {
            return Ok(SocketAddr::new(ip, port));
        }
        let mut msg = Message::new();
        msg.set_id(uuid::Uuid::new_v4().as_u128() as u16)
            .set_recursion_desired(true)
            .add_query(Query::query(Name::from_ascii(host)?, RecordType::A));
        for server in &self.config.default_nameserver {
            let addr = parse_server(server, 53)?;
            let Ok(ip) = addr.host.parse::<IpAddr>() else {
                continue;
            };
            if let Ok(response) = self.raw_udp(SocketAddr::new(ip, addr.port), &msg).await {
                for r in response.answers() {
                    if let RData::A(ip) = r.data() {
                        return Ok(SocketAddr::new(IpAddr::V4(ip.0), port));
                    }
                }
            }
        }
        anyhow::bail!("DNS bootstrap failed")
    }
    async fn query_upstream(&self, server: &str, request: &Message) -> Result<Message> {
        if server.starts_with("https://") {
            let uri: http::Uri = server.parse()?;
            let host = uri.host().context("DoH host missing")?;
            let addr = self.bootstrap(host, uri.port_u16().unwrap_or(443)).await?;
            let socket = meta_platform::tcp_connect(addr, &*self.hooks).await?;
            let config = meta_protocol::tls::config(&["http/1.1".into()], false)?;
            let mut tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
                .connect(
                    rustls::pki_types::ServerName::try_from(host.to_owned())?,
                    socket,
                )
                .await?;
            let body = request.to_vec()?;
            let path = uri
                .path_and_query()
                .map(|v| v.as_str())
                .unwrap_or("/dns-query");
            let header = format!(
                "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            tls.write_all(header.as_bytes()).await?;
            tls.write_all(&body).await?;
            tls.flush().await?;
            let mut response = vec![];
            let mut byte = [0];
            while !response.ends_with(b"\r\n\r\n") {
                ensure!(response.len() < 16384, "DoH header limit");
                tls.read_exact(&mut byte).await?;
                response.push(byte[0]);
            }
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut parsed = httparse::Response::new(&mut headers);
            parsed.parse(&response)?;
            ensure!(parsed.code == Some(200), "DoH HTTP error");
            let chunked = parsed.headers.iter().any(|h| {
                h.name.eq_ignore_ascii_case("transfer-encoding")
                    && h.value.eq_ignore_ascii_case(b"chunked")
            });
            let mut body = vec![];
            if chunked {
                loop {
                    let mut line = vec![];
                    while !line.ends_with(b"\r\n") {
                        ensure!(line.len() < 128, "DoH chunk header limit");
                        tls.read_exact(&mut byte).await?;
                        line.push(byte[0]);
                    }
                    let n = usize::from_str_radix(
                        std::str::from_utf8(&line)?
                            .trim()
                            .split(';')
                            .next()
                            .unwrap(),
                        16,
                    )?;
                    if n == 0 {
                        break;
                    }
                    ensure!(body.len() + n <= 65535, "DoH body limit");
                    let start = body.len();
                    body.resize(start + n, 0);
                    tls.read_exact(&mut body[start..]).await?;
                    let mut crlf = [0; 2];
                    tls.read_exact(&mut crlf).await?;
                    ensure!(&crlf == b"\r\n", "invalid chunk terminator");
                }
            } else {
                let n = parsed
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .context("DoH content-length missing")?;
                let n = std::str::from_utf8(n.value)?.parse::<usize>()?;
                ensure!(n <= 65535, "DoH body limit");
                body.resize(n, 0);
                tls.read_exact(&mut body).await?;
            }
            let response = Message::from_vec(&body)?;
            validate_response(request, &response)?;
            return Ok(response);
        }
        let tcp = server.starts_with("tcp://");
        let raw = server
            .trim_start_matches("udp://")
            .trim_start_matches("tcp://");
        let target = parse_server(raw, 53)?;
        let addr = self.bootstrap(&target.host, target.port).await?;
        if tcp {
            self.raw_tcp(addr, request).await
        } else {
            let response = self.raw_udp(addr, request).await?;
            if response.truncated() {
                self.raw_tcp(addr, request).await
            } else {
                Ok(response)
            }
        }
    }
    async fn raw_udp(&self, addr: SocketAddr, request: &Message) -> Result<Message> {
        let bind = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()?;
        let socket = meta_platform::udp_bind(bind, &*self.hooks)?;
        socket.connect(addr).await?;
        socket.send(&request.to_vec()?).await?;
        let mut bytes = vec![0; 65535];
        let n = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut bytes)).await??;
        let response = Message::from_vec(&bytes[..n])?;
        validate_response(request, &response)?;
        Ok(response)
    }
    async fn raw_tcp(&self, addr: SocketAddr, request: &Message) -> Result<Message> {
        let mut socket = meta_platform::tcp_connect(addr, &*self.hooks).await?;
        let bytes = request.to_vec()?;
        socket.write_u16(bytes.len() as u16).await?;
        socket.write_all(&bytes).await?;
        let n = socket.read_u16().await?;
        let mut bytes = vec![0; n as usize];
        socket.read_exact(&mut bytes).await?;
        let response = Message::from_vec(&bytes)?;
        validate_response(request, &response)?;
        Ok(response)
    }
    pub async fn answer(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let request = Message::from_vec(bytes)?;
        ensure!(
            request.message_type() == MessageType::Query
                && request.op_code() == OpCode::Query
                && request.queries().len() == 1,
            "unsupported DNS request"
        );
        let query = &request.queries()[0];
        let host = query
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let excluded = self.config.fake_ip_filter.iter().any(|pattern| {
            host == *pattern
                || pattern
                    .strip_prefix("*.")
                    .is_some_and(|suffix| host == suffix || host.ends_with(&format!(".{suffix}")))
        });
        let mut response = Message::new();
        response
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_recursion_desired(request.recursion_desired())
            .set_recursion_available(true)
            .add_query(query.clone());
        if query.query_type() == RecordType::AAAA && !self.config.ipv6 {
            return Ok(response.to_vec()?);
        }
        if self.config.enhanced_mode == "fake-ip"
            && !excluded
            && matches!(query.query_type(), RecordType::A | RecordType::AAAA)
        {
            let ip = self.fake_address(&host, query.query_type() == RecordType::AAAA)?;
            let data = match ip {
                IpAddr::V4(ip) => RData::A(A(ip)),
                IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
            };
            response.add_answer(Record::from_rdata(query.name().clone(), 60, data));
        } else {
            match self.exchange(&request).await {
                Ok(upstream) => {
                    response = upstream;
                }
                Err(_) => {
                    response.set_response_code(ResponseCode::ServFail);
                }
            }
        }
        Ok(response.to_vec()?)
    }
    fn fake_address(&self, host: &str, v6: bool) -> Result<IpAddr> {
        let mut map = self.fake.lock().unwrap();
        let key = (host.into(), v6);
        if let Some(ip) = map.by_name.get(&key) {
            return Ok(*ip);
        }
        ensure!(
            map.by_name.len() < 32768,
            "fake-IP capacity reached; refusing to reuse live mappings"
        );
        let ip = if v6 {
            let net = self.config.fake_ip_range6;
            let ip = std::net::Ipv6Addr::from(u128::from(net.network()) + map.next6);
            ensure!(net.contains(&ip), "fake-IP v6 pool exhausted");
            map.next6 += 1;
            IpAddr::V6(ip)
        } else {
            let net = self.config.fake_ip_range;
            let ip = std::net::Ipv4Addr::from(u32::from(net.network()) + map.next4);
            ensure!(
                net.contains(&ip) && ip != net.broadcast(),
                "fake-IP v4 pool exhausted"
            );
            map.next4 += 1;
            IpAddr::V4(ip)
        };
        map.by_name.insert(key, ip);
        map.by_ip.insert(ip, host.into());
        Ok(ip)
    }
}
fn parse_server(server: &str, default: u16) -> Result<Target> {
    if let Ok(ip) = server.parse::<IpAddr>() {
        Target::new(ip.to_string(), default)
    } else if let Ok(target) = Target::parse(server) {
        Ok(target)
    } else {
        Target::new(server, default)
    }
}
fn validate_response(request: &Message, response: &Message) -> Result<()> {
    ensure!(
        response.id() == request.id()
            && response.message_type() == MessageType::Response
            && response.queries() == request.queries(),
        "DNS response mismatch"
    );
    Ok(())
}
