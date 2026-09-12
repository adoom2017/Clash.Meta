//! Fixed official Hysteria oracle; never linked or launched by the product.
use anyhow::{Context, Result, ensure};
use meta_config::Proxy;
use meta_platform::DefaultHooks;
use meta_protocol::{Target, hysteria2::Client};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinSet,
};
use tokio_util::task::AbortOnDropHandle;

struct Oracle {
    process: Child,
    config: std::path::PathBuf,
    log: std::path::PathBuf,
    binary: String,
    remote: SocketAddr,
    _directory: tempfile::TempDir,
}
impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        eprintln!(
            "oracle log: {}",
            std::fs::read_to_string(&self.log).unwrap_or_default()
        );
    }
}
fn command(binary: &str) -> Command {
    let mut cmd = Command::new(binary);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    cmd
}
impl Oracle {
    async fn start(host: &str, options: Value) -> Result<Self> {
        let binary =
            std::env::var("HYSTERIA_BIN").context("set HYSTERIA_BIN to official v2.6.4")?;
        let version = command(&binary).arg("version").output()?;
        ensure!(
            version.status.success()
                && String::from_utf8_lossy(&version.stdout)
                    .lines()
                    .any(|line| line.split_whitespace().collect::<Vec<_>>()
                        == ["Version:", "v2.6.4"]),
            "oracle must be official Hysteria v2.6.4"
        );
        let directory = tempfile::tempdir()?;
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(
            &cert,
            pem_rfc7468::encode_string(
                "CERTIFICATE",
                pem_rfc7468::LineEnding::LF,
                certificate.cert.der(),
            )?,
        )?;
        std::fs::write(
            &key,
            pem_rfc7468::encode_string(
                "PRIVATE KEY",
                pem_rfc7468::LineEnding::LF,
                &certificate.signing_key.serialize_der(),
            )?,
        )?;
        let reservation = UdpSocket::bind((host, 0)).await?;
        let remote = reservation.local_addr()?;
        drop(reservation);
        let mut cfg = json!({"listen":remote.to_string(),"tls":{"cert":cert,"key":key},
            "auth":{"type":"password","password":"synthetic-secret"}});
        for (key, value) in options.as_object().context("options object")? {
            cfg[key] = value.clone();
        }
        let config = directory.path().join("server.json");
        let log = directory.path().join("server.log");
        std::fs::write(&config, serde_json::to_vec(&cfg)?)?;
        let process = Self::spawn(&binary, &config, &log)?;
        let mut oracle = Self {
            process,
            config,
            log,
            binary,
            remote,
            _directory: directory,
        };
        oracle.ready().await?;
        Ok(oracle)
    }
    fn spawn(binary: &str, config: &std::path::Path, log: &std::path::Path) -> Result<Child> {
        let log = std::fs::File::create(log)?;
        Ok(command(binary)
            .args(["--disable-update-check", "--log-level", "debug"])
            .arg("server")
            .arg("--config")
            .arg(config)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?)
    }
    async fn ready(&mut self) -> Result<()> {
        for _ in 0..120 {
            ensure!(
                self.process.try_wait()?.is_none(),
                "oracle exited: {}",
                std::fs::read_to_string(&self.log)?
            );
            if std::fs::read_to_string(&self.log)?.contains("server up and running") {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        anyhow::bail!(
            "oracle startup timeout: {}",
            std::fs::read_to_string(&self.log)?
        )
    }
    fn proxy(&self) -> Result<Proxy> {
        Ok(serde_json::from_value(
            json!({"name":"hy2", "type":"hysteria2", "server":self.remote.ip().to_string(),
            "port":self.remote.port(), "password":"synthetic-secret", "sni":"localhost", "skip-cert-verify":true}),
        )?)
    }
    async fn restart(&mut self) -> Result<()> {
        self.process.kill()?;
        self.process.wait()?;
        self.process = Self::spawn(&self.binary, &self.config, &self.log)?;
        self.ready().await
    }
}

struct Echo {
    tcp: Target,
    udp: Target,
    _tcp_task: AbortOnDropHandle<()>,
    _udp_task: AbortOnDropHandle<()>,
}
impl Echo {
    async fn start(host: &str) -> Result<Self> {
        let tcp = TcpListener::bind((host, 0)).await?;
        let udp = UdpSocket::bind((host, 0)).await?;
        let tcp_target = Target::new(host, tcp.local_addr()?.port())?;
        let udp_target = Target::new(host, udp.local_addr()?.port())?;
        let tcp_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = tcp.accept() => {
                        let Ok((mut stream, _)) = accepted else { break };
                        tasks.spawn(async move {
                            let (mut read, mut write) = stream.split();
                            let _ = tokio::io::copy(&mut read, &mut write).await;
                        });
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        }));
        let udp_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut bytes = vec![0; 65535];
            while let Ok((n, peer)) = udp.recv_from(&mut bytes).await {
                let _ = udp.send_to(&bytes[..n], peer).await;
            }
        }));
        Ok(Self {
            tcp: tcp_target,
            udp: udp_target,
            _tcp_task: tcp_task,
            _udp_task: udp_task,
        })
    }
    async fn tcp(&self, client: &Client, size: usize) -> Result<()> {
        let mut stream = client.tcp(&self.tcp).await?;
        let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
        let mut received = vec![0; size];
        let (mut read, mut write) = tokio::io::split(&mut stream);
        tokio::try_join!(write.write_all(&payload), read.read_exact(&mut received))?;
        ensure!(payload == received, "HY2 TCP payload mismatch");
        write.shutdown().await?;
        Ok(())
    }
    async fn udp(&self, client: &Arc<Client>) -> Result<()> {
        let session = client.udp()?;
        for size in [1, 1200, 4000] {
            let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            session.send(&self.udp, &payload).await?;
            let (target, received) = tokio::time::timeout(Duration::from_secs(5), session.recv())
                .await
                .with_context(|| format!("HY2 UDP reply size={size}"))??;
            ensure!(
                target == self.udp && payload == received,
                "HY2 UDP mismatch at size {size}"
            );
        }
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires HYSTERIA_BIN official v2.6.4 oracle"]
async fn tcp_udp_ipv4_ipv6_salamander_and_negative_authentication() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    tokio::time::timeout(Duration::from_secs(70), async {
        for host in ["127.0.0.1", "::1"] {
            for obfs in [false, true] {
                eprintln!("HY2 host={host} salamander={obfs}");
                let oracle = Oracle::start(host, if obfs {json!({"obfs":{"type":"salamander","salamander":{"password":"synthetic-obfs"}}})} else {json!({})}).await?;
                let echo = Echo::start(host).await?;
                let mut proxy = oracle.proxy()?;
                if obfs { proxy.obfs=Some("salamander".into()); proxy.obfs_password="synthetic-obfs".into(); }
                let client = Client::connect(&proxy, oracle.remote, &DefaultHooks).await?;
                echo.tcp(&client, 131072).await?;
                echo.udp(&client).await?;
                let mut wrong = proxy.clone();
                wrong.password = "invalid-auth".into();
                ensure!(Client::connect(&wrong, oracle.remote, &DefaultHooks).await.is_err(), "wrong password accepted");
                wrong = proxy.clone();
                wrong.skip_cert_verify = false;
                ensure!(Client::connect(&wrong, oracle.remote, &DefaultHooks).await.is_err(), "untrusted certificate accepted");
                if obfs {
                    wrong = proxy.clone();
                    wrong.obfs_password = "wrong-obfs".into();
                    ensure!(!matches!(tokio::time::timeout(Duration::from_millis(800), Client::connect(&wrong, oracle.remote, &DefaultHooks)).await, Ok(Ok(_))), "wrong obfs accepted");
                }
                let fresh = Client::connect(&proxy, oracle.remote, &DefaultHooks).await?;
                echo.tcp(&fresh, 17).await?;
                let unused = TcpListener::bind((host, 0)).await?;
                let rejected = Target::new(host, unused.local_addr()?.port())?;
                drop(unused);
                ensure!(fresh.tcp(&rejected).await.is_err(), "unreachable target accepted");
                echo.tcp(&fresh, 17).await?;
            }
        }
        Ok::<_, anyhow::Error>(())
    }).await?
}

#[tokio::test]
#[ignore = "requires HYSTERIA_BIN official v2.6.4 oracle"]
async fn bandwidth_negotiation_pacing_udp_disable_and_restart() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60), async {
        let echo = Echo::start("127.0.0.1").await?;
        let mut oracle = Oracle::start(
            "127.0.0.1",
            json!({"bandwidth":{"down":"1 mbps"},"disableUDP":true}),
        )
        .await?;
        let mut proxy = oracle.proxy()?;
        proxy.up = Some("2 mbps".into());
        let client = Client::connect(&proxy, oracle.remote, &DefaultHooks).await?;
        ensure!(client.send_rate() == 125000, "server cap not negotiated");
        ensure!(client.udp().is_err(), "UDP disable ignored");
        let start = Instant::now();
        echo.tcp(&client, 262144).await?;
        ensure!(
            start.elapsed() >= Duration::from_secs(2),
            "negotiated pacing not applied"
        );
        oracle.restart().await?;
        let fresh = Client::connect(&proxy, oracle.remote, &DefaultHooks).await?;
        echo.tcp(&fresh, 17).await?;
        let automatic = Oracle::start("127.0.0.1", json!({"ignoreClientBandwidth":true})).await?;
        let mut proxy = automatic.proxy()?;
        proxy.up = Some("1 kbps".into());
        let client = Client::connect(&proxy, automatic.remote, &DefaultHooks).await?;
        ensure!(client.send_rate() == 0, "server auto request ignored");
        echo.tcp(&client, 32768).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
#[ignore = "requires HYSTERIA_BIN official v2.6.4 oracle"]
async fn salamander_port_hopping_preserves_tcp_and_udp() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(35), async {
        let oracle = Oracle::start(
            "127.0.0.1",
            json!({"obfs":{"type":"salamander","salamander":{"password":"synthetic-obfs"}}}),
        )
        .await?;
        let echo = Echo::start("127.0.0.1").await?;
        // Two port forwards share one backend NAT socket, like server DNAT rules.
        let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        backend.connect(oracle.remote).await?;
        let fronts = [
            Arc::new(UdpSocket::bind("127.0.0.1:0").await?),
            Arc::new(UdpSocket::bind("127.0.0.1:0").await?),
        ];
        let counters = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
        type ReturnPath = Arc<std::sync::Mutex<Option<(Arc<UdpSocket>, SocketAddr)>>>;
        let return_path: ReturnPath = Arc::new(std::sync::Mutex::new(None));
        let mut tasks = JoinSet::new();
        for (front, counter) in fronts.iter().cloned().zip(counters.iter().cloned()) {
            let backend = backend.clone();
            let return_path = return_path.clone();
            tasks.spawn(async move {
                let mut packet = vec![0; 65535];
                while let Ok((n, source)) = front.recv_from(&mut packet).await {
                    *return_path.lock().unwrap() = Some((front.clone(), source));
                    counter.fetch_add(1, Ordering::Relaxed);
                    let _ = backend.send(&packet[..n]).await;
                }
            });
        }
        tasks.spawn(async move {
            let mut packet = vec![0; 65535];
            while let Ok(n) = backend.recv(&mut packet).await {
                let route = return_path.lock().unwrap().clone();
                if let Some((socket, peer)) = route {
                    let _ = socket.send_to(&packet[..n], peer).await;
                }
            }
        });
        let mut proxy = oracle.proxy()?;
        proxy.ports = Some(format!(
            "{},{}",
            fronts[0].local_addr()?.port(),
            fronts[1].local_addr()?.port()
        ));
        proxy.hop_interval = "5s".into();
        proxy.obfs = Some("salamander".into());
        proxy.obfs_password = "synthetic-obfs".into();
        let client = Client::connect(&proxy, oracle.remote, &DefaultHooks).await?;
        let mut stream = client.tcp(&echo.tcp).await?;
        for round in 0..3 {
            stream.write_all(b"hop").await?;
            let mut reply = [0; 3];
            stream.read_exact(&mut reply).await?;
            ensure!(&reply == b"hop", "TCP failed across port hop");
            echo.udp(&client).await?;
            if round < 2 {
                tokio::time::sleep(Duration::from_millis(5200)).await;
            }
        }
        ensure!(
            counters.iter().all(|v| v.load(Ordering::Relaxed) > 0),
            "both forwarded ports must carry packets"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
