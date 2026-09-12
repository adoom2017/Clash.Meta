//! Explicit oracle test: XRAY_BIN points to an independently downloaded official
//! Xray executable. The release executable never launches or links this oracle.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use meta_protocol::{
    BoxStream, Datagram, Target, record::RecordStream, vision::VisionStream, vless,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::{
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

struct Oracle(Child);
struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test]
#[ignore = "requires XRAY_BIN official oracle"]
async fn reality_vision_tcp_and_inner_tls() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(90), scenario()).await?
}
async fn scenario() -> Result<()> {
    let binary = std::env::var("XRAY_BIN").context("set XRAY_BIN to official Xray executable")?;
    let mut version = Command::new(&binary);
    version.arg("version");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        version.creation_flags(0x08000000);
    }
    let version = version.output()?;
    ensure!(
        version.status.success()
            && String::from_utf8_lossy(&version.stdout).starts_with("Xray 25.9.11 "),
        "oracle must be official Xray v25.9.11"
    );
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.signing_key.serialize_der(),
    ));
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], key)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let tls_port = listener.local_addr()?.port();
    let _tls_task = Task(tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted=listener.accept()=>{
                    let Ok((socket,_))=accepted else{break;};let acceptor=acceptor.clone();
                    tasks.spawn(async move {
                        if let Ok(mut stream)=acceptor.accept(socket).await {
                            let mut bytes=vec![0;16384];
                            while let Ok(n)=stream.read(&mut bytes).await {
                                if n==0{let _=stream.shutdown().await;break;}
                                if stream.write_all(&bytes[..n]).await.is_err(){break;}
                                let _=stream.flush().await;
                            }
                        }
                    });
                },
                _=tasks.join_next(),if !tasks.is_empty()=>{}
            }
        }
    }));
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_port = echo_listener.local_addr()?.port();
    let _echo_task = Task(tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted=echo_listener.accept()=>{
                    let Ok((mut stream,_))=accepted else{break;};
                    tasks.spawn(async move {let(mut r,mut w)=stream.split();let _=tokio::io::copy(&mut r,&mut w).await;});
                },
                _=tasks.join_next(),if !tasks.is_empty()=>{}
            }
        }
    }));
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let udp_port = udp.local_addr()?.port();
    let _udp_task = Task(tokio::spawn(async move {
        let mut bytes = vec![0; 65535];
        while let Ok((n, peer)) = udp.recv_from(&mut bytes).await {
            let _ = udp.send_to(&bytes[..n], peer).await;
        }
    }));
    let secret = x25519_dalek::StaticSecret::from([17; 32]);
    let public = x25519_dalek::PublicKey::from(&secret);
    let port = free_port();
    let id = uuid::Uuid::from_u128(0x112233445566778899aabbccddeeff00);
    let plain_id = uuid::Uuid::from_u128(0x112233445566778899aabbccddeeff01);
    let tmp = tempfile::tempdir()?;
    let config = serde_json::json!({"log":{"loglevel":"debug"},"inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless","settings":{"clients":[{"id":id,"flow":"xtls-rprx-vision"},{"id":plain_id}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"show":false,"dest":format!("127.0.0.1:{tls_port}"),"serverNames":["localhost"],"privateKey":URL_SAFE_NO_PAD.encode(secret.to_bytes()),"shortIds":["01020304"]}}}],"outbounds":[{"protocol":"freedom"}]});
    let path = tmp.path().join("server.json");
    std::fs::write(&path, serde_json::to_vec(&config)?)?;
    let log_path = tmp.path().join("oracle.log");
    let log = std::fs::File::create(&log_path)?;
    let mut command = Command::new(&binary);
    command
        .args(["run", "-config"])
        .arg(&path)
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut oracle = Oracle(command.spawn()?);
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        if let Some(status) = oracle.0.try_wait()? {
            anyhow::bail!(
                "oracle exited {status}: {}",
                std::fs::read_to_string(&log_path)?
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let options = meta_config::Reality {
        public_key: URL_SAFE_NO_PAD.encode(public.as_bytes()),
        short_id: "01020304".into(),
    };
    let result = async {
        for inner_tls in [false, true] {
            eprintln!("case inner_tls={inner_tls}: outer handshake");
            let config = meta_protocol::reality::config(&options, &["h2".into()])?;
            let socket = TcpStream::connect(("127.0.0.1", port)).await?;
            let mut stream = tokio::time::timeout(
                Duration::from_secs(8),
                RecordStream::handshake(
                    socket,
                    Arc::new(config),
                    ServerName::try_from("localhost")?,
                ),
            )
            .await
            .context("REALITY outer handshake timeout")??;
            eprintln!("outer authenticated");
            let target = Target::new("127.0.0.1", if inner_tls { tls_port } else { echo_port })?;
            stream
                .write_all(&vless::request(id, &target, 1, "xtls-rprx-vision")?)
                .await?;
            stream.flush().await?;
            let vision = VisionStream::new(stream, id)?;
            let mut stream: BoxStream = if inner_tls {
                let mut roots = rustls::RootCertStore::empty();
                roots.add(certificate.cert.der().clone())?;
                let config = rustls::ClientConfig::builder_with_provider(provider.clone())
                    .with_protocol_versions(&[&rustls::version::TLS13])?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                Box::new(
                    tokio::time::timeout(
                        Duration::from_secs(8),
                        tokio_rustls::TlsConnector::from(Arc::new(config))
                            .connect(ServerName::try_from("localhost")?, vision),
                    )
                    .await
                    .context("inner TLS handshake timeout")??,
                )
            } else {
                Box::new(vision)
            };
            // Several round trips exercise padded and unpadded/direct phases.
            for size in [1, 17, 8192, 32768, 131072] {
                eprintln!("echo {size}");
                let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
                stream.write_all(&payload).await?;
                stream.flush().await?;
                let mut received = vec![0; size];
                tokio::time::timeout(Duration::from_secs(8), stream.read_exact(&mut received))
                    .await
                    .context("Vision echo timeout")??;
                ensure!(payload == received, "Vision payload mismatch");
            }
        }
        let proxy: meta_config::Proxy = serde_json::from_value(serde_json::json!({
            "name":"reality", "type":"vless", "server":"127.0.0.1", "port":port,
            "uuid":id, "tls":true, "servername":"localhost", "flow":"xtls-rprx-vision",
            "reality-opts":{"public-key":options.public_key,"short-id":options.short_id}
        }))?;
        let target = Target::new("127.0.0.1", udp_port)?;
        let mut plain_proxy = proxy.clone();
        plain_proxy.flow.clear();
        plain_proxy.uuid = Some(plain_id);
        let mut plain = vless::connect(
            TcpStream::connect(("127.0.0.1", port)).await?,
            &plain_proxy,
            &Target::new("127.0.0.1", echo_port)?,
            1,
        )
        .await?;
        plain.write_all(b"reality-without-vision").await?;
        plain.flush().await?;
        let mut reply = [0; 22];
        plain.read_exact(&mut reply).await?;
        ensure!(
            &reply == b"reality-without-vision",
            "REALITY without Vision failed"
        );
        for multiplex in [false, true] {
            let stream = vless::connect(
                TcpStream::connect(("127.0.0.1", port)).await?,
                &plain_proxy,
                &target,
                if multiplex { 3 } else { 2 },
            )
            .await?;
            let session: Arc<dyn Datagram> = if multiplex {
                Arc::new(meta_protocol::xudp::Session::new(stream, target.clone()))
            } else {
                Arc::new(vless::UdpSession::new(stream, target.clone()))
            };
            session.send(&target, b"reality-udp").await?;
            let (source, reply) =
                tokio::time::timeout(Duration::from_secs(8), session.recv()).await??;
            ensure!(
                source == target && reply == b"reality-udp",
                "REALITY UDP failed xudp={multiplex}"
            );
        }
        let socket = TcpStream::connect(("127.0.0.1", port)).await?;
        let stream = vless::connect(socket, &proxy, &target, 3).await?;
        let session = meta_protocol::xudp::Session::new(stream, target.clone());
        for size in [1, 1232, 8192] {
            let payload = vec![42; size];
            session.send(&target, &payload).await?;
            let (source, reply) =
                tokio::time::timeout(Duration::from_secs(8), session.recv()).await??;
            ensure!(
                source == target && reply == payload,
                "Reality/Vision XUDP echo mismatch"
            );
        }
        let mut wrong_uuid = proxy.clone();
        wrong_uuid.uuid = Some(uuid::Uuid::nil());
        let rejected = async {
            let socket = TcpStream::connect(("127.0.0.1", port)).await?;
            let mut stream = vless::connect(
                socket,
                &wrong_uuid,
                &Target::new("127.0.0.1", echo_port)?,
                1,
            )
            .await?;
            stream.write_all(b"bad-id").await?;
            stream.flush().await?;
            stream.read_u8().await.map_err(anyhow::Error::from)
        };
        ensure!(
            tokio::time::timeout(Duration::from_secs(8), rejected)
                .await?
                .is_err(),
            "wrong UUID accepted"
        );
        for failure in ["short-id", "public-key", "sni"] {
            let mut wrong = options.clone();
            let mut name = "localhost";
            match failure {
                "short-id" => wrong.short_id = "ffffffff".into(),
                "public-key" => {
                    let secret = x25519_dalek::StaticSecret::from([33; 32]);
                    wrong.public_key =
                        URL_SAFE_NO_PAD.encode(x25519_dalek::PublicKey::from(&secret).as_bytes());
                }
                _ => name = "wrong.example",
            }
            let config = meta_protocol::reality::config(&wrong, &["h2".into()])?;
            let socket = TcpStream::connect(("127.0.0.1", port)).await?;
            let rejected = tokio::time::timeout(
                Duration::from_secs(8),
                RecordStream::handshake(socket, Arc::new(config), ServerName::try_from(name)?),
            )
            .await?;
            ensure!(rejected.is_err(), "wrong {failure} accepted");
        }
        // A fresh session must still work after all rejected authentications.
        for _ in 0..3 {
            let socket = TcpStream::connect(("127.0.0.1", port)).await?;
            let mut stream =
                vless::connect(socket, &proxy, &Target::new("127.0.0.1", echo_port)?, 1).await?;
            stream.write_all(b"reconnected").await?;
            stream.flush().await?;
            let mut reply = [0; 11];
            tokio::time::timeout(Duration::from_secs(8), stream.read_exact(&mut reply)).await??;
            ensure!(&reply == b"reconnected", "REALITY reconnect failed");
        }
        oracle.0.kill()?;
        oracle.0.wait()?;
        oracle.0 = command.spawn()?;
        let mut ready = false;
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        ensure!(ready, "restarted oracle did not listen");
        let mut stream = vless::connect(
            TcpStream::connect(("127.0.0.1", port)).await?,
            &proxy,
            &Target::new("127.0.0.1", echo_port)?,
            1,
        )
        .await?;
        stream.write_all(b"after-restart").await?;
        stream.flush().await?;
        let mut reply = [0; 13];
        tokio::time::timeout(Duration::from_secs(8), stream.read_exact(&mut reply)).await??;
        ensure!(
            &reply == b"after-restart",
            "REALITY reconnect after server restart failed"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if result.is_err() {
        eprintln!("{}", std::fs::read_to_string(&log_path)?);
    }
    result
}
