use anyhow::{Context, Result, ensure};
use meta_config::Config;
use meta_protocol::{Datagram, Target, vless, xudp};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn proxy(tls: bool, insecure: bool) -> meta_config::Proxy {
    Config::parse(format!("proxies:\n- name: test\n  type: vless\n  server: localhost\n  port: 443\n  uuid: 11223344-5566-7788-99aa-bbccddeeff00\n  tls: {tls}\n  skip-cert-verify: {insecure}\n").as_bytes()).unwrap().proxies.remove(0)
}

fn tls_server_version(version: &'static rustls::SupportedProtocolVersion) -> rustls::ServerConfig {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap()
}

fn tls_server() -> rustls::ServerConfig {
    tls_server_version(&rustls::version::TLS13)
}

#[tokio::test]
async fn tls12_supports_vless_but_rejects_vision_before_request() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        for vision in [false, true] {
            let (client, server) = tokio::io::duplex(8192);
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_server_version(
                &rustls::version::TLS12,
            )));
            let task = tokio::spawn(async move {
                let mut stream = acceptor.accept(server).await?;
                let byte = stream.read_u8().await;
                if vision {
                    ensure!(byte.is_err(), "Vision sent a request over TLS 1.2");
                } else {
                    ensure!(byte? == 0, "VLESS version mismatch");
                }
                Ok::<_, anyhow::Error>(())
            });
            let mut proxy = proxy(true, true);
            if vision {
                proxy.flow = "xtls-rprx-vision".into();
            }
            let stream = vless::connect(client, &proxy, &Target::new("example.com", 80)?, 1).await;
            ensure!(stream.is_err() == vision, "incorrect TLS 1.2 handling");
            drop(stream);
            task.await??;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn tcp_plain_and_tls_fragmented_reply_and_large_transfer() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        for tls in [false, true] {
            let config = proxy(tls, true);
            for host in ["127.0.0.1", "2001:db8::1", "example.com"] {
                let target = Target::new(host, 8443)?;
                let header = vless::request(config.uuid.unwrap(), &target, 1, "")?;
                let (client, server) = tokio::io::duplex(128);
                let server_config = tls_server();
                let task = tokio::spawn(async move {
                    let mut server: meta_protocol::BoxStream = if tls {
                        Box::new(
                            tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                                .accept(server)
                                .await?,
                        )
                    } else {
                        Box::new(server)
                    };
                    let mut request = vec![0; header.len()];
                    server.read_exact(&mut request).await?;
                    ensure!(request == header, "VLESS request mismatch");
                    // Wait for data before responding, as real VLESS peers do.
                    let first = server.read_u8().await?;
                    for byte in [0, 2, 9, 9, first] {
                        server.write_u8(byte).await?;
                        server.flush().await?;
                    }
                    let (mut reader, mut writer) = tokio::io::split(server);
                    tokio::io::copy(&mut reader, &mut writer).await?;
                    writer.shutdown().await?;
                    Ok::<_, anyhow::Error>(())
                });
                let stream = vless::connect(client, &config, &target, 1).await?;
                let payload: Vec<_> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
                let (mut reader, mut writer) = tokio::io::split(stream);
                let upload = async {
                    writer.write_all(&payload).await?;
                    writer.shutdown().await
                };
                let download = async {
                    let mut result = Vec::new();
                    reader.read_to_end(&mut result).await?;
                    Ok::<_, std::io::Error>(result)
                };
                let (_, received) = tokio::try_join!(upload, download)
                    .with_context(|| format!("client tls={tls} host={host}"))?;
                ensure!(received == payload, "TCP echo mismatch");
                task.await?
                    .with_context(|| format!("server tls={tls} host={host}"))?;
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn tls_rejects_untrusted_certificate_before_sending_uuid() -> Result<()> {
    let config = proxy(true, false);
    let (client, server) = tokio::io::duplex(8192);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_server()));
    let task = tokio::spawn(async move { acceptor.accept(server).await });
    let result = vless::connect(client, &config, &Target::new("example.com", 80)?, 1).await;
    assert!(result.is_err());
    task.abort();
    let _ = task.await;
    Ok(())
}

#[tokio::test]
async fn udp_framing_preserves_packet_boundaries() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        for multiplex in [false, true] {
            let config = proxy(false, false);
            let target = Target::new("1.2.3.4", 53)?;
            let (client, mut server) = tokio::io::duplex(64);
            let expected = vless::request(
                config.uuid.unwrap(),
                &target,
                if multiplex { 3 } else { 2 },
                "",
            )?;
            let task = tokio::spawn(async move {
                let mut header = vec![0; expected.len()];
                server.read_exact(&mut header).await?;
                ensure!(header == expected, "UDP request mismatch");
                server.write_all(&[0, 0]).await?;
                for index in 0..4 {
                    if multiplex {
                        let length = server.read_u16().await?;
                        ensure!(length == 12, "unexpected XUDP metadata length");
                        let mut metadata = [0; 12];
                        server.read_exact(&mut metadata).await?;
                        ensure!(
                            metadata
                                == [
                                    0,
                                    0,
                                    if index == 0 { 1 } else { 2 },
                                    1,
                                    2,
                                    0,
                                    53,
                                    1,
                                    1,
                                    2,
                                    3,
                                    4
                                ],
                            "XUDP metadata mismatch"
                        );
                    }
                    let length = server.read_u16().await?;
                    let mut payload = vec![0; length as usize];
                    server.read_exact(&mut payload).await?;
                    if multiplex {
                        server.write_all(&[0, 4, 0, 0, 2, 1]).await?;
                    }
                    server.write_u16(length).await?;
                    server.write_all(&payload).await?;
                    server.flush().await?;
                }
                Ok::<_, anyhow::Error>(())
            });
            let stream =
                vless::connect(client, &config, &target, if multiplex { 3 } else { 2 }).await?;
            let session: Arc<dyn Datagram> = if multiplex {
                Arc::new(xudp::Session::new(stream, target.clone()))
            } else {
                Arc::new(vless::UdpSession::new(stream, target.clone()))
            };
            for size in [0, 1, 1232, 65507] {
                let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
                session.send(&target, &payload).await?;
                ensure!(
                    session.recv().await? == (target.clone(), payload),
                    "UDP echo mismatch"
                );
            }
            task.await??;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
