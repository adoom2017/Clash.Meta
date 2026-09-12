//! Independent regression for the locally maintained generic Quinn setting.
use anyhow::{Result, ensure};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{sync::Arc, time::Duration};

#[tokio::test]
async fn advertised_frame_bound_preserves_receive_queue_capacity() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
            )?;
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.initial_mtu(1452).mtu_discovery_config(None);
        server_cfg.transport_config(Arc::new(transport));
        let server = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse()?)?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone())?;
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
        ));
        let mut transport = quinn::TransportConfig::default();
        transport
            .datagram_receive_buffer_size(Some(65536))
            .datagram_max_frame_size(Some(1200));
        config.transport_config(Arc::new(transport));
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        client.set_default_client_config(config);
        let (outbound, inbound) =
            tokio::join!(client.connect(server.local_addr()?, "localhost")?, async {
                server.accept().await.unwrap().await
            });
        let outbound = outbound?;
        let inbound = inbound?;
        ensure!(
            inbound.max_datagram_size().unwrap() <= 1200,
            "frame limit was not advertised"
        );
        for n in 0..8u8 {
            inbound.send_datagram_wait(vec![n; 1100].into()).await?;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            let bytes = outbound.read_datagram().await?;
            ensure!(bytes.len() == 1100, "bad datagram size");
            seen.insert(bytes[0]);
        }
        ensure!(
            seen.len() == 8,
            "aggregate queue was incorrectly capped to one frame"
        );
        client.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
