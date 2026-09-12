use super::*;
use tokio::io::AsyncReadExt;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn configuration(server: SocketAddr, xudp: bool) -> Config {
    Config::parse(format!("proxies:\n- name: vless\n  type: vless\n  server: {}\n  port: {}\n  uuid: 11223344-5566-7788-99aa-bbccddeeff00\n  xudp: {xudp}\nrules: ['MATCH,vless']\n", server.ip(), server.port()).as_bytes()).unwrap()
}

async fn read_http_header(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut bytes = vec![];
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 32768);
        bytes.push(stream.read_u8().await.unwrap());
    }
    bytes
}

#[tokio::test]
async fn mixed_socks_and_http_connect_use_vless_and_restore_fake_ip() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for socks in [false, true] {
            let oracle = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = configuration(oracle.local_addr().unwrap(), false);
            config.mixed_port = free_port();
            let port = config.mixed_port;
            let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
            let name = hickory_proto::rr::Name::from_ascii("example.test").unwrap();
            let mut query = hickory_proto::op::Message::new();
            query.add_query(hickory_proto::op::Query::query(
                name,
                hickory_proto::rr::RecordType::A,
            ));
            let answer = core
                .resolver
                .answer(&query.to_vec().unwrap())
                .await
                .unwrap();
            let answer = hickory_proto::op::Message::from_vec(&answer).unwrap();
            let hickory_proto::rr::RData::A(fake) = answer.answers()[0].data() else {
                panic!("expected A")
            };
            let fake = fake.0;
            let task = tokio::spawn(async move {
                let (mut server, _) = oracle.accept().await.unwrap();
                let mut request = [0; 19];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(request[0], 0);
                assert_eq!(&request[17..], &[0, 1]);
                assert_eq!(server.read_u16().await.unwrap(), 443);
                assert_eq!(server.read_u8().await.unwrap(), 2);
                let n = server.read_u8().await.unwrap();
                let mut host = vec![0; n as usize];
                server.read_exact(&mut host).await.unwrap();
                assert_eq!(host, b"example.test");
                let mut payload = [0; 4];
                server.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
                server.write_all(b"\x00\x00pong").await.unwrap();
            });
            let running = core.start().await.unwrap();
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            if socks {
                client.write_all(&[5, 1, 0]).await.unwrap();
                let mut reply = [0; 2];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply, [5, 0]);
                let mut request = vec![5, 1, 0, 1];
                request.extend(fake.octets());
                request.extend(443u16.to_be_bytes());
                client.write_all(&request).await.unwrap();
                let mut reply = [0; 10];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[1], 0);
            } else {
                client
                    .write_all(
                        format!("CONNECT {fake}:443 HTTP/1.1\r\nHost: {fake}:443\r\n\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                assert!(
                    read_http_header(&mut client)
                        .await
                        .starts_with(b"HTTP/1.1 200")
                );
            }
            client.write_all(b"ping").await.unwrap();
            let mut reply = [0; 4];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"pong");
            drop(client);
            task.await.unwrap();
            running.shutdown().await;
            assert!(
                tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_err()
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn core_selects_udp_or_xudp_from_configuration() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for xudp in [false, true] {
            let oracle = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let core = Core::new(
                configuration(oracle.local_addr().unwrap(), xudp),
                Arc::new(meta_platform::DefaultHooks),
            )
            .unwrap();
            let task = tokio::spawn(async move {
                let (mut stream, _) = oracle.accept().await.unwrap();
                let mut request = [0; 19];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[17..], &[0, if xudp { 3 } else { 2 }]);
                if xudp {
                    assert_eq!(stream.read_u16().await.unwrap(), 12);
                    let mut metadata = [0; 12];
                    stream.read_exact(&mut metadata).await.unwrap();
                    assert_eq!(metadata, [0, 0, 1, 1, 2, 0, 53, 1, 1, 2, 3, 4]);
                } else {
                    let mut target = [0; 7];
                    stream.read_exact(&mut target).await.unwrap();
                    assert_eq!(target, [0, 53, 1, 1, 2, 3, 4]);
                }
                assert_eq!(stream.read_u16().await.unwrap(), 4);
                let mut data = [0; 4];
                stream.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"ping");
                stream.write_all(&[0, 0]).await.unwrap();
                if xudp {
                    stream.write_all(&[0, 4, 0, 0, 2, 1]).await.unwrap();
                }
                stream.write_all(b"\x00\x04pong").await.unwrap();
            });
            let target = Target::new("1.2.3.4", 53).unwrap();
            let session = core.datagram(&target).await.unwrap();
            session.send(&target, b"ping").await.unwrap();
            assert_eq!(session.recv().await.unwrap(), (target, b"pong".to_vec()));
            task.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks_udp_reconnects_after_outbound_closes() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for xudp in [false, true] {
            let oracle = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut config = configuration(oracle.local_addr().unwrap(), xudp);
            config.socks_port = free_port();
            let port = config.socks_port;
            let core = Core::new(config, Arc::new(meta_platform::DefaultHooks)).unwrap();
            let running = core.start().await.unwrap();
            let task = tokio::spawn(async move {
                for round in 0..3u8 {
                    let (mut stream, _) = oracle.accept().await.unwrap();
                    let mut header = vec![0; if xudp { 19 } else { 26 }];
                    stream.read_exact(&mut header).await.unwrap();
                    assert_eq!(header[18], if xudp { 3 } else { 2 });
                    if xudp {
                        let length = stream.read_u16().await.unwrap();
                        let mut metadata = vec![0; length as usize];
                        stream.read_exact(&mut metadata).await.unwrap();
                        assert_eq!(metadata[2], 1);
                    }
                    assert_eq!(stream.read_u16().await.unwrap(), 1);
                    assert_eq!(stream.read_u8().await.unwrap(), round);
                    stream.write_all(&[0, 0]).await.unwrap();
                    if xudp {
                        stream.write_all(&[0, 4, 0, 0, 2, 1]).await.unwrap();
                    }
                    stream.write_all(&[0, 1, round]).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            });
            let mut control = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            control.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            control.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            control
                .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut reply = [0; 10];
            control.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[..4], &[5, 0, 0, 1]);
            let relay = SocketAddr::from((
                [reply[4], reply[5], reply[6], reply[7]],
                u16::from_be_bytes([reply[8], reply[9]]),
            ));
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            for round in 0..3u8 {
                let packet = [0, 0, 0, 1, 1, 2, 3, 4, 0, 53, round];
                loop {
                    socket.send_to(&packet, relay).await.unwrap();
                    let mut reply = [0; 128];
                    if let Ok(Ok((n, source))) = tokio::time::timeout(
                        Duration::from_millis(100),
                        socket.recv_from(&mut reply),
                    )
                    .await
                    {
                        assert_eq!(source, relay);
                        assert_eq!(&reply[..n], &packet);
                        break;
                    }
                }
            }
            task.await.unwrap();
            drop(control);
            running.shutdown().await;
        }
    })
    .await
    .unwrap();
}
