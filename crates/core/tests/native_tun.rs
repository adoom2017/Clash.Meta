#![cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
use meta_core::Core;
use meta_platform::{DefaultHooks, native::NativeTun};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct OwnedRoute(route_manager::Route);
impl Drop for OwnedRoute {
    fn drop(&mut self) {
        let mut manager = route_manager::RouteManager::new().unwrap();
        for route in manager.list().unwrap().into_iter().filter(|route| {
            route.network() == self.0.network()
                && route.prefix() == self.0.prefix()
                && route.if_index() == self.0.if_index()
        }) {
            manager.delete(&route).unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires root/administrator and a working native TUN driver; changes only an isolated test /32 route"]
async fn operating_system_tcp_and_udp_use_native_tun_and_restore_route() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let oracle = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = oracle.local_addr().unwrap();
        let config = meta_config::Config::parse(format!("tun: {{enable: true, auto-route: false}}\nproxies:\n- name: test\n  type: vless\n  server: 127.0.0.1\n  port: {}\n  uuid: 11223344-5566-7788-99aa-bbccddeeff00\nrules: ['MATCH,test']\n", address.port()).as_bytes()).unwrap();
        let core = Core::new(config, Arc::new(DefaultHooks)).unwrap();
        let name = if cfg!(target_os = "macos") {"utun19"} else {"meta-test"};
        let device = Arc::new(NativeTun::open(name, 1500, true).unwrap());
        let route = route_manager::Route::new("198.19.254.253".parse().unwrap(), 32).with_if_index(device.index().unwrap());
        #[cfg(target_os = "linux")]
        let route = route.with_table(254);
        let mut manager = route_manager::RouteManager::new().unwrap();
        assert!(!manager.list().unwrap().iter().any(|r| r.network() == route.network() && r.prefix() == 32));
        manager.add(&route).unwrap();
        let route = OwnedRoute(route);
        let running = core.start_with_packets(Some(device)).await.unwrap();
        let server = tokio::spawn(async move {
            for udp in [false, true] {
                let (mut stream, _) = oracle.accept().await.unwrap();
                let mut request = [0; 26]; stream.read_exact(&mut request).await.unwrap();
                assert_eq!(request[18], if udp {2} else {1});
                assert_eq!(&request[22..26], &[198, 19, 254, 253]);
                if udp { assert_eq!(stream.read_u16().await.unwrap(), 4); }
                let mut data = [0; 4]; stream.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"ping");
                stream.write_all(&[0, 0]).await.unwrap();
                if udp { stream.write_u16(4).await.unwrap(); }
                stream.write_all(b"pong").await.unwrap();
            }
        });
        let mut tcp = tokio::net::TcpStream::connect("198.19.254.253:23456").await.unwrap();
        tcp.write_all(b"ping").await.unwrap(); let mut reply = [0; 4]; tcp.read_exact(&mut reply).await.unwrap(); assert_eq!(&reply, b"pong");
        drop(tcp);
        let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        udp.send_to(b"ping", "198.19.254.253:23457").await.unwrap();
        let (n, source) = udp.recv_from(&mut reply).await.unwrap();
        assert_eq!(n, 4); assert_eq!(&reply, b"pong"); assert_eq!(source.to_string(), "198.19.254.253:23457");
        server.await.unwrap();
        running.shutdown().await;
        drop(route);
        assert!(!manager.list().unwrap().iter().any(|r| r.network().to_string() == "198.19.254.253" && r.prefix() == 32));
    }).await.unwrap();
}
