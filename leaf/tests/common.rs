use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;

use futures::future::abortable;
use futures::FutureExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, ToSocketAddrs, UdpSocket};
use tokio::sync::RwLock;
use tokio::time::timeout;

use leaf::proxy::*;
use leaf::session::Session;

pub async fn run_tcp_echo_server<A: ToSocketAddrs>(addr: A) {
    let listener = TcpListener::bind(addr).await.unwrap();
    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
            Err(e) => {
                panic!("accept tcp failed: {}", e);
            }
        }
    }
}

pub async fn run_udp_echo_server<A: ToSocketAddrs>(addr: A) {
    let socket = UdpSocket::bind(addr).await.unwrap();
    let mut buf = vec![0u8; 2 * 1024];
    loop {
        let (n, raddr) = socket.recv_from(&mut buf).await.unwrap();
        let _ = socket.send_to(&buf[..n], &raddr).await.unwrap();
    }
}

// Runs echo servers.
pub async fn run_echo_servers<A: ToSocketAddrs + 'static + Copy>(addr: A) {
    let tcp_task = run_tcp_echo_server(addr);
    let udp_task = run_udp_echo_server(addr);
    futures::future::join(tcp_task, udp_task).await;
}

// Runs multiple leaf instances.
pub fn run_leaf_instances(
    rt: &tokio::runtime::Runtime,
    configs: Vec<String>,
) -> Vec<leaf::RuntimeId> {
    let mut leaf_rt_ids = Vec::new();
    let mut rt_id = 0;
    for config in configs {
        let config = leaf::config::json::from_string(&config).unwrap();
        let opts = leaf::StartOptions {
            config: leaf::Config::Internal(config),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: leaf::RuntimeOption::SingleThread,
        };
        rt.spawn_blocking(move || {
            leaf::start(rt_id, opts).unwrap();
        });
        leaf_rt_ids.push(rt_id);
        rt_id += 1;
    }
    leaf_rt_ids
}

fn new_socks_outbound(socks_addr: &str, socks_port: u16) -> AnyOutboundHandler {
    // Make use of a socks outbound to initiate a socks request to a leaf instance.
    let settings = leaf::config::json::SocksOutboundSettings {
        address: Some(socks_addr.to_string()),
        port: Some(socks_port),
    };
    let settings_str = serde_json::to_string(&settings).unwrap();
    let raw_settings = serde_json::value::RawValue::from_string(settings_str).unwrap();
    let outbounds = vec![leaf::config::json::Outbound {
        protocol: "socks".to_string(),
        tag: Some("socks".to_string()),
        settings: Some(raw_settings),
    }];
    let mut config = leaf::config::json::Config {
        log: None,
        inbounds: None,
        outbounds: Some(outbounds),
        router: None,
        dns: None,
    };
    let config = leaf::config::json::to_internal(&mut config).unwrap();
    let dns_client = Arc::new(RwLock::new(
        leaf::app::dns_client::DnsClient::new(&config.dns).unwrap(),
    ));
    let outbound_manager =
        leaf::app::outbound::manager::OutboundManager::new(&config.outbounds, dns_client).unwrap();
    let handler = outbound_manager.get("socks").unwrap();
    handler
}

pub async fn new_socks_stream(socks_addr: &str, socks_port: u16, sess: &Session) -> AnyStream {
    let handler = new_socks_outbound(socks_addr, socks_port);
    let stream = tokio::net::TcpStream::connect(format!("{}:{}", socks_addr, socks_port))
        .await
        .unwrap();
    TcpOutboundHandler::handle(handler.as_ref(), sess, Some(Box::new(stream)))
        .await
        .unwrap()
}

pub async fn new_socks_datagram(
    socks_addr: &str,
    socks_port: u16,
    sess: &Session,
) -> AnyOutboundDatagram {
    let handler = new_socks_outbound(socks_addr, socks_port);
    UdpOutboundHandler::handle(handler.as_ref(), sess, None)
        .await
        .unwrap()
}

pub fn test_tcp_half_close_on_configs(configs: Vec<String>, socks_addr: &str, socks_port: u16) {
    std::env::set_var("TCP_DOWNLINK_TIMEOUT", "3");
    std::env::set_var("TCP_UPLINK_TIMEOUT", "3");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let leaf_rt_ids = run_leaf_instances(&rt, configs);
    let socks_addr = socks_addr.to_string();
    let res = rt.block_on(rt.spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip("127.0.0.1:3000".parse().unwrap());

        let mut client_stream = new_socks_stream(&socks_addr, socks_port, &sess).await;
        let (mut server_stream, _) = listener.accept().await.unwrap();

        // client <-> server
        //
        // Ensure both directions work.
        //
        // When testing with proxy protocols need additional info from the other
        // side to initialize itself, such as shadowsocks needs a salt from the
        // other side, we must forward some payload first.
        client_stream.write_all(b"hello").await.unwrap();
        let mut buf = Vec::new();
        let n = server_stream.read_buf(&mut buf).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "hello");
        server_stream.write_all(b"world").await.unwrap();
        let mut buf = Vec::new();
        let n = client_stream.read_buf(&mut buf).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "world");

        // client(shutdown) <-> server
        //
        // The case client performs a shutdown.
        //
        // The expected behaiver is, the client socket is no longer writable
        // after the shutdown, but can still read data from server socket.
        // The server socket can write data to client, a read on the server socket
        // will return zero bytes (EOF) immediately. After TCP_DOWNLINK_TIMEOUT and
        // reading out all previous transfered data, a read on client socket should
        // also return zero bytes immediately even though we havn't explicitly
        // shutdown the server socket, this verifies TCP_DOWNLINK_TIMEOUT works as
        // expected.
        client_stream.shutdown().await.unwrap();
        let res = client_stream
            .write_all(b"hello")
            .await
            .map_err(|e| e.kind());
        assert_eq!(res, Err(ErrorKind::BrokenPipe));
        server_stream.write_all(b"world").await.unwrap();
        let mut buf = Vec::new();
        let n = client_stream.read_buf(&mut buf).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "world");
        let mut buf = Vec::new();
        let n = timeout(Duration::from_millis(20), server_stream.read_buf(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
        tokio::time::sleep(
            Duration::from_secs(*leaf::option::TCP_DOWNLINK_TIMEOUT)
                .checked_sub(Duration::from_secs(1))
                .unwrap(),
        )
        .await;
        server_stream.write_all(b"world").await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let res = client_stream.read_buf(&mut buf).await.unwrap();
        assert_eq!(res, 5);
        let mut buf = Vec::new();
        let n = timeout(Duration::from_millis(20), client_stream.read_buf(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);

        let mut client_stream = new_socks_stream(&socks_addr, socks_port, &sess).await;
        let (mut server_stream, _) = listener.accept().await.unwrap();

        // Another direction.
        //
        // client <-> server
        //
        // Ensure both directions work.
        //
        // When testing with proxy protocols need additional info from the other
        // side to initialize itself, such as shadowsocks needs a salt from the
        // other side, we must forward some payload first.
        client_stream.write_all(b"hello").await.unwrap();
        let mut buf = Vec::new();
        let n = server_stream.read_buf(&mut buf).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "hello");
        server_stream.write_all(b"world").await.unwrap();
        let mut buf = Vec::new();
        let n = client_stream.read_buf(&mut buf).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "world");

        server_stream.shutdown().await.unwrap();
        client_stream.write_all(b"hello").await.unwrap();
        let mut buf = Vec::new();
        let n = server_stream.read_buf(&mut buf).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "hello");
        let res = server_stream
            .write_all(b"world")
            .await
            .map_err(|e| e.kind());
        assert_eq!(res, Err(ErrorKind::BrokenPipe));
        let mut buf = Vec::new();
        let n = timeout(Duration::from_millis(20), client_stream.read_buf(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
        tokio::time::sleep(
            Duration::from_secs(*leaf::option::TCP_UPLINK_TIMEOUT)
                .checked_sub(Duration::from_millis(500))
                .unwrap(),
        )
        .await;
        client_stream.write_all(b"world").await.unwrap();
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let res = server_stream.read_buf(&mut buf).await.unwrap();
        assert_eq!(res, 5);
        let mut buf = Vec::new();
        let n = timeout(Duration::from_millis(20), server_stream.read_buf(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
    }));
    for id in leaf_rt_ids.into_iter() {
        leaf::shutdown(id);
    }
    assert!(res.is_ok());
}

// Runs multiple leaf instances, thereafter a socks request will be sent to the
// given socks server to test the proxy chain. The proxy chain is expected to
// correctly handle the request to it's destination.
pub fn test_configs(configs: Vec<String>, socks_addr: &str, socks_port: u16) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Use an echo server as the destination of the socks request.
    let mut bg_tasks: Vec<leaf::Runner> = Vec::new();
    let echo_server_task = run_echo_servers("127.0.0.1:3000");
    bg_tasks.push(Box::pin(echo_server_task));
    let (bg_task, bg_task_handle) = abortable(futures::future::join_all(bg_tasks));

    let leaf_rt_ids = run_leaf_instances(&rt, configs);

    // Simulates an application request.
    let app_task = async move {
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip("127.0.0.1:3000".parse().unwrap());
        let mut s = new_socks_stream(socks_addr, socks_port, &sess).await;
        s.write_all(b"abc").await.unwrap();
        let mut buf = Vec::new();
        let n = s.read_buf(&mut buf).await.unwrap();
        assert_eq!("abc".to_string(), String::from_utf8_lossy(&buf[..n]));

        // Test UDP
        let dgram = new_socks_datagram(socks_addr, socks_port, &sess).await;
        let (mut r, mut s) = dgram.split();
        let msg = b"def";
        let n = s.send_to(&msg.to_vec(), &sess.destination).await.unwrap();
        assert_eq!(msg.len(), n);
        let mut buf = vec![0u8; 2 * 1024];
        let (n, raddr) = timeout(Duration::from_secs(1), r.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg, &buf[..n]);
        assert_eq!(&raddr, &sess.destination);

        // Test if we can handle a second UDP session. This can fail in stream
        // transports if the stream ID has not been correctly set.
        let dgram2 = new_socks_datagram(socks_addr, socks_port, &sess).await;
        let (mut r, mut s) = dgram2.split();
        let msg = b"ghi";
        let n = s.send_to(&msg.to_vec(), &sess.destination).await.unwrap();
        assert_eq!(msg.len(), n);
        let mut buf = vec![0u8; 2 * 1024];
        let (n, raddr) = timeout(Duration::from_secs(1), r.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg, &buf[..n]);
        assert_eq!(&raddr, &sess.destination);

        // Cancel the background task.
        bg_task_handle.abort();
    };
    rt.block_on(futures::future::join(bg_task, app_task).map(|_| ()));
    for id in leaf_rt_ids.into_iter() {
        assert!(leaf::shutdown(id));
    }
}
