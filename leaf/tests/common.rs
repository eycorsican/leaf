use std::time::Duration;

use futures::future::abortable;
use futures::FutureExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, ToSocketAddrs, UdpSocket};
use tokio::time::timeout;

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
pub async fn run_leaf_instances(configs: Vec<String>) {
    let mut leaf_runners = Vec::new();
    for config in configs {
        let config = leaf::config::json::from_string(config).unwrap();
        let config = leaf::config::json::to_internal(config).unwrap();
        let task_runners = leaf::util::create_runners(config).unwrap();
        let task = async move {
            futures::future::join_all(task_runners).await;
        };
        leaf_runners.push(task);
    }
    futures::future::join_all(leaf_runners).await;
}

// Runs multiple leaf instances, thereafter a socks request will be sent to the
// given socks server to test the proxy chain. The proxy chain is expected to
// correctly handle the request to it's destination.
pub fn test_configs(configs: Vec<String>, socks_addr: &str, socks_port: u16) {
    let mut bg_tasks: Vec<leaf::Runner> = Vec::new();

    // Use an echo server as the destination of the socks request.
    let echo_server_task = run_echo_servers("127.0.0.1:3000");
    bg_tasks.push(Box::pin(echo_server_task));

    let leaf_task = run_leaf_instances(configs);
    bg_tasks.push(Box::pin(leaf_task));

    let (bg_task, bg_task_handle) = abortable(futures::future::join_all(bg_tasks));

    // Simulates an application request.
    let app_task = async move {
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
            bind: None,
            settings: Some(raw_settings),
        }];
        let config = leaf::config::json::Config {
            log: None,
            inbounds: None,
            outbounds: Some(outbounds),
            rules: None,
            dns: None,
        };
        let config = leaf::config::json::to_internal(config).unwrap();
        let outbound_manager = leaf::app::outbound::manager::OutboundManager::new(
            &config.outbounds,
            config.dns.as_ref().unwrap(),
        )
        .unwrap();
        let handler = outbound_manager.get("socks").unwrap();
        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip("127.0.0.1:3000".parse().unwrap());

        // Test TCP
        let mut s = handler.handle_tcp(&sess, None).await.unwrap();
        s.write_all(b"abc").await.unwrap();
        let mut buf = Vec::new();
        let n = s.read_buf(&mut buf).await.unwrap();
        assert_eq!("abc".to_string(), String::from_utf8_lossy(&buf[..n]));

        // Test UDP
        let dgram = handler.handle_udp(&sess, None).await.unwrap();
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

        // Cancel the background task.
        bg_task_handle.abort();
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(futures::future::join(bg_task, app_task).map(|_| ()));
}
