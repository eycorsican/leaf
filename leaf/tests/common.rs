use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::future::abortable;
use futures::FutureExt;
use rand::RngCore;
use rand::{rngs::StdRng, Rng, SeedableRng};
use sha2::{Digest, Sha256};
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
        username: None,
        password: None,
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
    timeout(
        Duration::from_secs(2),
        handler.stream().unwrap().handle(sess, Some(Box::new(stream))),
    )
    .await
    .unwrap()
    .unwrap()
}

pub async fn new_socks_datagram(
    socks_addr: &str,
    socks_port: u16,
    sess: &Session,
) -> AnyOutboundDatagram {
    let handler = new_socks_outbound(socks_addr, socks_port);
    timeout(
        Duration::from_secs(2),
        handler.datagram().unwrap().handle(sess, None),
    )
    .await
    .unwrap()
    .unwrap()
}

pub fn test_tcp_half_close_on_configs(configs: Vec<String>, socks_addr: &str, socks_port: u16) {
    log::warn!("testing tcp half close");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let leaf_rt_ids = run_leaf_instances(&rt, configs);
    let socks_addr = socks_addr.to_string();
    let res = rt.block_on(rt.spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
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
        assert!(res.is_err());
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
        assert!(res.is_err());
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
        assert!(rt
            .block_on(rt.spawn(async move {
                timeout(Duration::from_millis(50), wait_for_shutdown(id))
                    .await
                    .unwrap();
            }))
            .is_ok());
    }
    assert!(res.is_ok());
}

async fn file_hash<P: AsRef<Path>>(p: P) -> Box<[u8]> {
    let mut src = tokio::fs::File::open(p).await.unwrap();
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    while let Ok(n) = src.read_buf(&mut buf).await {
        if n == 0 {
            break;
        } else {
            hasher.write(&buf[..n]);
        }
    }
    hasher.finalize().as_slice().to_owned().into_boxed_slice()
}

pub fn test_data_transfering_reliability_on_configs(
    configs: Vec<String>,
    socks_addr: &str,
    socks_port: u16,
) {
    log::warn!("testing data transfering reliability");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    let src_file = "source_random_bytes.bin";
    let dst_file = "destination_random_bytes.bin";
    let source = path.join(src_file);
    let dst = path.join(dst_file);
    if !source.exists() {
        let mut rng = StdRng::from_entropy();
        let mut data = vec![0u8; 25 * 1024 * 1024]; // 25MB payload
        rng.fill_bytes(&mut data);
        let mut f = std::fs::File::create(source).unwrap();
        f.write_all(&data).unwrap();
        f.sync_all().unwrap();
    }

    // TCP uplink
    let recv_task = async move {
        let source = path.join(src_file);
        let dst = path.join(dst_file);
        let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
        let (mut stream, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        if dst.exists() {
            tokio::fs::remove_file(&dst).await.unwrap();
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .unwrap();
        let n = timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut stream, &mut dst_file),
        )
        .await
        .unwrap()
        .unwrap();
        dst_file.sync_all().await.unwrap();
        assert_eq!(dst_file.metadata().await.unwrap().len(), n);
        let src_hash = file_hash(source).await;
        let dst_hash = file_hash(&dst).await;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
    };
    let socks_addr_cloned = socks_addr.to_string();
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    let send_task = async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let source = path.join(src_file);
        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip("127.0.0.1:3000".parse().unwrap());
        let mut stream = new_socks_stream(&socks_addr_cloned, socks_port, &sess).await;
        let mut src = tokio::fs::File::open(source).await.unwrap();
        timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut src, &mut stream),
        )
        .await
        .unwrap()
        .unwrap();
    };
    let leaf_rt_ids = run_leaf_instances(&rt, configs.clone());
    let mut futs: Vec<leaf::Runner> = Vec::new();
    futs.push(Box::pin(recv_task));
    futs.push(Box::pin(send_task));
    let res = rt.block_on(rt.spawn(futures::future::join_all(futs)));
    for id in leaf_rt_ids.into_iter() {
        leaf::shutdown(id);
        assert!(rt
            .block_on(rt.spawn(async move {
                timeout(Duration::from_millis(50), wait_for_shutdown(id))
                    .await
                    .unwrap();
            }))
            .is_ok());
    }
    assert!(res.is_ok());

    // TCP downlink
    let socks_addr_cloned = socks_addr.to_string();
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    let recv_task = async move {
        let source = path.join(src_file);
        let dst = path.join(dst_file);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip("127.0.0.1:3000".parse().unwrap());
        let mut stream = new_socks_stream(&socks_addr_cloned, socks_port, &sess).await;
        if dst.exists() {
            tokio::fs::remove_file(&dst).await.unwrap();
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .unwrap();
        let n = timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut stream, &mut dst_file),
        )
        .await
        .unwrap()
        .unwrap();
        dst_file.sync_all().await.unwrap();
        assert_eq!(dst_file.metadata().await.unwrap().len(), n);
        let src_hash = file_hash(source).await;
        let dst_hash = file_hash(&dst).await;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
    };
    let socks_addr_cloned = socks_addr.to_string();
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    let send_task = async move {
        let source = path.join(src_file);
        let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
        let (mut stream, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut src = tokio::fs::File::open(source).await.unwrap();
        timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut src, &mut stream),
        )
        .await
        .unwrap()
        .unwrap();
    };
    let leaf_rt_ids = run_leaf_instances(&rt, configs.clone());
    let mut futs: Vec<leaf::Runner> = Vec::new();
    futs.push(Box::pin(recv_task));
    futs.push(Box::pin(send_task));
    let res = rt.block_on(rt.spawn(futures::future::join_all(futs)));
    for id in leaf_rt_ids.into_iter() {
        leaf::shutdown(id);
        assert!(rt
            .block_on(rt.spawn(async move {
                timeout(Duration::from_millis(50), wait_for_shutdown(id))
                    .await
                    .unwrap();
            }))
            .is_ok());
    }
    assert!(res.is_ok());

    // UDP uplink
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    let recv_task = async move {
        let source = path.join(src_file);
        let dst = path.join(dst_file);
        let socket = UdpSocket::bind("127.0.0.1:3000").await.unwrap();
        if dst.exists() {
            tokio::fs::remove_file(&dst).await.unwrap();
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .unwrap();
        let expected_total_bytes = tokio::fs::File::open(&source)
            .await
            .unwrap()
            .metadata()
            .await
            .unwrap()
            .len() as usize;
        let mut recvd_bytes: usize = 0;
        let mut buf = vec![0u8; 1500];
        let mut recvd_data = Vec::new();
        loop {
            assert!(recvd_bytes <= expected_total_bytes);
            if recvd_bytes == expected_total_bytes {
                break;
            }
            let (n, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            recvd_data.push((&buf[..n]).to_vec());
            recvd_bytes += n;
        }
        for data in recvd_data.into_iter() {
            dst_file.write(&data).await.unwrap();
        }
        dst_file.sync_all().await.unwrap();
        assert_eq!(
            dst_file.metadata().await.unwrap().len() as usize,
            expected_total_bytes
        );
        let src_hash = file_hash(&source).await;
        let dst_hash = file_hash(&dst).await;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
    };
    let socks_addr_cloned = socks_addr.to_string();
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    let send_task = async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let source = path.join(src_file);
        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip("127.0.0.1:3000".parse().unwrap());
        let mut dgram = new_socks_datagram(&socks_addr_cloned, socks_port, &sess).await;
        let (_, mut s) = dgram.split();
        let mut src = tokio::fs::File::open(source).await.unwrap();
        let mut buf = vec![0u8; 1500];
        loop {
            // Since UDP is unordered and unreliable, even tests on local could
            // fail, make some delay to mitigate this.
            tokio::time::sleep(Duration::from_millis(1)).await;
            let n = timeout(Duration::from_secs(2), src.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            if n > 0 {
                let n = timeout(
                    Duration::from_secs(2),
                    s.send_to(&buf[..n], &sess.destination),
                )
                .await
                .unwrap()
                .unwrap();
            } else {
                break;
            }
        }
    };
    let leaf_rt_ids = run_leaf_instances(&rt, configs.clone());
    let mut futs: Vec<leaf::Runner> = Vec::new();
    futs.push(Box::pin(recv_task));
    futs.push(Box::pin(send_task));
    let res = rt.block_on(rt.spawn(futures::future::join_all(futs)));
    for id in leaf_rt_ids.into_iter() {
        leaf::shutdown(id);
        assert!(rt
            .block_on(rt.spawn(async move {
                timeout(Duration::from_millis(50), wait_for_shutdown(id))
                    .await
                    .unwrap();
            }))
            .is_ok());
    }
    assert!(res.is_ok());

    // UDP downlink
    let socks_addr_cloned = socks_addr.to_string();
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    let recv_task = async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip("127.0.0.1:3000".parse().unwrap());
        let mut dgram = new_socks_datagram(&socks_addr_cloned, socks_port, &sess).await;
        let (mut r, mut s) = dgram.split();
        let source = path.join(src_file);
        let mut buf = vec![0u8; 1500];
        if dst.exists() {
            tokio::fs::remove_file(&dst).await.unwrap();
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .unwrap();
        let expected_total_bytes = tokio::fs::File::open(&source)
            .await
            .unwrap()
            .metadata()
            .await
            .unwrap()
            .len() as usize;
        let mut recvd_bytes: usize = 0;
        let mut buf = vec![0u8; 1500];
        let mut recvd_data = Vec::new();
        // Send a datagram to establish the session.
        s.send_to(b"hello", &sess.destination).await.unwrap();
        loop {
            assert!(recvd_bytes <= expected_total_bytes);
            if recvd_bytes == expected_total_bytes {
                break;
            }
            let (n, _) = timeout(Duration::from_secs(2), r.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            recvd_data.push((&buf[..n]).to_vec());
            recvd_bytes += n;
        }
        for data in recvd_data.into_iter() {
            dst_file.write(&data).await.unwrap();
        }
        dst_file.sync_all().await.unwrap();
        assert_eq!(
            dst_file.metadata().await.unwrap().len() as usize,
            expected_total_bytes
        );
        let src_hash = file_hash(&source).await;
        let dst_hash = file_hash(&dst).await;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
    };
    let socks_addr_cloned = socks_addr.to_string();
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    let send_task = async move {
        let mut socket = UdpSocket::bind("127.0.0.1:3000").await.unwrap();
        let source = path.join(src_file);
        let mut src = tokio::fs::File::open(source).await.unwrap();
        let mut buf = vec![0u8; 1500];
        // Receive a single packet to decide the remote peer.
        let (_, raddr) = socket.recv_from(&mut buf).await.unwrap();
        loop {
            // Since UDP is unordered and unreliable, even tests on local could
            // fail, make some delay to mitigate this.
            tokio::time::sleep(Duration::from_millis(1)).await;
            let n = timeout(Duration::from_secs(2), src.read(&mut buf))
                .await
                .unwrap()
                .unwrap();
            if n > 0 {
                let n = timeout(Duration::from_secs(2), socket.send_to(&buf[..n], &raddr))
                    .await
                    .unwrap()
                    .unwrap();
            } else {
                break;
            }
        }
    };
    let leaf_rt_ids = run_leaf_instances(&rt, configs.clone());
    let mut futs: Vec<leaf::Runner> = Vec::new();
    futs.push(Box::pin(recv_task));
    futs.push(Box::pin(send_task));
    let res = rt.block_on(rt.spawn(futures::future::join_all(futs)));
    for id in leaf_rt_ids.into_iter() {
        leaf::shutdown(id);
        assert!(rt
            .block_on(rt.spawn(async move {
                timeout(Duration::from_millis(50), wait_for_shutdown(id))
                    .await
                    .unwrap();
            }))
            .is_ok());
    }
    assert!(res.is_ok());
}

// Runs multiple leaf instances, thereafter a socks request will be sent to the
// given socks server to test the proxy chain. The proxy chain is expected to
// correctly handle the request to it's destination.
pub fn test_configs(configs: Vec<String>, socks_addr: &str, socks_port: u16) {
    log::warn!("testing configs");
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
    let socks_addr = socks_addr.to_string();
    let app_task = async move {
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip("127.0.0.1:3000".parse().unwrap());
        let mut s = timeout(
            Duration::from_secs(1),
            new_socks_stream(&socks_addr, socks_port, &sess),
        )
        .await
        .unwrap();
        timeout(Duration::from_secs(1), s.write_all(b"abc"))
            .await
            .unwrap()
            .unwrap();
        let mut buf = Vec::new();
        let n = timeout(Duration::from_secs(1), s.read_buf(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!("abc".to_string(), String::from_utf8_lossy(&buf[..n]));

        // Test UDP
        let dgram = timeout(
            Duration::from_secs(1),
            new_socks_datagram(&socks_addr, socks_port, &sess),
        )
        .await
        .unwrap();
        let (mut r, mut s) = dgram.split();
        let msg = b"def";
        let n = timeout(
            Duration::from_secs(1),
            s.send_to(&msg.to_vec(), &sess.destination),
        )
        .await
        .unwrap()
        .unwrap();
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
        let dgram2 = timeout(
            Duration::from_secs(1),
            new_socks_datagram(&socks_addr, socks_port, &sess),
        )
        .await
        .unwrap();
        let (mut r, mut s) = dgram2.split();
        let msg = b"ghi";
        let n = timeout(
            Duration::from_secs(1),
            s.send_to(&msg.to_vec(), &sess.destination),
        )
        .await
        .unwrap()
        .unwrap();
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
    let bg_task = async move {
        bg_task.await;
    };
    let mut futs = Vec::new();
    futs.push(rt.spawn(bg_task));
    futs.push(rt.spawn(app_task));
    let res = rt.block_on(futures::future::select_all(futs));
    for id in leaf_rt_ids.into_iter() {
        assert!(leaf::shutdown(id));
        assert!(rt
            .block_on(rt.spawn(async move {
                timeout(Duration::from_millis(50), wait_for_shutdown(id))
                    .await
                    .unwrap();
            }))
            .is_ok());
    }
    assert!(res.0.is_ok());
}

async fn wait_for_shutdown(id: leaf::RuntimeId) {
    loop {
        if !leaf::is_running(id) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
