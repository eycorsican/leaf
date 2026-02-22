#![allow(dead_code)]

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::future::abortable;

use rand::RngCore;
use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::info;

use leaf::proxy::*;
use leaf::session::Session;

static NEXT_RT_ID: AtomicU16 = AtomicU16::new(0);

pub async fn run_tcp_echo_server(
    addr: &str,
) -> anyhow::Result<(
    std::net::SocketAddr,
    impl std::future::Future<Output = anyhow::Result<()>>,
)> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind tcp failed: {}", e))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
    let fut = async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let (mut r, mut w) = stream.split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("accept tcp failed: {}", e));
                }
            }
        }
    };
    Ok((local_addr, fut))
}

pub async fn run_udp_echo_server(
    addr: &str,
) -> anyhow::Result<(
    std::net::SocketAddr,
    impl std::future::Future<Output = anyhow::Result<()>>,
)> {
    let socket = UdpSocket::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind udp failed: {}", e))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
    let fut = async move {
        let mut buf = vec![0u8; 2 * 1024];
        loop {
            let (n, raddr) = socket
                .recv_from(&mut buf)
                .await
                .map_err(|e| anyhow::anyhow!("recv udp failed: {}", e))?;
            let _ = socket
                .send_to(&buf[..n], &raddr)
                .await
                .map_err(|e| anyhow::anyhow!("send udp failed: {}", e))?;
        }
    };
    Ok((local_addr, fut))
}

// Runs multiple leaf instances.
pub fn run_leaf_instances(
    rt: &tokio::runtime::Runtime,
    configs: Vec<String>,
) -> anyhow::Result<Vec<leaf::RuntimeId>> {
    let mut leaf_rt_ids = Vec::new();
    for config in configs {
        let rt_id = NEXT_RT_ID.fetch_add(1, Ordering::Relaxed);
        let config = leaf::config::from_string(&config)
            .map_err(|e| anyhow::anyhow!("parse config failed: {}", e))?;
        let opts = leaf::StartOptions {
            config: leaf::Config::Internal(config),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: leaf::RuntimeOption::SingleThread,
        };
        rt.spawn_blocking(move || {
            if let Err(e) = leaf::start(rt_id, opts) {
                panic!("start leaf failed: {}", e);
            }
        });
        leaf_rt_ids.push(rt_id);
    }
    Ok(leaf_rt_ids)
}

fn new_socks_outbound(
    socks_addr: &str,
    socks_port: u16,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<AnyOutboundHandler> {
    // Make use of a socks outbound to initiate a socks request to a leaf instance.
    let settings = leaf::config::json::SocksOutboundSettings {
        address: Some(socks_addr.to_string()),
        port: Some(socks_port),
        username,
        password,
    };
    let outbounds = vec![leaf::config::json::Outbound {
        tag: Some("socks".to_string()),
        settings: leaf::config::json::OutboundSettings::Socks {
            settings: Some(settings),
        },
    }];
    let config = leaf::config::json::Config {
        log: None,
        inbounds: None,
        outbounds: Some(outbounds),
        router: None,
        dns: None,
    };
    let config = leaf::config::json::to_internal(config).map_err(|e| anyhow::anyhow!(e))?;
    let dns_client = Arc::new(RwLock::new(
        leaf::app::dns_client::DnsClient::new(&config.dns).map_err(|e| anyhow::anyhow!(e))?,
    ));
    let outbound_manager =
        leaf::app::outbound::manager::OutboundManager::new(&config.outbounds, dns_client)
            .map_err(|e| anyhow::anyhow!(e))?;

    Ok((outbound_manager
        .get("socks")
        .ok_or_else(|| anyhow::anyhow!("socks outbound not found"))?) as _)
}

pub async fn new_socks_stream(
    socks_addr: &str,
    socks_port: u16,
    sess: &Session,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<AnyStream> {
    // Use a socks outbound to simulate a client request.
    let handler = new_socks_outbound(socks_addr, socks_port, username, password)?;
    let stream = tokio::net::TcpStream::connect(format!("{}:{}", socks_addr, socks_port)).await?;
    timeout(
        Duration::from_secs(2),
        handler.stream().map_err(|e| anyhow::anyhow!(e))?.handle(
            sess,
            None,
            Some(Box::new(stream)),
        ),
    )
    .await?
    .map_err(|e| anyhow::anyhow!(e))
}

pub async fn new_socks_datagram(
    socks_addr: &str,
    socks_port: u16,
    sess: &Session,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<AnyOutboundDatagram> {
    // Use a socks outbound to simulate a client request.
    let handler = new_socks_outbound(socks_addr, socks_port, username, password)?;
    timeout(
        Duration::from_secs(2),
        handler
            .datagram()
            .map_err(|e| anyhow::anyhow!(e))?
            .handle(sess, None),
    )
    .await?
    .map_err(|e| anyhow::anyhow!(e))
}

pub fn test_tcp_half_close_on_configs(
    configs: Vec<String>,
    socks_addr: &str,
    socks_port: u16,
) -> anyhow::Result<()> {
    info!("testing tcp half close");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("build runtime failed: {}", e))?;
    let leaf_rt_ids = run_leaf_instances(&rt, configs)?;
    let socks_addr = socks_addr.to_string();
    let res = rt.block_on(rt.spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| anyhow::anyhow!("bind tcp failed: {}", e))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip(local_addr);
        let mut client_stream =
            new_socks_stream(&socks_addr, socks_port, &sess, None, None).await?;
        let (mut server_stream, _) = listener
            .accept()
            .await
            .map_err(|e| anyhow::anyhow!("accept tcp failed: {}", e))?;

        // client <-> server
        //
        // Ensure both directions work.
        //
        // When testing with proxy protocols need additional info from the other
        // side to initialize itself, such as shadowsocks needs a salt from the
        // other side, we must forward some payload first.
        client_stream
            .write_all(b"hello")
            .await
            .map_err(|e| anyhow::anyhow!("write hello failed: {}", e))?;
        let mut buf = Vec::new();
        let n = server_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read hello failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "hello");
        server_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world failed: {}", e))?;
        let mut buf = Vec::new();
        let n = client_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read world failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "world");

        // client(shutdown) <-> server
        //
        // The case client performs a shutdown.
        //
        // The expected behaiver is, the client socket is no longer writable
        // after the shutdown, but can still read data from server socket.
        // The server socket can write data to client, a read on the server socket
        // will return zero bytes (EOF) immediately. After TCP_DOWNLINK_TIMEOUT and
        // reading out all previous transferred data, a read on client socket should
        // also return zero bytes immediately even though we havn't explicitly
        // shutdown the server socket, this verifies TCP_DOWNLINK_TIMEOUT works as
        // expected.
        client_stream
            .shutdown()
            .await
            .map_err(|e| anyhow::anyhow!("shutdown client failed: {}", e))?;
        let res = client_stream
            .write_all(b"hello")
            .await
            .map_err(|e| e.kind());
        assert!(res.is_err());
        server_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world after shutdown failed: {}", e))?;
        let mut buf = Vec::new();
        let n = client_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read world after shutdown failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "world");
        let mut buf = Vec::new();
        let n = timeout(Duration::from_millis(20), server_stream.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("timeout read failed: {}", e))?
            .map_err(|e| anyhow::anyhow!("read failed: {}", e))?;
        assert_eq!(n, 0);
        tokio::time::sleep(
            Duration::from_secs(*leaf::option::TCP_DOWNLINK_TIMEOUT)
                .checked_sub(Duration::from_secs(1))
                .ok_or_else(|| anyhow::anyhow!("duration sub failed"))?,
        )
        .await;
        server_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world after timeout failed: {}", e))?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let res = client_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read buf after timeout failed: {}", e))?;
        assert_eq!(res, 5);
        let mut buf = Vec::new();
        let n = timeout(Duration::from_millis(20), client_stream.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("timeout read 2 failed: {}", e))?
            .map_err(|e| anyhow::anyhow!("read 2 failed: {}", e))?;
        assert_eq!(n, 0);

        let mut client_stream =
            new_socks_stream(&socks_addr, socks_port, &sess, None, None).await?;
        let (mut server_stream, _) = listener
            .accept()
            .await
            .map_err(|e| anyhow::anyhow!("accept 2 failed: {}", e))?;

        // Another direction.
        //
        // client <-> server
        //
        // Ensure both directions work.
        //
        // When testing with proxy protocols need additional info from the other
        // side to initialize itself, such as shadowsocks needs a salt from the
        // other side, we must forward some payload first.
        client_stream
            .write_all(b"hello")
            .await
            .map_err(|e| anyhow::anyhow!("write hello 2 failed: {}", e))?;
        let mut buf = Vec::new();
        let n = server_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read hello 2 failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "hello");
        server_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world 2 failed: {}", e))?;
        let mut buf = Vec::new();
        let n = client_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read world 2 failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "world");

        server_stream
            .shutdown()
            .await
            .map_err(|e| anyhow::anyhow!("shutdown server failed: {}", e))?;
        client_stream
            .write_all(b"hello")
            .await
            .map_err(|e| anyhow::anyhow!("write hello 3 failed: {}", e))?;
        let mut buf = Vec::new();
        let n = server_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read hello 3 failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "hello");
        let res = server_stream
            .write_all(b"world")
            .await
            .map_err(|e| e.kind());
        assert!(res.is_err());
        let mut buf = Vec::new();
        let n = timeout(Duration::from_millis(20), client_stream.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("timeout read 3 failed: {}", e))?
            .map_err(|e| anyhow::anyhow!("read 3 failed: {}", e))?;
        assert_eq!(n, 0);
        tokio::time::sleep(
            Duration::from_secs(*leaf::option::TCP_UPLINK_TIMEOUT)
                .checked_sub(Duration::from_millis(500))
                .ok_or_else(|| anyhow::anyhow!("duration sub failed"))?,
        )
        .await;
        client_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world 3 failed: {}", e))?;
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let res = server_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read buf 3 failed: {}", e))?;
        assert_eq!(res, 5);
        let mut buf = Vec::new();
        let n = timeout(Duration::from_millis(20), server_stream.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("timeout read 4 failed: {}", e))?
            .map_err(|e| anyhow::anyhow!("read 4 failed: {}", e))?;
        assert_eq!(n, 0);
        Ok::<(), anyhow::Error>(())
    }));
    for id in leaf_rt_ids.into_iter() {
        leaf::shutdown(id);
        assert!(rt
            .block_on(rt.spawn(async move {
                timeout(Duration::from_millis(50), wait_for_shutdown(id))
                    .await
                    .map_err(|e| anyhow::anyhow!("wait shutdown timeout: {}", e))
            }))
            .is_ok());
    }
    match res {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(anyhow::anyhow!("task join error: {}", e)),
    }
}

async fn file_hash<P: AsRef<Path>>(p: P) -> anyhow::Result<Box<[u8]>> {
    let mut src = tokio::fs::File::open(p)
        .await
        .map_err(|e| anyhow::anyhow!("open file failed: {}", e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = src
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read file failed: {}", e))?;
        if n == 0 {
            break;
        }
        hasher
            .write_all(&buf[..n])
            .map_err(|e| anyhow::anyhow!("write hasher failed: {}", e))?;
    }
    Ok(hasher.finalize().as_slice().to_owned().into_boxed_slice())
}

pub fn test_data_transfering_reliability_on_configs(
    configs: Vec<String>,
    socks_addr: &str,
    socks_port: u16,
) -> anyhow::Result<()> {
    info!("testing data transfering reliability");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("build runtime failed: {}", e))?;
    let mut path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current exe failed: {}", e))?;
    path.pop();
    let src_file = "source_random_bytes.bin";
    let dst_file = "destination_random_bytes.bin";
    let source = path.join(src_file);
    let dst = path.join(dst_file);
    if source.exists() {
        std::fs::remove_file(&source)
            .map_err(|e| anyhow::anyhow!("remove source failed: {}", e))?;
    }
    let mut rng = StdRng::from_entropy();
    let mut data = vec![0u8; 2 * 1024 * 1024];
    rng.fill_bytes(&mut data);
    let mut f = std::fs::File::create(&source)
        .map_err(|e| anyhow::anyhow!("create source failed: {}", e))?;
    f.write_all(&data)
        .map_err(|e| anyhow::anyhow!("write source failed: {}", e))?;
    f.sync_all()
        .map_err(|e| anyhow::anyhow!("sync source failed: {}", e))?;

    // TCP uplink
    let listener = rt
        .block_on(TcpListener::bind("127.0.0.1:0"))
        .map_err(|e| anyhow::anyhow!("bind tcp failed: {}", e))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
    let recv_task = async move {
        let source = path.join(src_file);
        let dst = path.join(dst_file);
        let (mut stream, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .map_err(|e| anyhow::anyhow!("accept timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("accept failed: {}", e))?;
        if dst.exists() {
            tokio::fs::remove_file(&dst)
                .await
                .map_err(|e| anyhow::anyhow!("remove dst failed: {}", e))?;
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .map_err(|e| anyhow::anyhow!("open dst failed: {}", e))?;
        let n = timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut stream, &mut dst_file),
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("copy failed: {}", e))?;
        dst_file
            .sync_all()
            .await
            .map_err(|e| anyhow::anyhow!("sync dst failed: {}", e))?;
        assert_eq!(
            dst_file
                .metadata()
                .await
                .map_err(|e| anyhow::anyhow!("metadata failed: {}", e))?
                .len(),
            n
        );
        let src_hash = file_hash(source).await?;
        let dst_hash = file_hash(&dst).await?;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
        Ok::<(), anyhow::Error>(())
    };
    let socks_addr_cloned = socks_addr.to_string();
    let mut path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current exe failed: {}", e))?;
    path.pop();
    let send_task = async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let source = path.join(src_file);
        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip(local_addr);
        let mut stream =
            new_socks_stream(&socks_addr_cloned, socks_port, &sess, None, None).await?;
        let mut src = tokio::fs::File::open(source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?;
        timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut src, &mut stream),
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("copy failed: {}", e))?;
        Ok::<(), anyhow::Error>(())
    };
    let leaf_rt_ids = run_leaf_instances(&rt, configs.clone())?;
    let mut futs: Vec<
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>,
    > = Vec::new();
    futs.push(Box::pin(recv_task));
    futs.push(Box::pin(send_task));
    let res = rt.block_on(rt.spawn(futures::future::try_join_all(futs)));
    for id in leaf_rt_ids.into_iter() {
        leaf::shutdown(id);
        assert!(rt
            .block_on(rt.spawn(async move {
                timeout(Duration::from_millis(50), wait_for_shutdown(id))
                    .await
                    .map_err(|e| anyhow::anyhow!("wait shutdown timeout: {}", e))
            }))
            .is_ok());
    }
    match res {
        Ok(Ok(_)) => (),
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(anyhow::anyhow!("task join error: {}", e)),
    }

    // TCP downlink
    let listener = rt
        .block_on(TcpListener::bind("127.0.0.1:0"))
        .map_err(|e| anyhow::anyhow!("bind tcp failed: {}", e))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
    let socks_addr_cloned = socks_addr.to_string();
    let mut path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current exe failed: {}", e))?;
    path.pop();
    let recv_task = async move {
        let source = path.join(src_file);
        let dst = path.join(dst_file);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip(local_addr);
        let mut stream =
            new_socks_stream(&socks_addr_cloned, socks_port, &sess, None, None).await?;
        if dst.exists() {
            tokio::fs::remove_file(&dst)
                .await
                .map_err(|e| anyhow::anyhow!("remove dst failed: {}", e))?;
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .map_err(|e| anyhow::anyhow!("open dst failed: {}", e))?;
        let n = timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut stream, &mut dst_file),
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("copy failed: {}", e))?;
        dst_file
            .sync_all()
            .await
            .map_err(|e| anyhow::anyhow!("sync dst failed: {}", e))?;
        assert_eq!(
            dst_file
                .metadata()
                .await
                .map_err(|e| anyhow::anyhow!("metadata failed: {}", e))?
                .len(),
            n
        );
        let src_hash = file_hash(source).await?;
        let dst_hash = file_hash(&dst).await?;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
        Ok::<(), anyhow::Error>(())
    };
    let _socks_addr_cloned = socks_addr.to_string();
    let mut path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current exe failed: {}", e))?;
    path.pop();
    let send_task = async move {
        let source = path.join(src_file);
        let (mut stream, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .map_err(|e| anyhow::anyhow!("accept timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("accept failed: {}", e))?;
        let mut src = tokio::fs::File::open(source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?;
        timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut src, &mut stream),
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("copy failed: {}", e))?;
        Ok::<(), anyhow::Error>(())
    };
    let leaf_rt_ids = run_leaf_instances(&rt, configs.clone())?;
    let mut futs: Vec<
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>,
    > = Vec::new();
    futs.push(Box::pin(recv_task));
    futs.push(Box::pin(send_task));
    let res = rt.block_on(rt.spawn(futures::future::try_join_all(futs)));
    for id in leaf_rt_ids.into_iter() {
        leaf::shutdown(id);
        assert!(rt
            .block_on(rt.spawn(async move {
                timeout(Duration::from_millis(50), wait_for_shutdown(id))
                    .await
                    .map_err(|e| anyhow::anyhow!("wait shutdown timeout: {}", e))
            }))
            .is_ok());
    }
    match res {
        Ok(Ok(_)) => (),
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(anyhow::anyhow!("task join error: {}", e)),
    }

    // UDP uplink
    let socket = rt
        .block_on(UdpSocket::bind("127.0.0.1:0"))
        .map_err(|e| anyhow::anyhow!("bind udp failed: {}", e))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;

    let mut path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current exe failed: {}", e))?;
    path.pop();
    let recv_task = async move {
        let source = path.join(src_file);
        let dst = path.join(dst_file);
        if dst.exists() {
            tokio::fs::remove_file(&dst)
                .await
                .map_err(|e| anyhow::anyhow!("remove dst failed: {}", e))?;
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .map_err(|e| anyhow::anyhow!("open dst failed: {}", e))?;
        let expected_total_bytes = tokio::fs::File::open(&source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?
            .metadata()
            .await
            .map_err(|e| anyhow::anyhow!("metadata source failed: {}", e))?
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
                .map_err(|e| anyhow::anyhow!("recv timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("recv failed: {}", e))?;
            recvd_data.push(buf[..n].to_vec());
            recvd_bytes += n;
        }
        for data in recvd_data.into_iter() {
            dst_file
                .write_all(&data)
                .await
                .map_err(|e| anyhow::anyhow!("write dst failed: {}", e))?;
        }
        dst_file
            .sync_all()
            .await
            .map_err(|e| anyhow::anyhow!("sync dst failed: {}", e))?;
        assert_eq!(
            dst_file
                .metadata()
                .await
                .map_err(|e| anyhow::anyhow!("metadata dst failed: {}", e))?
                .len() as usize,
            expected_total_bytes
        );
        let src_hash = file_hash(&source).await?;
        let dst_hash = file_hash(&dst).await?;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
        Ok::<(), anyhow::Error>(())
    };
    let socks_addr_cloned = socks_addr.to_string();
    let mut path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current exe failed: {}", e))?;
    path.pop();
    let send_task = async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let source = path.join(src_file);
        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip(local_addr);
        let dgram = new_socks_datagram(&socks_addr_cloned, socks_port, &sess, None, None).await?;
        let (_, mut s) = dgram.split();
        let mut src = tokio::fs::File::open(source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?;
        let mut buf = vec![0u8; 1500];
        loop {
            // Since UDP is unordered and unreliable, even tests on local could
            // fail, make some delay to mitigate this.
            tokio::time::sleep(Duration::from_millis(1)).await;
            let n = timeout(Duration::from_secs(2), src.read(&mut buf))
                .await
                .map_err(|e| anyhow::anyhow!("read timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("read failed: {}", e))?;
            if n > 0 {
                let _n = timeout(
                    Duration::from_secs(2),
                    s.send_to(&buf[..n], &sess.destination),
                )
                .await
                .map_err(|e| anyhow::anyhow!("send timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("send failed: {}", e))?;
            } else {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let leaf_rt_ids = run_leaf_instances(&rt, configs.clone())?;
    let mut futs: Vec<
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>,
    > = Vec::new();
    futs.push(Box::pin(recv_task));
    futs.push(Box::pin(send_task));
    let res = rt.block_on(rt.spawn(futures::future::try_join_all(futs)));
    for id in leaf_rt_ids.into_iter() {
        leaf::shutdown(id);
        assert!(rt
            .block_on(rt.spawn(async move {
                timeout(Duration::from_millis(50), wait_for_shutdown(id))
                    .await
                    .map_err(|e| anyhow::anyhow!("wait shutdown timeout: {}", e))
            }))
            .is_ok());
    }
    match res {
        Ok(Ok(_)) => (),
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(anyhow::anyhow!("task join error: {}", e)),
    }

    // UDP downlink
    let socket = rt
        .block_on(UdpSocket::bind("127.0.0.1:0"))
        .map_err(|e| anyhow::anyhow!("bind udp failed: {}", e))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;

    let socks_addr_cloned = socks_addr.to_string();
    let mut path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current exe failed: {}", e))?;
    path.pop();
    let recv_task = async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip(local_addr);
        let dgram = new_socks_datagram(&socks_addr_cloned, socks_port, &sess, None, None).await?;
        let (mut r, mut s) = dgram.split();
        let source = path.join(src_file);
        let _buf = vec![0u8; 1500];
        if dst.exists() {
            tokio::fs::remove_file(&dst)
                .await
                .map_err(|e| anyhow::anyhow!("remove dst failed: {}", e))?;
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .map_err(|e| anyhow::anyhow!("open dst failed: {}", e))?;
        let expected_total_bytes = tokio::fs::File::open(&source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?
            .metadata()
            .await
            .map_err(|e| anyhow::anyhow!("metadata source failed: {}", e))?
            .len() as usize;
        let mut recvd_bytes: usize = 0;
        let mut buf = vec![0u8; 1500];
        let mut recvd_data = Vec::new();
        // Send a datagram to establish the session.
        s.send_to(b"hello", &sess.destination)
            .await
            .map_err(|e| anyhow::anyhow!("send hello failed: {}", e))?;
        loop {
            assert!(recvd_bytes <= expected_total_bytes);
            if recvd_bytes == expected_total_bytes {
                break;
            }
            let (n, _) = timeout(Duration::from_secs(2), r.recv_from(&mut buf))
                .await
                .map_err(|e| anyhow::anyhow!("recv timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("recv failed: {}", e))?;
            recvd_data.push(buf[..n].to_vec());
            recvd_bytes += n;
        }
        for data in recvd_data.into_iter() {
            dst_file
                .write_all(&data)
                .await
                .map_err(|e| anyhow::anyhow!("write dst failed: {}", e))?;
        }
        dst_file
            .sync_all()
            .await
            .map_err(|e| anyhow::anyhow!("sync dst failed: {}", e))?;
        assert_eq!(
            dst_file
                .metadata()
                .await
                .map_err(|e| anyhow::anyhow!("metadata dst failed: {}", e))?
                .len() as usize,
            expected_total_bytes
        );
        let src_hash = file_hash(&source).await?;
        let dst_hash = file_hash(&dst).await?;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
        Ok::<(), anyhow::Error>(())
    };
    let _socks_addr_cloned = socks_addr.to_string();
    let mut path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current exe failed: {}", e))?;
    path.pop();
    let send_task = async move {
        let source = path.join(src_file);
        let mut src = tokio::fs::File::open(source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?;
        let mut buf = vec![0u8; 1500];
        // Receive a single packet to decide the remote peer.
        let (_, raddr) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("recv initial failed: {}", e))?;
        loop {
            // Since UDP is unordered and unreliable, even tests on local could
            // fail, make some delay to mitigate this.
            tokio::time::sleep(Duration::from_millis(1)).await;
            let n = timeout(Duration::from_secs(2), src.read(&mut buf))
                .await
                .map_err(|e| anyhow::anyhow!("read timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("read failed: {}", e))?;
            if n > 0 {
                let _n = timeout(Duration::from_secs(2), socket.send_to(&buf[..n], &raddr))
                    .await
                    .map_err(|e| anyhow::anyhow!("send timeout: {}", e))?
                    .map_err(|e| anyhow::anyhow!("send failed: {}", e))?;
            } else {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let leaf_rt_ids = run_leaf_instances(&rt, configs.clone())?;
    let mut futs: Vec<
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>,
    > = Vec::new();
    futs.push(Box::pin(recv_task));
    futs.push(Box::pin(send_task));
    let res = rt.block_on(rt.spawn(futures::future::try_join_all(futs)));
    for id in leaf_rt_ids.into_iter() {
        leaf::shutdown(id);
        assert!(rt
            .block_on(rt.spawn(async move {
                timeout(Duration::from_millis(50), wait_for_shutdown(id))
                    .await
                    .map_err(|e| anyhow::anyhow!("wait shutdown timeout: {}", e))
            }))
            .is_ok());
    }
    match res {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(anyhow::anyhow!("task join error: {}", e)),
    }
}

// Runs multiple leaf instances, thereafter a socks request will be sent to the
// given socks server to test the proxy chain. The proxy chain is expected to
// correctly handle the request to it's destination.
pub fn test_configs(configs: Vec<String>, socks_addr: &str, socks_port: u16) -> anyhow::Result<()> {
    test_configs_with_auth(configs, socks_addr, socks_port, None, None)
}

pub fn test_configs_with_auth(
    configs: Vec<String>,
    socks_addr: &str,
    socks_port: u16,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<()> {
    info!("testing configs");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("build runtime failed: {}", e))?;

    // Use an echo server as the destination of the socks request.
    let mut bg_tasks: Vec<
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>,
    > = Vec::new();
    let (tcp_addr, tcp_fut) = rt.block_on(run_tcp_echo_server("127.0.0.1:0"))?;
    let (udp_addr, udp_fut) = rt.block_on(run_udp_echo_server("127.0.0.1:0"))?;
    bg_tasks.push(Box::pin(tcp_fut));
    bg_tasks.push(Box::pin(udp_fut));
    let (bg_task, bg_task_handle) = abortable(futures::future::try_join_all(bg_tasks));

    let leaf_rt_ids = run_leaf_instances(&rt, configs)?;

    // Simulates an application request.
    let socks_addr = socks_addr.to_string();
    let app_task = async move {
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip(tcp_addr);
        let mut s = timeout(
            Duration::from_secs(1),
            new_socks_stream(
                &socks_addr,
                socks_port,
                &sess,
                username.clone(),
                password.clone(),
            ),
        )
        .await
        .map_err(|e| anyhow::anyhow!("connect socks stream timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("connect socks stream failed: {}", e))?;

        timeout(Duration::from_secs(1), s.write_all(b"abc"))
            .await
            .map_err(|e| anyhow::anyhow!("write to stream timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("write to stream failed: {}", e))?;

        let mut buf = Vec::new();
        let n = timeout(Duration::from_secs(1), s.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("read from stream timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("read from stream failed: {}", e))?;

        if "abc" != String::from_utf8_lossy(&buf[..n]) {
            return Err(anyhow::anyhow!(
                "stream echo mismatch: expected 'abc', got '{}'",
                String::from_utf8_lossy(&buf[..n])
            ));
        }

        // Test UDP
        sess.destination = leaf::session::SocksAddr::Ip(udp_addr);
        let dgram = timeout(
            Duration::from_secs(1),
            new_socks_datagram(
                &socks_addr,
                socks_port,
                &sess,
                username.clone(),
                password.clone(),
            ),
        )
        .await
        .map_err(|e| anyhow::anyhow!("create socks datagram timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("create socks datagram failed: {}", e))?;

        let (mut r, mut s) = dgram.split();
        let msg = b"def";
        let n = timeout(
            Duration::from_secs(1),
            s.send_to(msg.as_ref(), &sess.destination),
        )
        .await
        .map_err(|e| anyhow::anyhow!("send datagram timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("send datagram failed: {}", e))?;

        if msg.len() != n {
            return Err(anyhow::anyhow!(
                "send datagram partial write: expected {}, got {}",
                msg.len(),
                n
            ));
        }

        let mut buf = vec![0u8; 2 * 1024];
        let (n, raddr) = timeout(Duration::from_secs(1), r.recv_from(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("recv datagram timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("recv datagram failed: {}", e))?;

        if msg != &buf[..n] {
            return Err(anyhow::anyhow!(
                "datagram echo mismatch: expected {:?}, got {:?}",
                msg,
                &buf[..n]
            ));
        }
        if &raddr != &sess.destination {
            return Err(anyhow::anyhow!(
                "datagram source mismatch: expected {:?}, got {:?}",
                sess.destination,
                raddr
            ));
        }

        // Test if we can handle a second UDP session. This can fail in stream
        // transports if the stream ID has not been correctly set.
        let dgram2 = timeout(
            Duration::from_secs(1),
            new_socks_datagram(
                &socks_addr,
                socks_port,
                &sess,
                username.clone(),
                password.clone(),
            ),
        )
        .await
        .map_err(|e| anyhow::anyhow!("create second socks datagram timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("create second socks datagram failed: {}", e))?;

        let (mut r, mut s) = dgram2.split();
        let msg = b"ghi";
        let n = timeout(
            Duration::from_secs(1),
            s.send_to(msg.as_ref(), &sess.destination),
        )
        .await
        .map_err(|e| anyhow::anyhow!("send second datagram timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("send second datagram failed: {}", e))?;

        if msg.len() != n {
            return Err(anyhow::anyhow!(
                "send second datagram partial write: expected {}, got {}",
                msg.len(),
                n
            ));
        }

        let mut buf = vec![0u8; 2 * 1024];
        let (n, raddr) = timeout(Duration::from_secs(1), r.recv_from(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("recv second datagram timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("recv second datagram failed: {}", e))?;

        if msg != &buf[..n] {
            return Err(anyhow::anyhow!(
                "second datagram echo mismatch: expected {:?}, got {:?}",
                msg,
                &buf[..n]
            ));
        }
        if &raddr != &sess.destination {
            return Err(anyhow::anyhow!(
                "second datagram source mismatch: expected {:?}, got {:?}",
                sess.destination,
                raddr
            ));
        }

        // Cancel the background task.
        bg_task_handle.abort();
        Ok::<(), anyhow::Error>(())
    };
    let bg_task = async move {
        match bg_task.await {
            Ok(res) => res.map(|_| ()),
            Err(_) => Ok(()), // Aborted
        }
    };
    let mut futs = Vec::new();
    futs.push(rt.spawn(bg_task));
    futs.push(rt.spawn(app_task));
    let res = rt.block_on(async {
        timeout(Duration::from_secs(30), futures::future::select_all(futs))
            .await
            .map_err(|e| anyhow::anyhow!("test timeout: {}", e))
    });

    for id in leaf_rt_ids.into_iter() {
        assert!(leaf::shutdown(id));
        assert!(rt
            .block_on(rt.spawn(async move {
                timeout(Duration::from_millis(50), wait_for_shutdown(id))
                    .await
                    .map_err(|e| anyhow::anyhow!("wait shutdown timeout: {}", e))?;
                Ok::<(), anyhow::Error>(())
            }))
            .is_ok());
    }

    match res {
        Ok((result, _, _)) => {
            // result is Result<Result<(), Error>, JoinError>
            match result {
                Ok(inner_res) => inner_res,
                Err(e) => Err(anyhow::anyhow!("task join failed: {:?}", e)),
            }
        }
        Err(e) => Err(anyhow::anyhow!("test execution failed: {:?}", e)),
    }
}

async fn wait_for_shutdown(id: leaf::RuntimeId) {
    loop {
        if !leaf::is_running(id) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
