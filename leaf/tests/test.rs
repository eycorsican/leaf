use futures::future::abortable;
use futures::FutureExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::stream::StreamExt;

async fn run_tcp_echo_server<A: ToSocketAddrs>(addr: A) {
    let mut listener = TcpListener::bind(addr).await.unwrap();
    let mut incoming = listener.incoming();
    while let Some(stream) = incoming.next().await {
        match stream {
            Ok(mut stream) => {
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

// App -> Client -> Server -> Echo Server
#[test]
fn test_leaf() {
    let app_config = r#"
    {
        "outbounds": [
            {
                "protocol": "socks",
                "tag": "socks",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 1086
                }
            }
        ]
    }
    "#;

    let client_config = r#"
    {
        "inbounds": [
            {
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 1086
            }
        ],
        "outbounds": [
            {
                "protocol": "trojan",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3001,
                    "password": "password"
                }
            }
        ]
    }
    "#;

    let server_config = r#"
    {
        "inbounds": [
            {
                "protocol": "trojan",
                "address": "127.0.0.1",
                "port": 3001,
                "settings": {
                    "password": "password"
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "direct"
            }
        ]
    }
    "#;

    let mut rt = tokio::runtime::Builder::new()
        .basic_scheduler()
        .enable_all()
        .build()
        .unwrap();

    let mut all_tasks: Vec<leaf::Runner> = Vec::new();

    // An echo server.
    let (echo_server_task, echo_server_task_handle) =
        abortable(run_tcp_echo_server("127.0.0.1:3000"));

    // Proxy server.
    let config = leaf::config::json::from_string(server_config.to_string()).unwrap();
    let config = leaf::config::json::to_internal(config).unwrap();
    let server_task_runners = leaf::util::create_runners(config).unwrap();
    let server_task = async move {
        futures::future::join_all(server_task_runners).await;
    };
    let (server_task, server_task_handle) = abortable(server_task);

    // Proxy client.
    let config = leaf::config::json::from_string(client_config.to_string()).unwrap();
    let config = leaf::config::json::to_internal(config).unwrap();
    let client_task_runners = leaf::util::create_runners(config).unwrap();
    let client_task = async move {
        futures::future::join_all(client_task_runners).await;
    };
    let (client_task, client_task_handle) = abortable(client_task);

    // Simulates an application request.
    let app_task = async move {
        // Make use of a socks outbound to initiate a socks request to the proxy client.
        let config = leaf::config::json::from_string(app_config.to_string()).unwrap();
        let config = leaf::config::json::to_internal(config).unwrap();
        let outbound_manager = leaf::app::outbound::manager::OutboundManager::new(
            &config.outbounds,
            config.dns.as_ref().unwrap(),
        );
        let handler = outbound_manager.get("socks").unwrap();
        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip("127.0.0.1:3000".parse().unwrap());
        let mut s = handler.handle_tcp(&sess, None).await.unwrap();
        s.write_all(b"abc").await.unwrap();
        let mut buf = Vec::new();
        let n = s.read_buf(&mut buf).await.unwrap();
        assert_eq!("abc".to_string(), String::from_utf8_lossy(&buf[..n]));
        // Cancel all other tasks and exit.
        echo_server_task_handle.abort();
        server_task_handle.abort();
        client_task_handle.abort();
    };

    all_tasks.push(Box::pin(echo_server_task.map(|_| ())));
    all_tasks.push(Box::pin(server_task.map(|_| ())));
    all_tasks.push(Box::pin(client_task.map(|_| ())));
    all_tasks.push(Box::pin(app_task));

    // Actually run all the tasks.
    rt.block_on(futures::future::join_all(all_tasks));
}
