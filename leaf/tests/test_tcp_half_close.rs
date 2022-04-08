mod common;

use std::io::ErrorKind;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-shadowsocks",
    feature = "inbound-shadowsocks",
    feature = "outbound-trojan",
    feature = "inbound-trojan",
    feature = "outbound-direct",
))]
#[test]
fn test_tcp_half_close() {
    std::env::set_var("TCP_DOWNLINK_TIMEOUT", "3");
    std::env::set_var("TCP_UPLINK_TIMEOUT", "3");

    let config1 = r#"
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
                "protocol": "shadowsocks",
                "tag": "shadowsocks",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3001,
                    "method": "chacha20-ietf-poly1305",
                    "password": "password"
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3002,
                    "password": "password"
                }
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "inbounds": [
            {
                "protocol": "trojan",
                "tag": "trojan",
                "address": "127.0.0.1",
                "port": 3002,
                "settings": {
                    "passwords": [
                        "password",
                        "password2"
                    ]
                }
            },
            {
                "protocol": "shadowsocks",
                "tag": "shadowsocks",
                "address": "127.0.0.1",
                "port": 3001,
                "settings": {
                    "method": "chacha20-ietf-poly1305",
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

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let leaf_rt_ids =
        common::run_leaf_instances(&rt, vec![config1.to_string(), config2.to_string()]);
    let res = rt.block_on(rt.spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
        let mut sess = leaf::session::Session::default();
        sess.destination = leaf::session::SocksAddr::Ip("127.0.0.1:3000".parse().unwrap());

        let mut client_stream = common::new_socks_stream("127.0.0.1", 1086, &sess).await;
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

        let mut client_stream = common::new_socks_stream("127.0.0.1", 1086, &sess).await;
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
