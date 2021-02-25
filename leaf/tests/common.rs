use tokio::net::{TcpListener, ToSocketAddrs, UdpSocket};
use tokio::stream::StreamExt;

pub async fn run_tcp_echo_server<A: ToSocketAddrs>(addr: A) {
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

pub async fn run_udp_echo_server<A: ToSocketAddrs>(addr: A) {
    let mut socket = UdpSocket::bind(addr).await.unwrap();
    let mut buf = vec![0u8; 2 * 1024];
    loop {
        let (n, raddr) = socket.recv_from(&mut buf).await.unwrap();
        let _ = socket.send_to(&buf[..n], &raddr).await.unwrap();
    }
}
