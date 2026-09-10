use async_socks5::Auth;
use std::io;

use async_trait::async_trait;
use futures::future::TryFutureExt;

use crate::{proxy::*, session::*};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, self.address.clone(), self.port)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let mut stream = stream.ok_or_else(|| io::Error::other("invalid input"))?;
        let auth = match (&self.username, &self.password) {
            (auth_username, _) if auth_username.is_empty() => None,
            (auth_username, auth_password) => Some(Auth {
                username: auth_username.to_owned(),
                password: auth_password.to_owned(),
            }),
        };
        match &sess.destination {
            SocksAddr::Ip(a) => {
                let _ = async_socks5::connect(&mut stream, a.to_owned(), auth)
                    .map_err(io::Error::other)
                    .await?;
            }
            SocksAddr::Domain(domain, port) => {
                let _ = async_socks5::connect(&mut stream, (domain.to_owned(), *port), auth)
                    .map_err(io::Error::other)
                    .await?;
            }
        }
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_socks5_outbound_handler() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handler = Handler {
            address: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "".to_string(),
            password: "".to_string(),
        };

        let sess = Session {
            destination: SocksAddr::Domain("google.com".to_string(), 80),
            ..Default::default()
        };

        // Mock a SOCKS5 server in a separate task.
        //
        // It has to consume everything the client sends, not merely enough to
        // know what to reply: a socket dropped with unread bytes still in it is
        // reset rather than closed, and the client loses the reply it was in
        // the middle of being given. This used to read the greeting as two
        // bytes, one short of the shortest there is, and every read after it
        // was off by that byte -- so the request went unread, the close became
        // a reset, and whether the client got the reply out first was a race it
        // won often enough on Unix to look like a passing test.
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            // Greeting: VER, NMETHODS, and then that many method bytes.
            let mut greeting = [0u8; 2];
            socket.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut methods).await.unwrap();
            socket.write_all(&[0x05, 0x00]).await.unwrap();

            // Request: VER, CMD, RSV, ATYP, and then the address and port.
            let mut request = [0u8; 4];
            socket.read_exact(&mut request).await.unwrap();
            let address_len = match request[3] {
                0x01 => 4,
                0x04 => 16,
                0x03 => {
                    let mut len = [0u8; 1];
                    socket.read_exact(&mut len).await.unwrap();
                    len[0] as usize
                }
                other => panic!("the client asked for address type {}", other),
            };
            let mut address_and_port = vec![0u8; address_len + 2];
            socket.read_exact(&mut address_and_port).await.unwrap();

            // Reply
            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let client_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let result = handler
            .handle(&sess, None, Some(Box::new(client_stream)))
            .await;
        assert!(
            result.is_ok(),
            "the handshake failed: {}",
            result.err().unwrap()
        );
    }
}
