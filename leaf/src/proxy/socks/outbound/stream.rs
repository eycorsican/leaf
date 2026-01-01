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
                let _ =
                    async_socks5::connect(&mut stream, (domain.to_owned(), port.to_owned()), auth)
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

        // Mock a SOCKS5 server in a separate task
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            // Handshake
            let mut buf = [0u8; 2];
            socket.read_exact(&mut buf).await.unwrap();
            socket.write_all(&[0x05, 0x00]).await.unwrap();

            // Request
            let mut buf = [0u8; 10]; // Minimum size for domain request
            socket.read_exact(&mut buf[..4]).await.unwrap();
            let atyp = buf[3];
            if atyp == 0x03 {
                let mut len_buf = [0u8; 1];
                socket.read_exact(&mut len_buf).await.unwrap();
                let len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; len + 2];
                socket.read_exact(&mut domain_buf).await.unwrap();
            }

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
        assert!(result.is_ok());
    }
}
