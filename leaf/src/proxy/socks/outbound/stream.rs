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
        let mut stream =
            stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))?;
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
                    .map_err(|x| io::Error::new(io::ErrorKind::Other, x))
                    .await?;
            }
            SocksAddr::Domain(domain, port) => {
                let _ =
                    async_socks5::connect(&mut stream, (domain.to_owned(), port.to_owned()), auth)
                        .map_err(|x| io::Error::new(io::ErrorKind::Other, x))
                        .await?;
            }
        }
        Ok(stream)
    }
}
