use std::{
    io::{Error, ErrorKind, Result},
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use futures::future::TryFutureExt;
use socket2::{Domain, Socket, Type};
use tokio::net::TcpStream;

use crate::{
    common::dns_client::DnsClient,
    proxy::{stream::SimpleStream, ProxyStream, ProxyTcpHandler},
    session::{Session, SocksAddr},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

#[async_trait]
impl ProxyTcpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        Some((self.address.clone(), self.port, self.bind_addr.clone()))
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> Result<Box<dyn ProxyStream>> {
        let ips = match self
            .dns_client
            .lookup_with_bind(String::from(&self.address), &self.bind_addr)
            .await
        {
            Ok(ips) => ips,
            Err(err) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("lookup failed: {}", err),
                ));
            }
        };

        let mut last_err = None;

        for ip in ips {
            let socket = Socket::new(Domain::ipv4(), Type::stream(), None)?;
            socket.bind(&self.bind_addr.into())?;
            let addr = SocketAddr::new(ip, self.port);
            match TcpStream::connect_std(socket.into_tcp_stream(), &addr).await {
                Ok(mut stream) => {
                    match &sess.destination {
                        SocksAddr::Ip(a) => {
                            let _ = async_socks5::connect(&mut stream, a.to_owned(), None)
                                .map_err(|x| Error::new(ErrorKind::Other, x))
                                .await?;
                        }
                        SocksAddr::Domain(domain, port) => {
                            let _ = async_socks5::connect(
                                &mut stream,
                                (domain.to_owned(), port.to_owned()),
                                None,
                            )
                            .map_err(|x| Error::new(ErrorKind::Other, x))
                            .await?;
                        }
                    }
                    return Ok(Box::new(SimpleStream(stream)));
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            Error::new(ErrorKind::InvalidInput, "could not resolve to any address")
        }))
    }
}
