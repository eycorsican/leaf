use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use socket2::{Domain, Socket, Type};
use tokio::net::TcpStream;

use crate::{
    common::dns_client::DnsClient,
    proxy::{stream::SimpleStream, ProxyStream, ProxyTcpHandler},
    session::{Session, SocksAddr},
};

pub struct Handler {
    bind_addr: SocketAddr,
    dns_client: Arc<DnsClient>,
}

impl Handler {
    pub fn new(bind_addr: SocketAddr, dns_client: Arc<DnsClient>) -> Self {
        Handler {
            bind_addr,
            dns_client,
        }
    }
}

#[async_trait]
impl ProxyTcpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        None
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        let ips = match &sess.destination {
            SocksAddr::Domain(domain, _) => match self
                .dns_client
                .lookup_with_bind(domain.to_owned(), &self.bind_addr)
                .await
            {
                Ok(addrs) => addrs,
                Err(err) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("lookup failed: {}", err),
                    ));
                }
            },
            SocksAddr::Ip(addr) => vec![addr.ip()],
        };

        let mut last_err = None;

        for ip in ips {
            let socket = Socket::new(Domain::ipv4(), Type::stream(), None)?;
            socket.bind(&self.bind_addr.into())?;
            let addr = SocketAddr::new(ip, sess.destination.port());
            match TcpStream::connect_std(socket.into_tcp_stream(), &addr).await {
                Ok(stream) => {
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
