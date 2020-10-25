use std::{
    io::{Error, ErrorKind, Result},
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use futures::future::TryFutureExt;

use crate::{
    common::dns_client::DnsClient,
    proxy::{ProxyStream, ProxyTcpHandler},
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
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        Some((self.address.clone(), self.port, self.bind_addr))
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> Result<Box<dyn ProxyStream>> {
        let mut stream = if let Some(stream) = stream {
            stream
        } else {
            self.dial_tcp_stream(
                self.dns_client.clone(),
                &self.bind_addr,
                &self.address,
                &self.port,
            )
            .await?
        };
        match &sess.destination {
            SocksAddr::Ip(a) => {
                let _ = async_socks5::connect(&mut stream, a.to_owned(), None)
                    .map_err(|x| Error::new(ErrorKind::Other, x))
                    .await?;
            }
            SocksAddr::Domain(domain, port) => {
                let _ =
                    async_socks5::connect(&mut stream, (domain.to_owned(), port.to_owned()), None)
                        .map_err(|x| Error::new(ErrorKind::Other, x))
                        .await?;
            }
        }
        Ok(stream)
    }
}
