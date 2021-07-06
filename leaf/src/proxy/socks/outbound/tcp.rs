use std::io;

use async_trait::async_trait;
use futures::future::TryFutureExt;

use crate::{
    proxy::*,
    session::{Session, SocksAddr},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    type Stream = AnyStream;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Proxy(self.address.clone(), self.port))
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Self::Stream>,
    ) -> io::Result<Self::Stream> {
        let mut stream =
            stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))?;
        match &sess.destination {
            SocksAddr::Ip(a) => {
                let _ = async_socks5::connect(&mut stream, a.to_owned(), None)
                    .map_err(|x| io::Error::new(io::ErrorKind::Other, x))
                    .await?;
            }
            SocksAddr::Domain(domain, port) => {
                let _ =
                    async_socks5::connect(&mut stream, (domain.to_owned(), port.to_owned()), None)
                        .map_err(|x| io::Error::new(io::ErrorKind::Other, x))
                        .await?;
            }
        }
        Ok(stream)
    }
}
