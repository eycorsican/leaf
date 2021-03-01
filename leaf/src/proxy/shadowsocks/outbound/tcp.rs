use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;

use super::shadow::ShadowedStream;
use crate::{
    app::dns_client::DnsClient,
    proxy::{
        stream::SimpleProxyStream, OutboundConnect, ProxyStream, TcpConnector, TcpOutboundHandler,
    },
    session::{Session, SocksAddrWireType},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

impl TcpConnector for Handler {}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        if !self.address.is_empty() && self.port != 0 {
            Some(OutboundConnect::Proxy(
                self.address.clone(),
                self.port,
                self.bind_addr,
            ))
        } else {
            None
        }
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        let stream = if let Some(stream) = stream {
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
        let mut stream =
            ShadowedStream::new(stream, &self.cipher, &self.password).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("create shadowsocks stream failed: {}", e),
                )
            })?;
        sess.destination
            .write_to(&mut stream, SocksAddrWireType::PortLast)
            .await?;
        Ok(Box::new(SimpleProxyStream(stream)))
    }
}
