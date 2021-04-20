use std::io::Result;
use std::net::SocketAddr;

use async_trait::async_trait;

use crate::{
    app::SyncDnsClient,
    proxy::{
        stream::SimpleProxyStream, OutboundConnect, ProxyStream, TcpConnector, TcpOutboundHandler,
    },
    session::Session,
};

/// Handler with a redirect target address.
pub struct Handler {
    pub address: String,
    pub port: u16,
    pub bind_addr: SocketAddr,
    pub dns_client: SyncDnsClient,
}

impl TcpConnector for Handler {}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    async fn handle_tcp<'a>(
        &'a self,
        _sess: &'a Session,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> Result<Box<dyn ProxyStream>> {
        Ok(Box::new(SimpleProxyStream(
            self.dial_tcp_stream(
                self.dns_client.clone(),
                &self.bind_addr,
                &self.address,
                &self.port,
            )
            .await?,
        )))
    }
}
