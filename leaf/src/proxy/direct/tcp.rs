use std::{io, net::SocketAddr};

use async_trait::async_trait;

use crate::{
    app::SyncDnsClient,
    proxy::{OutboundConnect, ProxyStream, TcpConnector, TcpOutboundHandler},
    session::Session,
};

pub struct Handler {
    bind_addr: SocketAddr,
    dns_client: SyncDnsClient,
}

impl Handler {
    pub fn new(bind_addr: SocketAddr, dns_client: SyncDnsClient) -> Self {
        Handler {
            bind_addr,
            dns_client,
        }
    }
}

impl TcpConnector for Handler {}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Direct(self.bind_addr))
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        Ok(self
            .dial_tcp_stream(
                self.dns_client.clone(),
                &self.bind_addr,
                &sess.destination.host(),
                &sess.destination.port(),
            )
            .await?)
    }
}
