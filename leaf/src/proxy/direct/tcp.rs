use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;

use crate::{
    app::dns_client::DnsClient,
    proxy::{OutboundConnect, ProxyStream, TcpConnector, TcpOutboundHandler},
    session::Session,
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

impl TcpConnector for Handler {}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

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
