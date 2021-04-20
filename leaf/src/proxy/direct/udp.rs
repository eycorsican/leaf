use std::{io, net::SocketAddr};

use async_trait::async_trait;

use crate::{
    app::SyncDnsClient,
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundTransport, SimpleOutboundDatagram, UdpConnector,
        UdpOutboundHandler, UdpTransportType,
    },
    session::{Session, SocksAddr},
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

impl UdpConnector for Handler {}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn udp_connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Direct(self.bind_addr))
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Packet
    }

    async fn handle_udp<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<OutboundTransport>,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        let socket = self
            .create_udp_socket(&self.bind_addr, &sess.source)
            .await?;
        let destination = match &sess.destination {
            SocksAddr::Domain(domain, port) => {
                Some(SocksAddr::Domain(domain.to_owned(), port.to_owned()))
            }
            _ => None,
        };
        Ok(Box::new(SimpleOutboundDatagram::new(
            socket,
            destination,
            self.dns_client.clone(),
            self.bind_addr,
        )))
    }
}
