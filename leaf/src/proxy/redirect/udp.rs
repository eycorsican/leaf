use std::sync::Arc;
use std::{
    io::Result,
    net::{IpAddr, SocketAddr},
};

use async_trait::async_trait;
use futures::TryFutureExt;

use crate::{
    app::dns_client::DnsClient,
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf,
        OutboundTransport, SimpleOutboundDatagram, UdpConnector, UdpOutboundHandler,
        UdpTransportType,
    },
    session::{Session, SocksAddr},
};

/// Handler with a redirect target address.
pub struct Handler {
    pub address: String,
    pub port: u16,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

impl UdpConnector for Handler {}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn udp_connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Packet
    }

    async fn handle_udp<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<OutboundTransport>,
    ) -> Result<Box<dyn OutboundDatagram>> {
        let socket = self.create_udp_socket(&self.bind_addr).await?;
        let socket = Box::new(SimpleOutboundDatagram::new(
            socket,
            None,
            self.dns_client.clone(),
            self.bind_addr,
        ));
        let target = SocksAddr::from((self.address.parse::<IpAddr>().unwrap(), self.port));
        Ok(Box::new(Datagram {
            socket,
            destination: sess.destination.clone(),
            target,
        }))
    }
}

pub struct Datagram {
    pub socket: Box<dyn OutboundDatagram>,
    // The destination application datagrams send to.
    pub destination: SocksAddr,
    // The target we would like to redirect to.
    pub target: SocksAddr,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, s) = self.socket.split();
        (
            Box::new(DatagramRecvHalf(r, self.destination)),
            Box::new(DatagramSendHalf(s, self.target)),
        )
    }
}

pub struct DatagramRecvHalf(Box<dyn OutboundDatagramRecvHalf>, SocksAddr);

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocksAddr)> {
        // Always rewrite the address, thus would allow only symmetric NAT sessions.
        let dest = self.1.clone();
        self.0.recv_from(buf).map_ok(|(n, _)| (n, dest)).await
    }
}

pub struct DatagramSendHalf(Box<dyn OutboundDatagramSendHalf>, SocksAddr);

#[async_trait]
impl OutboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], _target: &SocksAddr) -> Result<usize> {
        self.0.send_to(buf, &self.1).await
    }
}
