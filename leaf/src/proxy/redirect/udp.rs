use std::{
    io::Result,
    net::{IpAddr, SocketAddr},
};

use async_trait::async_trait;
use futures::TryFutureExt;
use tokio::net::udp::{RecvHalf, SendHalf};

use crate::{
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf,
        OutboundTransport, UdpConnector, UdpOutboundHandler, UdpTransportType,
    },
    session::Session,
};

/// Handler with a redirect target address.
pub struct Handler {
    pub address: String,
    pub port: u16,
}

impl proxy::UdpConnector for Handler {}

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
        _sess: &'a Session,
        _transport: Option<OutboundTransport>,
    ) -> Result<Box<dyn OutboundDatagram>> {
        let socket = self.create_udp_socket("0.0.0.0:0").await?;
        let (rh, sh) = socket.split();
        let addr = SocketAddr::new(self.address.parse::<IpAddr>().unwrap(), self.port);
        Ok(Box::new(Datagram {
            recv_half: rh,
            send_half: sh,
            target: addr,
        }))
    }
}

pub struct Datagram {
    pub recv_half: RecvHalf,
    pub send_half: SendHalf,
    pub target: SocketAddr,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (
            Box::new(DatagramRecvHalf(self.recv_half, self.target)),
            Box::new(DatagramSendHalf(self.send_half, self.target)),
        )
    }
}

pub struct DatagramRecvHalf(RecvHalf, SocketAddr);

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let addr = self.1;
        self.0.recv_from(buf).map_ok(|(n, _)| (n, addr)).await
    }
}

pub struct DatagramSendHalf(SendHalf, SocketAddr);

#[async_trait]
impl OutboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], _target: &SocketAddr) -> Result<usize> {
        self.0.send_to(buf, &self.1).await
    }
}
