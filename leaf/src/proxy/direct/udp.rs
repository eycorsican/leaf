use std::{io, net::SocketAddr};

use async_trait::async_trait;
use tokio::net::{
    udp::{RecvHalf, SendHalf},
    UdpSocket,
};

use crate::{
    proxy::{
        OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf, OutboundTransport,
        UdpOutboundHandler, UdpTransportType,
    },
    session::Session,
};

pub struct Handler {
    bind_addr: SocketAddr,
}

impl Handler {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Handler { bind_addr }
    }
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn udp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        None
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Packet
    }

    async fn handle_udp<'a>(
        &'a self,
        _sess: &'a Session,
        _transport: Option<OutboundTransport>,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        let socket = UdpSocket::bind(&self.bind_addr).await?;
        let (rh, sh) = socket.split();
        Ok(Box::new(Datagram {
            recv_half: rh,
            send_half: sh,
        }))
    }
}

pub struct Datagram {
    pub recv_half: RecvHalf,
    pub send_half: SendHalf,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (
            Box::new(DatagramRecvHalf(self.recv_half)),
            Box::new(DatagramSendHalf(self.send_half)),
        )
    }
}

pub struct DatagramRecvHalf(RecvHalf);

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }
}

pub struct DatagramSendHalf(SendHalf);

#[async_trait]
impl OutboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, target).await
    }
}
