use std::io;

use async_trait::async_trait;

use super::*;

use crate::session::Session;

/// An inbound handler groups a TCP inbound handler and a UDP inbound
/// handler.
pub struct Handler {
    tag: String,
    tcp_handler: Option<AnyTcpInboundHandler>,
    udp_handler: Option<AnyUdpInboundHandler>,
}

impl Handler {
    pub fn new(
        tag: String,
        tcp: Option<AnyTcpInboundHandler>,
        udp: Option<AnyUdpInboundHandler>,
    ) -> Self {
        Handler {
            tag,
            tcp_handler: tcp,
            udp_handler: udp,
        }
    }
}

impl Tag for Handler {
    fn tag(&self) -> &String {
        &self.tag
    }
}

impl InboundHandler for Handler {
    fn has_tcp(&self) -> bool {
        self.tcp_handler.is_some()
    }

    fn has_udp(&self) -> bool {
        self.udp_handler.is_some()
    }
}

#[async_trait]
impl TcpInboundHandler for Handler {
    type TStream = AnyStream;
    type TDatagram = AnyInboundDatagram;

    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: Self::TStream,
    ) -> std::io::Result<InboundTransport<Self::TStream, Self::TDatagram>> {
        if let Some(handler) = &self.tcp_handler {
            handler.handle(sess, stream).await
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "no TCP handler"))
        }
    }
}

#[async_trait]
impl UdpInboundHandler for Handler {
    type UStream = AnyStream;
    type UDatagram = AnyInboundDatagram;

    async fn handle<'a>(
        &'a self,
        socket: Self::UDatagram,
    ) -> std::io::Result<InboundTransport<Self::UStream, Self::UDatagram>> {
        if let Some(handler) = &self.udp_handler {
            handler.handle(socket).await
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "no UDP handler"))
        }
    }
}
