use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;

use crate::{
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundTransport, UdpOutboundHandler, UdpTransportType,
    },
    session::Session,
};

// struct StreamToDatagram(Box<dyn ProxyStream>);
//
// impl OutboundDatagram for StreamToDatagram {
//     fn split(
//         self: Box<Self>,
//     ) -> (
//         Box<dyn OutboundDatagramRecvHalf>,
//         Box<dyn OutboundDatagramSendHalf>,
//     ) {
//         let (r, w) = self.0.split();
//         (
//             Box::new(StreamToDatagramRecvHalf(r)),
//             Box::new(StreamToDatagramSendHalf(w)),
//         )
//     }
// }
//
// struct StreamToDatagramRecvHalf(Box<dyn OutboundDatagramRecvHalf>);
//
// #[async_trait]
// impl OutboundDatagramRecvHalf for StreamToDatagramRecvHalf {
//     async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
//         self.0.
//     }
// }

pub struct Handler {}

impl Handler {
    pub fn new() -> Self {
        Handler {}
    }
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn udp_connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Unknown
    }

    async fn handle_udp<'a>(
        &'a self,
        _sess: &'a Session,
        transport: Option<OutboundTransport>,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        match transport {
            Some(transport) => match transport {
                OutboundTransport::Stream(stream) => unimplemented!(),
                OutboundTransport::Datagram(socket) => {
                    log::debug!("stat udp datagram");
                    Ok(socket)
                }
            },
            None => Err(io::Error::new(io::ErrorKind::Other, "invalid input")),
        }
    }
}
