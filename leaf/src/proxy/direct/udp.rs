use std::io;

use async_trait::async_trait;

use crate::{
    proxy::{
        DatagramTransportType, OutboundConnect, OutboundDatagram, OutboundTransport,
        UdpOutboundHandler,
    },
    session::Session,
};

pub struct Handler;

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Direct)
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Datagram
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        transport: Option<OutboundTransport>,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        if let Some(OutboundTransport::Datagram(dgram)) = transport {
            Ok(dgram)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid input"))
        }
    }
}
