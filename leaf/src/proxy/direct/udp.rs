use std::io;

use async_trait::async_trait;

use crate::{proxy::*, session::Session};

pub struct Handler;

#[async_trait]
impl UdpOutboundHandler for Handler {
    type UStream = AnyStream;
    type Datagram = AnyOutboundDatagram;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Direct)
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Datagram
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        transport: Option<OutboundTransport<Self::UStream, Self::Datagram>>,
    ) -> io::Result<Self::Datagram> {
        if let Some(OutboundTransport::Datagram(dgram)) = transport {
            Ok(dgram)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid input"))
        }
    }
}
