use std::io;

use async_trait::async_trait;

use crate::{proxy::*, session::Session};

pub struct Handler;

#[async_trait]
impl UdpOutboundHandler for Handler {
    type UStream = AnyStream;
    type Datagram = AnyOutboundDatagram;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Datagram
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _transport: Option<OutboundTransport<Self::UStream, Self::Datagram>>,
    ) -> io::Result<Self::Datagram> {
        Err(io::Error::new(io::ErrorKind::Other, "dropped"))
    }
}
