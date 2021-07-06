use std::io;

use async_trait::async_trait;

use crate::{proxy::*, session::Session};

pub struct Handler {
    pub connect: Option<OutboundConnect>,
    pub transport_type: DatagramTransportType,
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    type UStream = AnyStream;
    type Datagram = AnyOutboundDatagram;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        self.connect.clone()
    }

    fn transport_type(&self) -> DatagramTransportType {
        self.transport_type
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _transport: Option<OutboundTransport<Self::UStream, Self::Datagram>>,
    ) -> io::Result<Self::Datagram> {
        Err(io::Error::new(io::ErrorKind::Other, "null handler"))
    }
}
