use std::io;

use async_trait::async_trait;

use crate::{proxy::*, session::Session};

pub struct Handler {
    pub interface: Option<String>,
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Direct(self.interface.as_ref().map(|x| x.as_str().into()))
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        if let Some(OutboundTransport::Datagram(dgram)) = transport {
            Ok(dgram)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid input"))
        }
    }
}
