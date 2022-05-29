use std::io;

use super::*;

/// An inbound handler groups a TCP inbound handler and a UDP inbound
/// handler.
pub struct Handler {
    tag: String,
    stream_handler: Option<AnyInboundStreamHandler>,
    datagram_handler: Option<AnyInboundDatagramHandler>,
}

impl Handler {
    pub fn new(
        tag: String,
        tcp: Option<AnyInboundStreamHandler>,
        udp: Option<AnyInboundDatagramHandler>,
    ) -> Self {
        Handler {
            tag,
            stream_handler: tcp,
            datagram_handler: udp,
        }
    }
}

impl Tag for Handler {
    fn tag(&self) -> &String {
        &self.tag
    }
}

impl InboundHandler for Handler {
    fn stream(&self) -> io::Result<&AnyInboundStreamHandler> {
        self.stream_handler
            .as_ref()
            .ok_or(io::Error::new(io::ErrorKind::Other, "no tcp handler"))
    }

    fn datagram(&self) -> io::Result<&AnyInboundDatagramHandler> {
        self.datagram_handler
            .as_ref()
            .ok_or(io::Error::new(io::ErrorKind::Other, "no udp handler"))
    }
}
