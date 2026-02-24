use std::io;
use std::sync::Arc;

use super::*;

/// An outbound handler groups a TCP outbound handler and a UDP outbound
/// handler.
pub struct Handler {
    tag: String,
    stream_handler: Option<AnyOutboundStreamHandler>,
    datagram_handler: Option<AnyOutboundDatagramHandler>,
}

impl Handler {
    pub(self) fn new(
        tag: String,
        stream_handler: Option<AnyOutboundStreamHandler>,
        datagram_handler: Option<AnyOutboundDatagramHandler>,
    ) -> Arc<Self> {
        Arc::new(Handler {
            tag,
            stream_handler,
            datagram_handler,
        })
    }
}

impl BaseHandler for Handler {}

impl OutboundHandler for Handler {
    fn stream(&self) -> io::Result<&AnyOutboundStreamHandler> {
        self.stream_handler
            .as_ref()
            .ok_or_else(|| io::Error::other("no tcp handler"))
    }

    fn datagram(&self) -> io::Result<&AnyOutboundDatagramHandler> {
        self.datagram_handler
            .as_ref()
            .ok_or_else(|| io::Error::other("no udp handler"))
    }
}

impl Tag for Handler {
    fn tag(&self) -> &String {
        &self.tag
    }
}

pub struct HandlerBuilder {
    tag: String,
    stream_handler: Option<AnyOutboundStreamHandler>,
    datagram_handler: Option<AnyOutboundDatagramHandler>,
}

impl HandlerBuilder {
    pub fn new() -> Self {
        Self {
            tag: "".to_string(),
            stream_handler: None,
            datagram_handler: None,
        }
    }

    pub fn tag(mut self, v: String) -> Self {
        self.tag = v;
        self
    }

    pub fn stream_handler(mut self, v: AnyOutboundStreamHandler) -> Self {
        self.stream_handler.replace(v);
        self
    }

    pub fn datagram_handler(mut self, v: AnyOutboundDatagramHandler) -> Self {
        self.datagram_handler.replace(v);
        self
    }

    pub fn build(self) -> AnyOutboundHandler {
        Handler::new(self.tag, self.stream_handler, self.datagram_handler)
    }
}

impl Default for HandlerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
