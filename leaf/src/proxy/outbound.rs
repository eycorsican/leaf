use std::io;
use std::sync::Arc;

use super::*;

/// An outbound handler groups a TCP outbound handler and a UDP outbound
/// handler.
pub struct Handler {
    tag: String,
    color: colored::Color,
    stream_handler: Option<AnyOutboundStreamHandler>,
    datagram_handler: Option<AnyOutboundDatagramHandler>,
}

impl Handler {
    pub(self) fn new(
        tag: String,
        color: colored::Color,
        stream_handler: Option<AnyOutboundStreamHandler>,
        datagram_handler: Option<AnyOutboundDatagramHandler>,
    ) -> Arc<Self> {
        Arc::new(Handler {
            tag,
            color,
            stream_handler,
            datagram_handler,
        })
    }
}

impl OutboundHandler for Handler {
    fn stream(&self) -> io::Result<&AnyOutboundStreamHandler> {
        self.stream_handler
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no tcp handler"))
    }

    fn datagram(&self) -> io::Result<&AnyOutboundDatagramHandler> {
        self.datagram_handler
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no udp handler"))
    }
}

impl Tag for Handler {
    fn tag(&self) -> &String {
        &self.tag
    }
}

impl Color for Handler {
    fn color(&self) -> &colored::Color {
        &self.color
    }
}

pub struct HandlerBuilder {
    tag: String,
    color: colored::Color,
    stream_handler: Option<AnyOutboundStreamHandler>,
    datagram_handler: Option<AnyOutboundDatagramHandler>,
}

impl HandlerBuilder {
    pub fn new() -> Self {
        Self {
            tag: "".to_string(),
            color: colored::Color::Magenta,
            stream_handler: None,
            datagram_handler: None,
        }
    }

    pub fn tag(mut self, v: String) -> Self {
        self.tag = v;
        self
    }

    pub fn color(mut self, v: colored::Color) -> Self {
        self.color = v;
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
        Handler::new(
            self.tag,
            self.color,
            self.stream_handler,
            self.datagram_handler,
        )
    }
}

impl Default for HandlerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
