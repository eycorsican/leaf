use std::io;
use std::sync::Arc;

use super::*;

/// An outbound handler groups a TCP outbound handler and a UDP outbound
/// handler.
pub struct Handler {
    tag: String,
    color: colored::Color,
    tcp_handler: Option<AnyTcpOutboundHandler>,
    udp_handler: Option<AnyUdpOutboundHandler>,
}

impl Handler {
    pub(self) fn new(
        tag: String,
        color: colored::Color,
        tcp_handler: Option<AnyTcpOutboundHandler>,
        udp_handler: Option<AnyUdpOutboundHandler>,
    ) -> Arc<Self> {
        Arc::new(Handler {
            tag,
            color,
            tcp_handler,
            udp_handler,
        })
    }
}

impl OutboundHandler for Handler {
    fn tcp(&self) -> io::Result<&AnyTcpOutboundHandler> {
        self.tcp_handler
            .as_ref()
            .ok_or(io::Error::new(io::ErrorKind::Other, "no tcp handler"))
    }

    fn udp(&self) -> io::Result<&AnyUdpOutboundHandler> {
        self.udp_handler
            .as_ref()
            .ok_or(io::Error::new(io::ErrorKind::Other, "no udp handler"))
    }
}

impl Tag for Handler {
    fn tag(&self) -> &String {
        &self.tag
    }
}

impl Color for Handler {
    fn color(&self) -> colored::Color {
        (&self.color).to_owned()
    }
}

pub struct HandlerBuilder {
    tag: String,
    color: colored::Color,
    tcp_handler: Option<AnyTcpOutboundHandler>,
    udp_handler: Option<AnyUdpOutboundHandler>,
}

impl HandlerBuilder {
    pub fn new() -> Self {
        Self {
            tag: "".to_string(),
            color: colored::Color::Magenta,
            tcp_handler: None,
            udp_handler: None,
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

    pub fn tcp_handler(mut self, v: AnyTcpOutboundHandler) -> Self {
        self.tcp_handler.replace(v);
        self
    }

    pub fn udp_handler(mut self, v: AnyUdpOutboundHandler) -> Self {
        self.udp_handler.replace(v);
        self
    }

    pub fn build(self) -> AnyOutboundHandler {
        Handler::new(self.tag, self.color, self.tcp_handler, self.udp_handler)
    }
}

impl Default for HandlerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
