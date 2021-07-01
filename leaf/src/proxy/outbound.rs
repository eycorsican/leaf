use std::io::Result;
use std::sync::Arc;

use async_trait::async_trait;

use crate::session::Session;

use super::{
    Color, DatagramTransportType, OutboundConnect, OutboundDatagram, OutboundHandler,
    OutboundTransport, ProxyStream, Tag, TcpOutboundHandler, UdpOutboundHandler,
};

/// An outbound handler groups a TCP outbound handler and a UDP outbound
/// handler.
pub struct Handler {
    tag: String,
    color: colored::Color,
    tcp_handler: Box<dyn TcpOutboundHandler>,
    udp_handler: Box<dyn UdpOutboundHandler>,
}

impl Handler {
    pub(self) fn new(
        tag: String,
        color: colored::Color,
        tcp: Box<dyn TcpOutboundHandler>,
        udp: Box<dyn UdpOutboundHandler>,
    ) -> Arc<Self> {
        Arc::new(Handler {
            tag,
            color,
            tcp_handler: tcp,
            udp_handler: udp,
        })
    }
}

impl OutboundHandler for Handler {}

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

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        self.tcp_handler.connect_addr()
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> Result<Box<dyn ProxyStream>> {
        self.tcp_handler.handle(sess, stream).await
    }
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        self.udp_handler.connect_addr()
    }

    fn transport_type(&self) -> DatagramTransportType {
        self.udp_handler.transport_type()
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport>,
    ) -> Result<Box<dyn OutboundDatagram>> {
        self.udp_handler.handle(sess, transport).await
    }
}

pub struct HandlerBuilder {
    tag: String,
    color: colored::Color,
    tcp_handler: Box<dyn TcpOutboundHandler>,
    udp_handler: Box<dyn UdpOutboundHandler>,
}

impl HandlerBuilder {
    pub fn new() -> Self {
        Self {
            tag: "".to_string(),
            color: colored::Color::Magenta,
            tcp_handler: Box::new(super::null::outbound::TcpHandler { connect: None }),
            udp_handler: Box::new(super::null::outbound::UdpHandler {
                connect: None,
                transport_type: super::DatagramTransportType::Undefined,
            }),
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

    pub fn tcp_handler(mut self, v: Box<dyn TcpOutboundHandler>) -> Self {
        self.tcp_handler = v;
        self
    }

    pub fn udp_handler(mut self, v: Box<dyn UdpOutboundHandler>) -> Self {
        self.udp_handler = v;
        self
    }

    pub fn build(self) -> Arc<Handler> {
        Handler::new(self.tag, self.color, self.tcp_handler, self.udp_handler)
    }
}

impl Default for HandlerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
