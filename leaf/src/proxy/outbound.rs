use std::io::Result;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::session::Session;

use super::{
    Color, HandlerTyped, OutboundConnect, OutboundDatagram, OutboundHandler, OutboundTransport,
    ProxyHandlerType, ProxyStream, Tag, TcpOutboundHandler, UdpOutboundHandler, UdpTransportType,
};

pub static NAME: &str = "handler";

/// An outbound handler groups a TCP outbound handler and a UDP outbound
/// handler.
pub struct Handler {
    tag: String,
    color: colored::Color,
    handler_type: ProxyHandlerType,
    // TODO make handlers optional so we can remove those unimplemented outbounds
    tcp_handler: Box<dyn TcpOutboundHandler>,
    udp_handler: Box<dyn UdpOutboundHandler>,
}

impl Handler {
    pub fn new(
        tag: String,
        color: colored::Color,
        handler_type: ProxyHandlerType,
        tcp: Box<dyn TcpOutboundHandler>,
        udp: Box<dyn UdpOutboundHandler>,
    ) -> Arc<Self> {
        Arc::new(Handler {
            tag,
            color,
            handler_type,
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

impl HandlerTyped for Handler {
    fn handler_type(&self) -> ProxyHandlerType {
        match self.handler_type {
            ProxyHandlerType::Direct => ProxyHandlerType::Direct,
            ProxyHandlerType::Endpoint => ProxyHandlerType::Endpoint,
            ProxyHandlerType::Ensemble => ProxyHandlerType::Ensemble,
        }
    }
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        NAME
    }

    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        self.tcp_handler.tcp_connect_addr()
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> Result<Box<dyn ProxyStream>> {
        self.tcp_handler.handle_tcp(sess, stream).await
    }
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn name(&self) -> &str {
        NAME
    }

    fn udp_connect_addr(&self) -> Option<OutboundConnect> {
        self.udp_handler.udp_connect_addr()
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        self.udp_handler.udp_transport_type()
    }

    async fn handle_udp<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport>,
    ) -> Result<Box<dyn OutboundDatagram>> {
        self.udp_handler.handle_udp(sess, transport).await
    }
}
