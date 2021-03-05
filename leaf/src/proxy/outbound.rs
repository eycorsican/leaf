use std::io::{self, Result};
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
    tcp_handler: Option<Box<dyn TcpOutboundHandler>>,
    udp_handler: Option<Box<dyn UdpOutboundHandler>>,
}

impl Handler {
    pub fn new(
        tag: String,
        color: colored::Color,
        handler_type: ProxyHandlerType,
        tcp: Option<Box<dyn TcpOutboundHandler>>,
        udp: Option<Box<dyn UdpOutboundHandler>>,
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

impl OutboundHandler for Handler {
    fn has_tcp(&self) -> bool {
        self.tcp_handler.is_some()
    }

    fn has_udp(&self) -> bool {
        self.udp_handler.is_some()
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
        if let Some(handler) = &self.tcp_handler {
            handler.tcp_connect_addr()
        } else {
            None
        }
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> Result<Box<dyn ProxyStream>> {
        if let Some(handler) = &self.tcp_handler {
            handler.handle_tcp(sess, stream).await
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "no TCP handler"))
        }
    }
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn name(&self) -> &str {
        NAME
    }

    fn udp_connect_addr(&self) -> Option<OutboundConnect> {
        if let Some(handler) = &self.udp_handler {
            return handler.udp_connect_addr();
        } else if let Some(handler) = &self.tcp_handler {
            return handler.tcp_connect_addr();
        }
        None
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        if let Some(handler) = &self.udp_handler {
            handler.udp_transport_type()
        } else {
            // Currently all handlers has a tcp outbound handler.
            // FIXME
            UdpTransportType::Stream
        }
    }

    async fn handle_udp<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport>,
    ) -> Result<Box<dyn OutboundDatagram>> {
        if let Some(handler) = &self.udp_handler {
            handler.handle_udp(sess, transport).await
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "no UDP handler"))
        }
    }
}
