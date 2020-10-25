use std::io::Result;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::session::Session;

use super::{
    Color, HandlerTyped, ProxyDatagram, ProxyHandler, ProxyHandlerType, ProxyStream,
    ProxyTcpHandler, ProxyUdpHandler, Tag, UdpTransportType,
};

pub static NAME: &str = "handler";

pub struct Handler {
    tag: String,
    color: colored::Color,
    handler_type: ProxyHandlerType,
    tcp_handler: Box<dyn ProxyTcpHandler>,
    udp_handler: Box<dyn ProxyUdpHandler>,
}

impl Handler {
    pub fn new(
        tag: String,
        color: colored::Color,
        handler_type: ProxyHandlerType,
        tcp: Box<dyn ProxyTcpHandler>,
        udp: Box<dyn ProxyUdpHandler>,
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

impl ProxyHandler for Handler {}

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
impl ProxyTcpHandler for Handler {
    fn name(&self) -> &str {
        NAME
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        self.tcp_handler.tcp_connect_addr()
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
impl ProxyUdpHandler for Handler {
    fn name(&self) -> &str {
        NAME
    }

    fn udp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        self.udp_handler.udp_connect_addr()
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        self.udp_handler.udp_transport_type()
    }

    async fn connect<'a>(
        &'a self,
        sess: &'a Session,
        datagram: Option<Box<dyn ProxyDatagram>>,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> Result<Box<dyn ProxyDatagram>> {
        self.udp_handler.connect(sess, datagram, stream).await
    }
}
