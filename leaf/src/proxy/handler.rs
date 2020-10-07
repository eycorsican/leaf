use std::io::Result;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
#[cfg(not(target_os = "ios"))]
use colored::Colorize;
use log::info;

use crate::session::{Session, SocksAddr};

use super::{
    Color, HandlerTyped, ProxyDatagram, ProxyHandler, ProxyHandlerType, ProxyStream,
    ProxyTcpHandler, ProxyUdpHandler, Tag, UdpTransportType,
};

pub static NAME: &'static str = "handler";

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

#[cfg(not(target_os = "ios"))]
fn log_tcp(
    tag: &String,
    tag_color: colored::Color,
    handler_name: &str,
    handshake_time: u128,
    addr: &SocksAddr,
) {
    info!(
        "[{}] [{}][{}][{}ms] {}",
        "tcp".color(colored::Color::TrueColor {
            r: 107,
            g: 208,
            b: 255,
        }),
        handler_name,
        tag.color(tag_color),
        handshake_time,
        addr,
    );
}

#[cfg(target_os = "ios")]
fn log_tcp(
    tag: &String,
    _tag_color: colored::Color,
    handler_name: &str,
    handshake_time: u128,
    addr: &SocksAddr,
) {
    info!(
        "[{}] [{}][{}][{}ms] {}",
        "tcp", tag, handler_name, handshake_time, addr
    );
}

#[cfg(not(target_os = "ios"))]
fn log_udp(
    tag: &String,
    tag_color: colored::Color,
    handler_name: &str,
    handshake_time: u128,
    addr: &SocksAddr,
) {
    info!(
        "[{}] [{}][{}][{}ms] {}",
        "udp".color(colored::Color::TrueColor {
            r: 255,
            g: 193,
            b: 107,
        }),
        handler_name,
        tag.color(tag_color),
        handshake_time,
        addr,
    );
}

#[cfg(target_os = "ios")]
fn log_udp(
    tag: &String,
    _tag_color: colored::Color,
    handler_name: &str,
    handshake_time: u128,
    addr: &SocksAddr,
) {
    info!(
        "[{}] [{}][{}][{}ms] {}",
        "udp", tag, handler_name, handshake_time, addr
    );
}

#[async_trait]
impl ProxyTcpHandler for Handler {
    fn name(&self) -> &str {
        return NAME;
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        self.tcp_handler.tcp_connect_addr()
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> Result<Box<dyn ProxyStream>> {
        let handshake_start = tokio::time::Instant::now();
        match self.tcp_handler.handle(sess, stream).await {
            Ok(s) => {
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);
                match self.handler_type() {
                    ProxyHandlerType::Direct | ProxyHandlerType::Endpoint => {
                        log_tcp(
                            self.tag(),
                            self.color(),
                            self.tcp_handler.name(),
                            elapsed.as_millis(),
                            &sess.destination,
                        );
                    }
                    ProxyHandlerType::Ensemble => (),
                }
                Ok(s)
            }
            Err(e) => Err(e),
        }
    }
}

#[async_trait]
impl ProxyUdpHandler for Handler {
    fn name(&self) -> &str {
        return NAME;
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
        let handshake_start = tokio::time::Instant::now();
        match self.udp_handler.connect(sess, datagram, stream).await {
            Ok(d) => {
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);
                match self.handler_type() {
                    ProxyHandlerType::Direct | ProxyHandlerType::Endpoint => {
                        log_udp(
                            self.tag(),
                            self.color(),
                            self.udp_handler.name(),
                            elapsed.as_millis(),
                            &sess.destination,
                        );
                    }
                    ProxyHandlerType::Ensemble => (),
                }
                Ok(d)
            }
            Err(e) => Err(e),
        }
    }
}
