use std::{io::Result, net::SocketAddr};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::session::Session;

pub mod datagram;
pub mod handler;
pub mod stream;

#[cfg(feature = "direct")]
pub mod direct;
#[cfg(feature = "drop")]
pub mod drop;
#[cfg(feature = "feature-h2")]
pub mod h2;
#[cfg(feature = "redirect")]
pub mod redirect;
#[cfg(feature = "shadowsocks")]
pub mod shadowsocks;
#[cfg(feature = "socks")]
pub mod socks;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "trojan")]
pub mod trojan;
#[cfg(feature = "vless")]
pub mod vless;
#[cfg(feature = "vmess")]
pub mod vmess;
#[cfg(feature = "ws")]
pub mod ws;

#[cfg(feature = "chain")]
pub mod chain;
#[cfg(feature = "failover")]
pub mod failover;
#[cfg(feature = "random")]
pub mod random;
#[cfg(feature = "tryall")]
pub mod tryall;

pub mod http;
#[cfg(any(target_os = "ios", target_os = "macos", target_os = "linux"))]
pub mod tun;

pub use datagram::{SimpleDatagram, SimpleDatagramRecvHalf, SimpleDatagramSendHalf};
pub use handler::Handler;
pub use stream::SimpleStream;

#[derive(Clone)]
pub enum ProxyHandlerType {
    Direct,
    Endpoint,
    Ensemble,
}

#[derive(Clone, PartialEq)]
pub enum UdpTransportType {
    Stream,
    Packet,
    Unknown,
}

pub trait ProxyHandler:
    Tag + Color + HandlerTyped + ProxyTcpHandler + ProxyUdpHandler + Send + Unpin
{
}

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Unpin {}

pub trait Tag {
    fn tag(&self) -> &String;
}

pub trait Color {
    fn color(&self) -> colored::Color;
}

pub trait HandlerTyped {
    fn handler_type(&self) -> ProxyHandlerType;
}

#[async_trait]
pub trait ProxyTcpHandler: Send + Sync + Unpin {
    fn name(&self) -> &str;
    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)>;
    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> Result<Box<dyn ProxyStream>>;
}

pub trait ProxyDatagram: Send + Unpin {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn ProxyDatagramRecvHalf>,
        Box<dyn ProxyDatagramSendHalf>,
    );
}

#[async_trait]
pub trait ProxyDatagramRecvHalf: Send + Unpin {
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
}

#[async_trait]
pub trait ProxyDatagramSendHalf: Send + Unpin {
    async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> Result<usize>;
}

#[async_trait]
pub trait ProxyUdpHandler: Send + Sync + Unpin {
    fn name(&self) -> &str;
    fn udp_connect_addr(&self) -> Option<(String, u16, SocketAddr)>;
    fn udp_transport_type(&self) -> UdpTransportType;
    async fn connect<'a>(
        &'a self,
        sess: &'a Session,
        datagram: Option<Box<dyn ProxyDatagram>>,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> Result<Box<dyn ProxyDatagram>>;
}
