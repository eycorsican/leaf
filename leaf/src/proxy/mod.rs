use std::sync::Arc;
use std::{io, net::SocketAddr};

use async_trait::async_trait;
use futures::TryFutureExt;
use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::{common::dns_client::DnsClient, common::resolver::Resolver, session::Session};

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

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

pub trait Tag {
    fn tag(&self) -> &String;
}

pub trait Color {
    fn color(&self) -> colored::Color;
}

pub trait HandlerTyped {
    fn handler_type(&self) -> ProxyHandlerType;
}

async fn dial_tcp_stream(
    dns_client: Arc<DnsClient>,
    bind_addr: &SocketAddr,
    address: &String,
    port: &u16,
) -> io::Result<Box<dyn ProxyStream>> {
    let resolver = Resolver::new(dns_client, bind_addr, address, port)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("resolve address failed: {}", e),
            )
        })
        .await?;

    let mut last_err = None;

    for addr in resolver {
        let socket = Socket::new(Domain::ipv4(), Type::stream(), None)?;
        socket.bind(&bind_addr.clone().into())?;
        match TcpStream::connect_std(socket.into_tcp_stream(), &addr).await {
            Ok(stream) => {
                return Ok(Box::new(SimpleStream(stream)));
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any address",
        )
    }))
}

#[async_trait]
pub trait ProxyTcpHandler: Send + Sync + Unpin {
    fn name(&self) -> &str;
    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)>;
    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>>;

    async fn dial_tcp_stream(
        &self,
        dns_client: Arc<DnsClient>,
        bind_addr: &SocketAddr,
        address: &String,
        port: &u16,
    ) -> io::Result<Box<dyn ProxyStream>> {
        dial_tcp_stream(dns_client, bind_addr, address, port).await
    }
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
pub trait ProxyDatagramRecvHalf: Sync + Send + Unpin {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
}

#[async_trait]
pub trait ProxyDatagramSendHalf: Sync + Send + Unpin {
    async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> io::Result<usize>;
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
    ) -> io::Result<Box<dyn ProxyDatagram>>;

    async fn dial_tcp_stream(
        &self,
        dns_client: Arc<DnsClient>,
        bind_addr: &SocketAddr,
        address: &String,
        port: &u16,
    ) -> io::Result<Box<dyn ProxyStream>> {
        dial_tcp_stream(dns_client, bind_addr, address, port).await
    }
}
