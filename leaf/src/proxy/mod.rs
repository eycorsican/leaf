use std::sync::Arc;
use std::{io, net::SocketAddr};

use async_trait::async_trait;
use futures::future::select_ok;
use futures::TryFutureExt;
use log::*;
use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::{
    app::dns_client::DnsClient,
    common::resolver::Resolver,
    option,
    session::{Session, SocksAddr},
};

pub mod datagram;
pub mod inbound;
pub mod outbound;
pub mod stream;

#[cfg(feature = "inbound-http")]
pub mod http;
#[cfg(all(
    feature = "inbound-tun",
    any(target_os = "ios", target_os = "macos", target_os = "linux")
))]
pub mod tun;

#[cfg(feature = "outbound-direct")]
pub mod direct;
#[cfg(feature = "outbound-drop")]
pub mod drop;
#[cfg(feature = "outbound-h2")]
pub mod h2;
#[cfg(feature = "outbound-redirect")]
pub mod redirect;
#[cfg(feature = "outbound-shadowsocks")]
pub mod shadowsocks;
#[cfg(any(feature = "inbound-socks", feature = "outbound-socks"))]
pub mod socks;
#[cfg(feature = "outbound-tls")]
pub mod tls;
#[cfg(any(feature = "inbound-trojan", feature = "outbound-trojan"))]
pub mod trojan;
#[cfg(feature = "outbound-vless")]
pub mod vless;
#[cfg(feature = "outbound-vmess")]
pub mod vmess;
#[cfg(any(feature = "inbound-ws", feature = "outbound-ws"))]
pub mod ws;

#[cfg(any(feature = "inbound-chain", feature = "outbound-chain"))]
pub mod chain;
#[cfg(feature = "outbound-failover")]
pub mod failover;
#[cfg(feature = "outbound-random")]
pub mod random;
#[cfg(feature = "outbound-tryall")]
pub mod tryall;

#[cfg(feature = "outbound-stat")]
pub mod stat;

pub use datagram::{
    SimpleInboundDatagram, SimpleInboundDatagramRecvHalf, SimpleInboundDatagramSendHalf,
    SimpleOutboundDatagram, SimpleOutboundDatagramRecvHalf, SimpleOutboundDatagramSendHalf,
};
pub use stream::{BufHeadProxyStream, SimpleProxyStream};

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

pub trait Tag {
    fn tag(&self) -> &String;
}

pub trait Color {
    fn color(&self) -> colored::Color;
}

pub trait HandlerTyped {
    fn handler_type(&self) -> ProxyHandlerType;
}

// A single TCP dial.
async fn tcp_dial_task(
    dial_addr: SocketAddr,
    bind_addr: &SocketAddr,
) -> io::Result<Box<dyn ProxyStream>> {
    let socket = Socket::new(Domain::ipv4(), Type::stream(), None)?;
    socket.bind(&bind_addr.clone().into())?;
    trace!("dialing tcp {}", &dial_addr);
    match TcpStream::connect_std(socket.into_tcp_stream(), &dial_addr).await {
        Ok(stream) => {
            trace!("connected tcp {}", &dial_addr);
            Ok(Box::new(SimpleProxyStream(stream)))
        }
        Err(e) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("connect failed: {}", e),
        )),
    }
}

// Dials a TCP stream.
async fn dial_tcp_stream(
    dns_client: Arc<DnsClient>,
    bind_addr: &SocketAddr,
    address: &str,
    port: &u16,
) -> io::Result<Box<dyn ProxyStream>> {
    let mut resolver = Resolver::new(dns_client, bind_addr, address, port)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("resolve address failed: {}", e),
            )
        })
        .await?;

    let mut last_err = None;

    let mut done = false;

    while !done {
        let mut tasks = Vec::new();
        for _ in 0..option::OUTBOUND_DIAL_CONCURRENCY {
            let dial_addr = match resolver.next() {
                Some(a) => a,
                None => {
                    done = true; // run out
                    break; // break and execute tasks if there're any
                }
            };
            let t = tcp_dial_task(dial_addr, bind_addr);
            tasks.push(Box::pin(t));
        }
        if !tasks.is_empty() {
            match select_ok(tasks.into_iter()).await {
                Ok(v) => return Ok(v.0),
                Err(e) => {
                    last_err = Some(io::Error::new(
                        io::ErrorKind::Other,
                        format!("all attempts failed, last error: {}", e),
                    ));
                }
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

/// A reliable transport for both inbound and outbound handlers.
pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

/// An outbound handler for both UDP and TCP outgoing connections.
pub trait OutboundHandler:
    Tag + Color + HandlerTyped + TcpOutboundHandler + UdpOutboundHandler + Send + Unpin
{
}

pub enum OutboundConnect {
    Proxy(String, u16, SocketAddr),
    Direct(SocketAddr),
}

/// An outbound handler for outgoing TCP conections.
#[async_trait]
pub trait TcpOutboundHandler: Send + Sync + Unpin {
    /// Returns the name of the handler.
    fn name(&self) -> &str;

    /// Returns the address which the underlying transport should
    /// communicate with.
    fn tcp_connect_addr(&self) -> Option<OutboundConnect>;

    /// Handles a session with the given stream. On success, returns a
    /// stream wraps the incoming stream.
    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>>;

    /// Dials a TCP connection.
    async fn dial_tcp_stream(
        &self,
        dns_client: Arc<DnsClient>,
        bind_addr: &SocketAddr,
        address: &str,
        port: &u16,
    ) -> io::Result<Box<dyn ProxyStream>> {
        dial_tcp_stream(dns_client, bind_addr, address, port).await
    }
}

/// An unreliable transport for outbound handlers.
pub trait OutboundDatagram: Send + Unpin {
    /// Splits the datagram.
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    );
}

/// The receive half.
#[async_trait]
pub trait OutboundDatagramRecvHalf: Sync + Send + Unpin {
    /// Receives a message on the socket. On success, returns the number of
    /// bytes read and the origin of the message.
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
}

/// The send half.
#[async_trait]
pub trait OutboundDatagramSendHalf: Sync + Send + Unpin {
    /// Sends a message on the socket to `dst_addr`. On success, returns the
    /// number of bytes sent.
    ///
    /// `dst_addr` is not the proxy server address.
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocketAddr) -> io::Result<usize>;
}

/// An outbound handler for outgoing UDP connections.
#[async_trait]
pub trait UdpOutboundHandler: Send + Sync + Unpin {
    /// Returns the name of the handler.
    fn name(&self) -> &str;

    /// Returns the address which the underlying transport should
    /// communicate with.
    fn udp_connect_addr(&self) -> Option<OutboundConnect>;

    /// Returns the transport type of this handler.
    ///
    /// For example, for a SOCKS5 handler, the UDP transport type is
    /// `UdpTransportType::Packet`, but for a trojan handler, the transport
    /// type is `UdpTransportType::Stream` because trojan transport UDP
    /// packets over TCP connections.
    fn udp_transport_type(&self) -> UdpTransportType;

    /// Handles a session with the transport. On success, returns an outbound
    /// datagram wraps the incoming transport.
    async fn handle_udp<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport>,
    ) -> io::Result<Box<dyn OutboundDatagram>>;

    /// Dials a TCP connection.
    async fn dial_tcp_stream(
        &self,
        dns_client: Arc<DnsClient>,
        bind_addr: &SocketAddr,
        address: &str,
        port: &u16,
    ) -> io::Result<Box<dyn ProxyStream>> {
        dial_tcp_stream(dns_client, bind_addr, address, port).await
    }
}

/// An outbound transport represents either a reliable or unreliable transport.
pub enum OutboundTransport {
    /// The reliable transport.
    Stream(Box<dyn ProxyStream>),
    /// The unreliable transport.
    Datagram(Box<dyn OutboundDatagram>),
}

pub trait InboundHandler: Tag + TcpInboundHandler + UdpInboundHandler + Send + Unpin {
    fn has_tcp(&self) -> bool;
    fn has_udp(&self) -> bool;
}

/// An inbound handler for incoming TCP connections.
#[async_trait]
pub trait TcpInboundHandler: Send + Sync + Unpin {
    async fn handle_tcp<'a>(
        &'a self,
        transport: InboundTransport,
    ) -> std::io::Result<InboundTransport>;
}

/// An inbound handler for incoming UDP connections.
#[async_trait]
pub trait UdpInboundHandler: Send + Sync + Unpin {
    async fn handle_udp<'a>(
        &'a self,
        socket: Option<Box<dyn InboundDatagram>>,
    ) -> io::Result<Box<dyn InboundDatagram>>;
}

/// An unreliable transport for inbound handlers.
pub trait InboundDatagram: Send + Unpin {
    /// Splits the datagram.
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    );
}

/// The receive half.
#[async_trait]
pub trait InboundDatagramRecvHalf: Sync + Send + Unpin {
    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read, the source address where this message
    /// originated and the destination this message shall be sent to.
    ///
    /// This should be implemented by a proxy inbound handler, the destination
    /// address could be decoded from the raw message according to the protocol
    /// specification.
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<SocksAddr>)>;
}

/// The send half.
#[async_trait]
pub trait InboundDatagramSendHalf: Sync + Send + Unpin {
    /// Sends a datagram message on the socket to `dst_addr`, the `src_addr`
    /// specifies the origin of the message. On success, returns the number
    /// of bytes sent.
    ///
    /// This should be implemented by a proxy inbound handler, and the
    /// `src_addr` should be encapsulated into the protocol header to indicate
    /// the origin of the message.
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: Option<&SocksAddr>,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize>;
}

/// An inbound transport represents either a reliable or unreliable transport.
pub enum InboundTransport {
    /// The reliable transport.
    Stream(Box<dyn ProxyStream>, Session),
    /// The unreliable transport.
    Datagram(Box<dyn InboundDatagram>),
    /// None.
    Empty,
}
