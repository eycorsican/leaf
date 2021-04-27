use std::ffi::CString;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{
    io,
    net::{IpAddr, SocketAddr},
};

use async_trait::async_trait;
use futures::future::select_ok;
use futures::stream::Stream;
use futures::TryFutureExt;
use lazy_static::lazy_static;
use log::*;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::Mutex;

#[cfg(target_os = "android")]
use {
    std::os::unix::io::AsRawFd, std::os::unix::io::RawFd, tokio::io::AsyncReadExt,
    tokio::io::AsyncWriteExt, tokio::net::UnixStream,
};

use crate::{
    app::SyncDnsClient,
    common::resolver::Resolver,
    option,
    session::{DatagramSource, Session, SocksAddr},
};

pub mod datagram;
pub mod inbound;
pub mod outbound;
pub mod stream;

#[cfg(any(feature = "inbound-amux", feature = "outbound-amux"))]
pub mod amux;
#[cfg(any(feature = "inbound-chain", feature = "outbound-chain"))]
pub mod chain;
#[cfg(feature = "outbound-direct")]
pub mod direct;
#[cfg(feature = "outbound-drop")]
pub mod drop;
#[cfg(feature = "outbound-failover")]
pub mod failover;
#[cfg(feature = "outbound-h2")]
pub mod h2;
#[cfg(feature = "inbound-http")]
pub mod http;
#[cfg(any(feature = "inbound-quic", feature = "outbound-quic"))]
pub mod quic;
#[cfg(feature = "outbound-random")]
pub mod random;
#[cfg(feature = "outbound-redirect")]
pub mod redirect;
#[cfg(feature = "outbound-retry")]
pub mod retry;
#[cfg(feature = "outbound-select")]
pub mod select;
#[cfg(any(feature = "inbound-shadowsocks", feature = "outbound-shadowsocks"))]
pub mod shadowsocks;
#[cfg(any(feature = "inbound-socks", feature = "outbound-socks"))]
pub mod socks;
#[cfg(feature = "outbound-tls")]
pub mod tls;
#[cfg(any(feature = "inbound-trojan", feature = "outbound-trojan"))]
pub mod trojan;
#[cfg(feature = "outbound-tryall")]
pub mod tryall;
#[cfg(all(
    feature = "inbound-tun",
    any(
        target_os = "ios",
        target_os = "android",
        target_os = "macos",
        target_os = "linux"
    )
))]
pub mod tun;
#[cfg(feature = "outbound-vmess")]
pub mod vmess;
#[cfg(any(feature = "inbound-ws", feature = "outbound-ws"))]
pub mod ws;

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

#[derive(Clone, PartialEq, Debug)]
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

#[cfg(target_os = "android")]
lazy_static! {
    static ref SOCKET_PROTECT_PATH: Mutex<Option<String>> = Mutex::new(None);
}

pub enum OutboundBind {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Interface(String),
}

lazy_static! {
    static ref OUTBOUND_BINDS: Mutex<Option<Vec<OutboundBind>>> = Mutex::new(None);
}

// Sets the RPC service endpoint for protecting outbound sockets on Android to
// avoid infinite loop. The `path` is treated as a Unix domain socket endpoint.
// The RPC service simply listens for incoming connections, reads an int32 on
// each connection, treats it as the file descriptor to protect, writes back 0
// on success.
#[cfg(target_os = "android")]
pub async fn set_socket_protect_path(path: String) {
    SOCKET_PROTECT_PATH.lock().await.replace(path);
}

pub async fn set_outbound_binds(binds: Vec<OutboundBind>) {
    OUTBOUND_BINDS.lock().await.replace(binds);
}

#[cfg(target_os = "android")]
async fn protect_socket(fd: RawFd) -> io::Result<()> {
    if let Some(path) = SOCKET_PROTECT_PATH.lock().await.as_ref() {
        let mut stream = UnixStream::connect(path).await?;
        stream.write_i32(fd as i32).await?;
        if stream.read_i32().await? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("failed to protect outbound socket {}", fd),
            ));
        }
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::os::unix::io::AsRawFd;

#[cfg(any(target_os = "macos", target_os = "linux"))]
trait BindSocket: AsRawFd {
    fn bind(&self, bind_addr: &SocketAddr) -> io::Result<()>;
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
trait BindSocket {
    fn bind(&self, bind_addr: &SocketAddr) -> io::Result<()>;
}

impl BindSocket for TcpSocket {
    fn bind(&self, bind_addr: &SocketAddr) -> io::Result<()> {
        self.bind(bind_addr.to_owned())
    }
}

impl BindSocket for socket2::Socket {
    fn bind(&self, bind_addr: &SocketAddr) -> io::Result<()> {
        self.bind(&bind_addr.to_owned().into())
    }
}

async fn bind_socket<T: BindSocket>(
    socket: &T,
    bind_addr: &SocketAddr,
    indicator: &SocketAddr,
) -> io::Result<()> {
    if let Some(binds) = OUTBOUND_BINDS.lock().await.as_ref() {
        for bind in binds.iter() {
            match bind {
                OutboundBind::Interface(iface) => unsafe {
                    #[cfg(target_os = "macos")]
                    {
                        let ifa = CString::new(iface.as_bytes()).unwrap();
                        let ifidx: libc::c_uint = libc::if_nametoindex(ifa.as_ptr());
                        if ifidx == 0 {
                            return Err(io::Error::last_os_error());
                        }

                        let ret = match indicator {
                            SocketAddr::V4(..) => {
                                // https://github.com/apple/darwin-xnu/blob/8f02f2a044b9bb1ad951987ef5bab20ec9486310/bsd/netinet/in.h#L484
                                const IP_BOUND_IF: libc::c_int = 25;
                                libc::setsockopt(
                                    socket.as_raw_fd(),
                                    libc::IPPROTO_IP,
                                    IP_BOUND_IF,
                                    &ifidx as *const _ as *const libc::c_void,
                                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                                )
                            }
                            SocketAddr::V6(..) => {
                                // https://github.com/apple/darwin-xnu/blob/8f02f2a044b9bb1ad951987ef5bab20ec9486310/bsd/netinet6/in6.h#L692
                                const IPV6_BOUND_IF: libc::c_int = 125;
                                libc::setsockopt(
                                    socket.as_raw_fd(),
                                    libc::IPPROTO_IPV6,
                                    IPV6_BOUND_IF,
                                    &ifidx as *const _ as *const libc::c_void,
                                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                                )
                            }
                        };
                        if ret == -1 {
                            return Err(io::Error::last_os_error());
                        }
                        trace!("socket bind {}", iface);
                        return Ok(());
                    }
                    #[cfg(target_os = "linux")]
                    {
                        let ifa = CString::new(iface.as_bytes()).unwrap();
                        let ret = libc::setsockopt(
                            socket.as_raw_fd(),
                            libc::SOL_SOCKET,
                            libc::SO_BINDTODEVICE,
                            ifa.as_ptr() as *const libc::c_void,
                            ifa.as_bytes().len() as libc::socklen_t,
                        );
                        if ret == -1 {
                            return Err(io::Error::last_os_error());
                        }
                        trace!("socket bind {}", iface);
                        return Ok(());
                    }
                    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "binding to interface is not supported on this platform",
                        ));
                    }
                },
                OutboundBind::Ipv4(ip) => {
                    if let SocketAddr::V4(..) = indicator {
                        trace!("socket bind {}", ip);
                        return socket.bind(&SocketAddr::new(IpAddr::V4(ip.to_owned()), 0));
                    }
                }
                OutboundBind::Ipv6(ip) => {
                    if let SocketAddr::V6(..) = indicator {
                        trace!("socket bind {}", ip);
                        return socket.bind(&SocketAddr::new(IpAddr::V6(ip.to_owned()), 0));
                    }
                }
            }
        }
    }
    if bind_addr.ip().is_unspecified() {
        match indicator {
            SocketAddr::V4(..) => {
                let ip = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
                trace!("socket bind {}", &ip);
                return socket.bind(&ip);
            }
            SocketAddr::V6(..) => {
                let ip = "[::]:0".parse::<SocketAddr>().unwrap();
                trace!("socket bind {}", &ip);
                return socket.bind(&ip);
            }
        }
    }
    trace!("socket bind {}", bind_addr);
    socket.bind(bind_addr)
}

// New UDP socket.
async fn create_udp_socket(
    bind_addr: &SocketAddr,
    indicator: &SocketAddr,
) -> io::Result<UdpSocket> {
    use socket2::{Domain, Socket, Type};
    let socket = match indicator {
        SocketAddr::V4(..) => Socket::new(Domain::IPV4, Type::DGRAM, None)?,
        SocketAddr::V6(..) => Socket::new(Domain::IPV6, Type::DGRAM, None)?,
    };
    socket.set_nonblocking(true)?;

    bind_socket(&socket, bind_addr, indicator).await?;

    #[cfg(target_os = "android")]
    protect_socket(socket.as_raw_fd()).await?;

    UdpSocket::from_std(socket.into())
}

// A single TCP dial.
async fn tcp_dial_task(
    dial_addr: SocketAddr,
    bind_addr: &SocketAddr,
) -> io::Result<(Box<dyn ProxyStream>, SocketAddr)> {
    let socket = match dial_addr {
        SocketAddr::V4(..) => TcpSocket::new_v4()?,
        SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };

    bind_socket(&socket, bind_addr, &dial_addr).await?;

    #[cfg(target_os = "android")]
    protect_socket(socket.as_raw_fd()).await?;

    trace!("tcp dialing {}", &dial_addr);
    let stream = socket.connect(dial_addr).await?;
    trace!("tcp connected {} <-> {}", stream.local_addr()?, &dial_addr);
    Ok((Box::new(SimpleProxyStream(stream)), dial_addr))
}

// Dials a TCP stream.
pub async fn dial_tcp_stream(
    dns_client: SyncDnsClient,
    bind_addr: &SocketAddr,
    address: &String,
    port: &u16,
) -> io::Result<Box<dyn ProxyStream>> {
    let mut resolver = Resolver::new(dns_client.clone(), bind_addr, address, port)
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
        for _ in 0..*option::OUTBOUND_DIAL_CONCURRENCY {
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
                Ok(v) => {
                    #[rustfmt::skip]
                    dns_client.read().await.optimize_cache(address.to_owned(), v.0.1.ip()).await;
                    #[rustfmt::skip]
                    return Ok(v.0.0);
                }
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

/// An interface with the ability to dial TCP connections.
#[async_trait]
pub trait TcpConnector: Send + Sync + Unpin {
    /// Dials a TCP connection.
    async fn dial_tcp_stream(
        &self,
        dns_client: SyncDnsClient,
        bind_addr: &SocketAddr,
        address: &String,
        port: &u16,
    ) -> io::Result<Box<dyn ProxyStream>> {
        dial_tcp_stream(dns_client, bind_addr, address, port).await
    }
}

/// An interface with the ability to create UDP sockets.
#[async_trait]
pub trait UdpConnector: Send + Sync + Unpin {
    /// Creates a UDP socket.
    async fn create_udp_socket(
        &self,
        bind_addr: &SocketAddr,
        indicator: &SocketAddr,
    ) -> io::Result<UdpSocket> {
        create_udp_socket(bind_addr, indicator).await
    }
}

/// A reliable transport for both inbound and outbound handlers.
pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

/// An outbound handler for both UDP and TCP outgoing connections.
pub trait OutboundHandler:
    Tag + Color + HandlerTyped + TcpOutboundHandler + UdpOutboundHandler + Send + Unpin
{
    fn has_tcp(&self) -> bool;
    fn has_udp(&self) -> bool;
}

#[derive(Debug)]
pub enum OutboundConnect {
    Proxy(String, u16, SocketAddr),
    Direct(SocketAddr),
    NoConnect,
}

/// An outbound handler for outgoing TCP conections.
#[async_trait]
pub trait TcpOutboundHandler: Send + Sync + Unpin {
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
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)>;
}

/// The send half.
#[async_trait]
pub trait OutboundDatagramSendHalf: Sync + Send + Unpin {
    /// Sends a message on the socket to `dst_addr`. On success, returns the
    /// number of bytes sent.
    ///
    /// `dst_addr` is not the proxy server address.
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize>;
}

/// An outbound handler for outgoing UDP connections.
#[async_trait]
pub trait UdpOutboundHandler: Send + Sync + Unpin {
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
}

/// An outbound transport represents either a reliable or unreliable transport.
pub enum OutboundTransport {
    /// The reliable transport.
    Stream(Box<dyn ProxyStream>),
    /// The unreliable transport.
    Datagram(Box<dyn OutboundDatagram>),
}

pub trait InboundHandler:
    Tag + TcpInboundHandler + UdpInboundHandler + Send + Sync + Unpin
{
    fn has_tcp(&self) -> bool;
    fn has_udp(&self) -> bool;
}

/// An inbound handler for incoming TCP connections.
#[async_trait]
pub trait TcpInboundHandler: Send + Sync + Unpin {
    async fn handle_tcp<'a>(
        &'a self,
        sess: Session,
        stream: Box<dyn ProxyStream>,
    ) -> std::io::Result<InboundTransport>;
}

/// An inbound handler for incoming UDP connections.
#[async_trait]
pub trait UdpInboundHandler: Send + Sync + Unpin {
    // TODO Returns an InboundTransport to support UDP-based reliable transports
    // such as QUIC.
    async fn handle_udp<'a>(
        &'a self,
        socket: Box<dyn InboundDatagram>,
    ) -> io::Result<InboundTransport>;
}

/// An unreliable transport for inbound handlers.
pub trait InboundDatagram: Send + Sync + Unpin {
    /// Splits the datagram.
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    );

    /// Turns the datagram into a [`std::net::UdpSocket`].
    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket>;
}

/// The receive half.
#[async_trait]
pub trait InboundDatagramRecvHalf: Sync + Send + Unpin {
    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read, the source where this message
    /// originated and the destination this message shall be sent to.
    ///
    /// This should be implemented by a proxy inbound handler, the destination
    /// address could be decoded from the raw message according to the protocol
    /// specification.
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<(usize, DatagramSource, Option<SocksAddr>)>;
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

pub enum SingleInboundTransport {
    /// The reliable transport.
    Stream(Box<dyn ProxyStream>, Session),
    /// The unreliable transport.
    Datagram(Box<dyn InboundDatagram>),
    /// None.
    Empty,
}

pub type IncomingTransport = Box<dyn Stream<Item = SingleInboundTransport> + Send + Unpin>;

/// An inbound transport represents either a reliable or unreliable transport.
pub enum InboundTransport {
    /// The reliable transport.
    Stream(Box<dyn ProxyStream>, Session),
    /// The unreliable transport.
    Datagram(Box<dyn InboundDatagram>),
    Incoming(IncomingTransport),
    /// None.
    Empty,
}
