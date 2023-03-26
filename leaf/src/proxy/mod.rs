use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::future::select_ok;
use futures::stream::Stream;
use futures::TryFutureExt;
use log::*;
use socket2::SockRef;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
#[cfg(target_os = "android")]
use {
    std::os::unix::io::RawFd, tokio::io::AsyncReadExt, tokio::io::AsyncWriteExt,
    tokio::net::UnixStream,
};

use crate::{
    app::SyncDnsClient,
    common::resolver::Resolver,
    option,
    session::{DatagramSource, Network, Session, SocksAddr},
};

pub mod datagram;
pub mod inbound;
pub mod outbound;

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
#[cfg(feature = "inbound-http")]
pub mod http;
#[cfg(any(feature = "inbound-quic", feature = "outbound-quic"))]
pub mod quic;
#[cfg(feature = "outbound-redirect")]
pub mod redirect;
#[cfg(feature = "outbound-select")]
pub mod select;
#[cfg(any(feature = "inbound-shadowsocks", feature = "outbound-shadowsocks"))]
pub mod shadowsocks;
#[cfg(feature = "outbound-obfs")]
pub mod obfs;
#[cfg(any(feature = "inbound-socks", feature = "outbound-socks"))]
pub mod socks;
#[cfg(feature = "outbound-static")]
pub mod r#static;
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
    StdOutboundDatagram,
};

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error(transparent)]
    DatagramWarn(anyhow::Error),
    #[error(transparent)]
    DatagramFatal(anyhow::Error),
}

pub type ProxyResult<T> = std::result::Result<T, ProxyError>;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DatagramTransportType {
    Reliable,
    Unreliable,
    Unknown,
}

pub trait Tag {
    fn tag(&self) -> &String;
}

pub trait Color {
    fn color(&self) -> &colored::Color;
}

#[derive(Debug)]
pub enum OutboundBind {
    Ip(SocketAddr),
    Interface(String),
}

#[cfg(target_os = "android")]
async fn protect_socket(fd: RawFd) -> io::Result<()> {
    if crate::mobile::callback::android::is_protect_socket_callback_set() {
        let start = std::time::Instant::now();
        crate::mobile::callback::android::protect_socket(fd).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to protect outbound socket {}: {:?}", fd, e),
            )
        })?;
        log::debug!(
            "protected socket {} in {} µs",
            fd,
            start.elapsed().as_micros()
        );
        return Ok(());
    }
    if let Some(addr) = &*option::SOCKET_PROTECT_SERVER {
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_i32(fd as i32).await?;
        if stream.read_i32().await? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("failed to protect outbound socket {}", fd),
            ));
        }
        return Ok(());
    }
    if !option::SOCKET_PROTECT_PATH.is_empty() {
        let mut stream = UnixStream::connect(&*option::SOCKET_PROTECT_PATH).await?;
        stream.write_i32(fd as i32).await?;
        if stream.read_i32().await? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("failed to protect outbound socket {}", fd),
            ));
        }
        return Ok(());
    }
    Ok(())
}

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

pub struct TcpListener {
    inner: tokio::net::TcpListener,
}

impl TcpListener {
    pub async fn bind(addr: &SocketAddr) -> io::Result<Self> {
        Ok(Self {
            inner: tokio::net::TcpListener::bind(addr).await?,
        })
    }

    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, addr) = self.inner.accept().await?;
        apply_socket_opts(&stream)?;
        stream.set_linger(Some(Duration::ZERO))?;
        Ok((stream, addr))
    }
}

async fn bind_socket<T: BindSocket>(socket: &T, indicator: &SocketAddr) -> io::Result<()> {
    match indicator.ip() {
        IpAddr::V4(v4) if v4.is_loopback() => {
            socket.bind(&SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0).into())?;
            trace!("socket bind loopback v4");
            return Ok(());
        }
        IpAddr::V6(v6) if v6.is_loopback() => {
            socket.bind(&SocketAddrV6::new("::1".parse().unwrap(), 0, 0, 0).into())?;
            trace!("socket bind loopback v6");
            return Ok(());
        }
        _ => {}
    }
    let mut last_err = None;
    for bind in option::OUTBOUND_BINDS.iter() {
        match bind {
            OutboundBind::Interface(iface) => {
                #[cfg(target_os = "macos")]
                unsafe {
                    let ifa = CString::new(iface.as_bytes()).unwrap();
                    let ifidx: libc::c_uint = libc::if_nametoindex(ifa.as_ptr());
                    if ifidx == 0 {
                        last_err = Some(io::Error::last_os_error());
                        continue;
                    }

                    let ret = match indicator {
                        SocketAddr::V4(..) => libc::setsockopt(
                            socket.as_raw_fd(),
                            libc::IPPROTO_IP,
                            libc::IP_BOUND_IF,
                            &ifidx as *const _ as *const libc::c_void,
                            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                        ),
                        SocketAddr::V6(..) => libc::setsockopt(
                            socket.as_raw_fd(),
                            libc::IPPROTO_IPV6,
                            libc::IPV6_BOUND_IF,
                            &ifidx as *const _ as *const libc::c_void,
                            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                        ),
                    };
                    if ret == -1 {
                        last_err = Some(io::Error::last_os_error());
                        continue;
                    }
                    trace!("socket bind {}", iface);
                    return Ok(());
                }
                #[cfg(target_os = "linux")]
                unsafe {
                    let ifa = CString::new(iface.as_bytes()).unwrap();
                    let ret = libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        ifa.as_ptr() as *const libc::c_void,
                        ifa.as_bytes().len() as libc::socklen_t,
                    );
                    if ret == -1 {
                        last_err = Some(io::Error::last_os_error());
                        continue;
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
            }
            OutboundBind::Ip(addr) => {
                if (addr.is_ipv4() && indicator.is_ipv4())
                    || (addr.is_ipv6() && indicator.is_ipv6())
                {
                    if let Err(e) = socket.bind(addr) {
                        last_err = Some(e);
                        continue;
                    }
                    trace!("socket bind {}", addr);
                    return Ok(());
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not bind to any address or interface",
        )
    }))
}

// New UDP socket.
pub async fn new_udp_socket(indicator: &SocketAddr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Socket, Type};
    let socket = if *option::ENABLE_IPV6 {
        // Dual-stack socket.
        // FIXME Windows IPV6_V6ONLY?
        Socket::new(Domain::IPV6, Type::DGRAM, None)?
    } else {
        match indicator {
            SocketAddr::V4(..) => Socket::new(Domain::IPV4, Type::DGRAM, None)?,
            SocketAddr::V6(..) => Socket::new(Domain::IPV6, Type::DGRAM, None)?,
        }
    };
    socket.set_nonblocking(true)?;

    // If the proxy request is coming from an inbound listens on the loopback,
    // the indicator could be a loopback address, we must ignore it.
    if indicator.ip().is_loopback() || *option::ENABLE_IPV6 {
        bind_socket(&socket, &*option::UNSPECIFIED_BIND_ADDR).await?;
    } else {
        bind_socket(&socket, indicator).await?;
    }

    #[cfg(target_os = "android")]
    protect_socket(socket.as_raw_fd()).await?;

    UdpSocket::from_std(socket.into())
}

fn apply_socket_opts_internal(s: SockRef) -> io::Result<()> {
    s.set_keepalive(true)
}

#[cfg(unix)]
fn apply_socket_opts<S: AsRawFd>(socket: &S) -> io::Result<()> {
    let sock_ref = SockRef::from(socket);
    apply_socket_opts_internal(sock_ref)
}
#[cfg(windows)]
fn apply_socket_opts<S: AsRawSocket>(socket: &S) -> io::Result<()> {
    let sock_ref = SockRef::from(socket);
    apply_socket_opts_internal(sock_ref)
}

// TCP dial order.
#[derive(PartialEq)]
pub enum DialOrder {
    // Leave the order of IPs untouched.
    Ordered,
    // Randomize the IPs.
    Random,
    // Randomize the IPs except the first one. We have a little optimization in
    // the DNS client that moves the previously connected IP to the head, we want
    // that IP always tried first.
    PartialRandom,
}

// A single TCP dial.
async fn tcp_dial_task(dial_addr: SocketAddr) -> io::Result<DialResult> {
    let socket = match dial_addr {
        SocketAddr::V4(..) => TcpSocket::new_v4()?,
        SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };

    bind_socket(&socket, &dial_addr).await?;

    #[cfg(target_os = "android")]
    protect_socket(socket.as_raw_fd()).await?;

    trace!("tcp dialing {}", &dial_addr);
    let start = tokio::time::Instant::now();
    let stream = timeout(
        Duration::from_secs(*option::OUTBOUND_DIAL_TIMEOUT),
        socket.connect(dial_addr),
    )
    .await??;
    let elapsed = tokio::time::Instant::now().duration_since(start);

    apply_socket_opts(&stream)?;

    trace!(
        "tcp {} <-> {} connected in {}ms",
        stream.local_addr()?,
        &dial_addr,
        elapsed.as_millis()
    );
    Ok(DialResult {
        stream: Box::new(stream),
        addr: dial_addr,
    })
}

pub async fn connect_stream_outbound(
    sess: &Session,
    dns_client: SyncDnsClient,
    handler: &AnyOutboundHandler,
) -> io::Result<Option<AnyStream>> {
    match handler.stream()?.connect_addr() {
        OutboundConnect::Proxy(Network::Tcp, addr, port) => {
            Ok(Some(new_tcp_stream(dns_client, &addr, &port).await?))
        }
        OutboundConnect::Direct => Ok(Some(
            new_tcp_stream(
                dns_client,
                &sess.destination.host(),
                &sess.destination.port(),
            )
            .await?,
        )),
        _ => Ok(None),
    }
}

pub async fn connect_datagram_outbound(
    sess: &Session,
    dns_client: SyncDnsClient,
    handler: &AnyOutboundHandler,
) -> io::Result<Option<AnyOutboundTransport>> {
    match handler.datagram()?.connect_addr() {
        OutboundConnect::Proxy(network, addr, port) => match network {
            Network::Udp => {
                let socket = new_udp_socket(&sess.source).await?;
                Ok(Some(OutboundTransport::Datagram(Box::new(
                    SimpleOutboundDatagram::new(socket, None, dns_client.clone()),
                ))))
            }
            Network::Tcp => {
                let stream = new_tcp_stream(dns_client.clone(), &addr, &port).await?;
                Ok(Some(OutboundTransport::Stream(stream)))
            }
        },
        OutboundConnect::Direct => {
            let socket = new_udp_socket(&sess.source).await?;
            let dest = match &sess.destination {
                SocksAddr::Domain(domain, port) => {
                    Some(SocksAddr::Domain(domain.to_owned(), port.to_owned()))
                }
                _ => None,
            };
            Ok(Some(OutboundTransport::Datagram(Box::new(
                SimpleOutboundDatagram::new(socket, dest, dns_client.clone()),
            ))))
        }
        _ => Ok(None),
    }
}

struct DialResult {
    stream: AnyStream,
    addr: SocketAddr,
}

// Dials a TCP stream.
pub async fn new_tcp_stream(
    dns_client: SyncDnsClient,
    address: &String,
    port: &u16,
) -> io::Result<AnyStream> {
    let mut resolver = Resolver::new(dns_client.clone(), address, port)
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
            let t = tcp_dial_task(dial_addr);
            tasks.push(Box::pin(t));
        }
        if !tasks.is_empty() {
            match select_ok(tasks.into_iter()).await {
                Ok(v) => {
                    dns_client
                        .read()
                        .await
                        .optimize_cache(address.to_owned(), v.0.addr.ip())
                        .await;
                    return Ok(v.0.stream);
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
    async fn new_tcp_stream(
        &self,
        dns_client: SyncDnsClient,
        address: &String,
        port: &u16,
    ) -> io::Result<AnyStream> {
        new_tcp_stream(dns_client, address, port).await
    }
}

/// An interface with the ability to create UDP sockets.
#[async_trait]
pub trait UdpConnector: Send + Sync + Unpin {
    /// Creates a UDP socket.
    async fn new_udp_socket(&self, indicator: &SocketAddr) -> io::Result<UdpSocket> {
        new_udp_socket(indicator).await
    }
}

/// A reliable transport for both inbound and outbound handlers.
pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

impl<S> ProxyStream for S where S: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

pub type AnyStream = Box<dyn ProxyStream>;

/// An outbound handler for both UDP and TCP outgoing connections.
pub trait OutboundHandler: Tag + Color + Sync + Send + Unpin {
    fn stream(&self) -> io::Result<&AnyOutboundStreamHandler>;
    fn datagram(&self) -> io::Result<&AnyOutboundDatagramHandler>;
}

pub type AnyOutboundHandler = Arc<dyn OutboundHandler>;

#[derive(Debug, Clone)]
pub enum OutboundConnect {
    Proxy(Network, String, u16),
    Direct,
    Next,
    Unknown,
}

/// An outbound handler for outgoing TCP conections.
#[async_trait]
pub trait OutboundStreamHandler<S = AnyStream>: Send + Sync + Unpin {
    /// Returns the address which the underlying transport should
    /// communicate with.
    fn connect_addr(&self) -> OutboundConnect;

    /// Handles a session with the given stream. On success, returns a
    /// stream wraps the incoming stream.
    async fn handle<'a>(&'a self, sess: &'a Session, stream: Option<S>) -> io::Result<S>;
}

type AnyOutboundStreamHandler = Box<dyn OutboundStreamHandler>;

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

pub type AnyOutboundDatagram = Box<dyn OutboundDatagram>;

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
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize>;

    /// Close the soccket gracefully.
    async fn close(&mut self) -> io::Result<()>;
}

/// An outbound handler for outgoing UDP connections.
#[async_trait]
pub trait OutboundDatagramHandler<S = AnyStream, D = AnyOutboundDatagram>:
    Send + Sync + Unpin
{
    /// Returns the address which the underlying transport should
    /// communicate with.
    fn connect_addr(&self) -> OutboundConnect;

    /// Returns the transport type of this handler.
    fn transport_type(&self) -> DatagramTransportType;

    /// Handles a session with the transport. On success, returns an outbound
    /// datagram wraps the incoming transport.
    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<S, D>>,
    ) -> io::Result<D>;
}

type AnyOutboundDatagramHandler = Box<dyn OutboundDatagramHandler>;

/// An outbound transport represents either a reliable or unreliable transport.
pub enum OutboundTransport<S, D> {
    /// The reliable transport.
    Stream(S),
    /// The unreliable transport.
    Datagram(D),
}

pub type AnyOutboundTransport = OutboundTransport<AnyStream, AnyOutboundDatagram>;

pub trait InboundHandler: Tag + Send + Sync + Unpin {
    fn stream(&self) -> io::Result<&AnyInboundStreamHandler>;
    fn datagram(&self) -> io::Result<&AnyInboundDatagramHandler>;
}

pub type AnyInboundHandler = Arc<dyn InboundHandler>;

/// An inbound handler for incoming TCP connections.
#[async_trait]
pub trait InboundStreamHandler<S = AnyStream, D = AnyInboundDatagram>: Send + Sync + Unpin {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: S,
    ) -> std::io::Result<InboundTransport<S, D>>;
}

pub type AnyInboundStreamHandler = Arc<dyn InboundStreamHandler>;

/// An inbound handler for incoming UDP connections.
#[async_trait]
pub trait InboundDatagramHandler<S = AnyStream, D = AnyInboundDatagram>:
    Send + Sync + Unpin
{
    async fn handle<'a>(&'a self, socket: D) -> io::Result<InboundTransport<S, D>>;
}

pub type AnyInboundDatagramHandler = Arc<dyn InboundDatagramHandler>;

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

pub type AnyInboundDatagram = Box<dyn InboundDatagram>;

/// The receive half.
#[async_trait]
pub trait InboundDatagramRecvHalf: Sync + Send + Unpin {
    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read, the source where this message
    /// originated and the destination this message shall be sent to.
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)>;
}

/// The send half.
#[async_trait]
pub trait InboundDatagramSendHalf: Sync + Send + Unpin {
    /// Sends a datagram message on the socket to `dst_addr`, the `src_addr`
    /// specifies the origin of the message. On success, returns the number
    /// of bytes sent.
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize>;

    /// Close the socket gracefully.
    async fn close(&mut self) -> io::Result<()>;
}

pub enum BaseInboundTransport<S, D> {
    /// The reliable transport.
    Stream(S, Session),
    /// The unreliable transport.
    Datagram(D, Option<Session>),
    /// None.
    Empty,
}

pub type AnyBaseInboundTransport = BaseInboundTransport<AnyStream, AnyInboundDatagram>;

pub type IncomingTransport<S, D> =
    Box<dyn Stream<Item = BaseInboundTransport<S, D>> + Send + Unpin>;

pub type AnyIncomingTransport = IncomingTransport<AnyStream, AnyInboundDatagram>;

/// An inbound transport represents either a reliable or unreliable transport.
pub enum InboundTransport<S, D> {
    /// The reliable transport.
    Stream(S, Session),
    /// The unreliable transport.
    Datagram(D, Option<Session>),
    /// Incoming transports can be either reliable or unreliable.
    Incoming(IncomingTransport<S, D>),
    /// None.
    Empty,
}

pub type AnyInboundTransport = InboundTransport<AnyStream, AnyInboundDatagram>;
