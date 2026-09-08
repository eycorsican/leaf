// Linux TPROXY inbound listener (TCP + UDP).
//
// TCP: a listening socket with IP_TRANSPARENT accepts connections that the
// kernel redirected via the `TPROXY` iptables target. For such a connection
// the accepted socket's local address is the *original* destination.
//
// UDP: a socket with IP_TRANSPARENT + IP_RECVORIGDSTADDR receives datagrams
// redirected by TPROXY; the original destination is read from the
// IP_ORIGDSTADDR control message via recvmsg(2). Replies are sent from a
// transparent socket bound to the original destination so the client sees the
// reply coming from the address it originally talked to.

use std::collections::HashMap;
use std::io;
use std::mem;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::channel as tokio_channel;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};
use tracing::{debug, info, warn};

use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::{NatManager, UdpPacket};
use crate::config::Inbound;
use crate::proxy::{ProxyError, ProxyResult};
use crate::session::{DatagramSource, Network, Session, SocksAddr};
use crate::Runner;

// These socket option / control message numbers are stable in the Linux ABI.
const IP_TRANSPARENT: libc::c_int = 19;
const IP_RECVORIGDSTADDR: libc::c_int = 20;
const IP_ORIGDSTADDR: libc::c_int = 20;
const IPV6_RECVORIGDSTADDR: libc::c_int = 74;
const IPV6_ORIGDSTADDR: libc::c_int = 74;
const IPV6_TRANSPARENT: libc::c_int = 75;

fn setsockopt_int(
    fd: libc::c_int,
    level: libc::c_int,
    optname: libc::c_int,
    val: libc::c_int,
) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &val as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_ip_transparent(fd: libc::c_int, is_v6: bool) -> io::Result<()> {
    if is_v6 {
        setsockopt_int(fd, libc::SOL_IPV6, IPV6_TRANSPARENT, 1)
            // some kernels also need the v4 option on a dual-stack socket
            .or_else(|_| setsockopt_int(fd, libc::SOL_IP, IP_TRANSPARENT, 1))
    } else {
        setsockopt_int(fd, libc::SOL_IP, IP_TRANSPARENT, 1)
    }
}

fn set_recv_origdstaddr(fd: libc::c_int, is_v6: bool) -> io::Result<()> {
    if is_v6 {
        setsockopt_int(fd, libc::SOL_IPV6, IPV6_RECVORIGDSTADDR, 1)?;
        // also enable v4-mapped origdst delivery
        let _ = setsockopt_int(fd, libc::SOL_IP, IP_RECVORIGDSTADDR, 1);
        Ok(())
    } else {
        setsockopt_int(fd, libc::SOL_IP, IP_RECVORIGDSTADDR, 1)
    }
}

fn storage_to_socketaddr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    // SAFETY: `storage`/`len` describe a valid sockaddr produced by the kernel.
    let sa = unsafe { socket2::SockAddr::new(*storage, len) };
    sa.as_socket()
}

// Build a transparent TCP listener bound to `addr`.
fn new_tproxy_tcp_listener(addr: SocketAddr) -> io::Result<tokio::net::TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    set_ip_transparent(socket.as_raw_fd(), addr.is_ipv6())?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener)
}

// Build a transparent UDP socket bound to `addr` that also receives the
// original destination address of each datagram.
fn new_tproxy_udp_listener(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    set_ip_transparent(socket.as_raw_fd(), addr.is_ipv6())?;
    set_recv_origdstaddr(socket.as_raw_fd(), addr.is_ipv6())?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

// Build a transparent UDP socket bound to `src` (a non-local address), used to
// emit reply datagrams with a spoofed source address.
fn new_tproxy_udp_sender(src: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(src), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    set_ip_transparent(socket.as_raw_fd(), src.is_ipv6())?;
    socket.set_nonblocking(true)?;
    socket.bind(&src.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_socket)
}

// recvmsg(2) wrapper that returns (len, source, original destination).
fn recv_with_origdst(
    fd: libc::c_int,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    // SAFETY: all pointers below outlive the recvmsg call and point to
    // correctly sized, owned storage.
    unsafe {
        let mut name: libc::sockaddr_storage = mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut control = [0u8; 128];
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_name = &mut name as *mut libc::sockaddr_storage as *mut libc::c_void;
        msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.len() as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let src = storage_to_socketaddr(&name, msg.msg_namelen)
            .ok_or_else(|| io::Error::other("tproxy: bad source address"))?;

        let mut dst: Option<SocketAddr> = None;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let ctype = (*cmsg).cmsg_type;
            let is_v4 = level == libc::SOL_IP && ctype == IP_ORIGDSTADDR;
            let is_v6 = level == libc::SOL_IPV6 && ctype == IPV6_ORIGDSTADDR;
            if is_v4 || is_v6 {
                let data = libc::CMSG_DATA(cmsg) as *const u8;
                let mut storage: libc::sockaddr_storage = mem::zeroed();
                let len = if is_v4 {
                    mem::size_of::<libc::sockaddr_in>()
                } else {
                    mem::size_of::<libc::sockaddr_in6>()
                };
                std::ptr::copy_nonoverlapping(
                    data,
                    &mut storage as *mut libc::sockaddr_storage as *mut u8,
                    len,
                );
                dst = storage_to_socketaddr(&storage, len as libc::socklen_t);
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }

        let dst =
            dst.ok_or_else(|| io::Error::other("tproxy: missing original destination cmsg"))?;
        Ok((n as usize, src, dst))
    }
}

// Receive half of the transparent UDP socket.
struct TproxyRecvHalf {
    afd: AsyncFd<std::net::UdpSocket>,
}

impl TproxyRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        loop {
            let mut guard = self
                .afd
                .readable()
                .await
                .map_err(|e| ProxyError::DatagramFatal(e.into()))?;
            match guard.try_io(|inner| recv_with_origdst(inner.get_ref().as_raw_fd(), buf)) {
                Ok(Ok((n, src, dst))) => {
                    return Ok((n, DatagramSource::new(src, None), SocksAddr::from(dst)));
                }
                Ok(Err(e)) => {
                    return Err(ProxyError::DatagramWarn(e.into()));
                }
                Err(_would_block) => continue,
            }
        }
    }
}

// Send half: keeps one transparent socket per spoofed source address.
struct TproxySendHalf {
    senders: HashMap<SocketAddr, tokio::net::UdpSocket>,
}

impl TproxySendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let src = src_addr
            .ip()
            .map(|ip| SocketAddr::new(ip, src_addr.port()))
            .ok_or_else(|| io::Error::other("tproxy: reply source is not an ip"))?;
        if !self.senders.contains_key(&src) {
            let socket = new_tproxy_udp_sender(src)?;
            self.senders.insert(src, socket);
        }
        let socket = self.senders.get(&src).unwrap();
        socket.send_to(buf, dst_addr).await
    }
}

pub struct TproxyInboundListener {
    pub inbound: Inbound,
    pub dispatcher: Arc<Dispatcher>,
    pub nat_manager: Arc<NatManager>,
}

impl TproxyInboundListener {
    pub fn listen(&self) -> Result<Vec<Runner>> {
        let listen_addr = SocketAddr::new(self.inbound.address.parse()?, self.inbound.port as u16);
        let tag = self.inbound.tag.clone();
        let mut runners: Vec<Runner> = Vec::new();

        // TCP runner.
        {
            let tag = tag.clone();
            let dispatcher = self.dispatcher.clone();
            runners.push(Box::pin(async move {
                let listener = match new_tproxy_tcp_listener(listen_addr) {
                    Ok(l) => l,
                    Err(e) => {
                        warn!("tproxy tcp listen {} failed: {}", listen_addr, e);
                        return;
                    }
                };
                info!("tproxy listening tcp {}", listen_addr);
                loop {
                    match listener.accept().await {
                        Ok((stream, peer)) => {
                            let orig = match stream.local_addr() {
                                Ok(a) => a,
                                Err(e) => {
                                    debug!("tproxy: no original destination: {}", e);
                                    continue;
                                }
                            };
                            let sess = Session {
                                network: Network::Tcp,
                                source: peer,
                                local_addr: orig,
                                destination: SocksAddr::from(orig),
                                inbound_tag: tag.clone(),
                                ..Default::default()
                            };
                            debug!("tproxy tcp src={} dst={}", peer, orig);
                            let dispatcher = dispatcher.clone();
                            tokio::spawn(async move {
                                dispatcher.dispatch_stream(sess, stream).await;
                            });
                        }
                        Err(e) => {
                            debug!("tproxy tcp accept failed: {}", e);
                        }
                    }
                }
            }));
        }

        // UDP runner.
        {
            let tag = tag.clone();
            let nat_manager = self.nat_manager.clone();
            runners.push(Box::pin(async move {
                let socket = match new_tproxy_udp_listener(listen_addr) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("tproxy udp listen {} failed: {}", listen_addr, e);
                        return;
                    }
                };
                let afd = match AsyncFd::new(socket) {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("tproxy udp register failed: {}", e);
                        return;
                    }
                };
                info!("tproxy listening udp {}", listen_addr);

                let mut lr = TproxyRecvHalf { afd };
                let mut ls = TproxySendHalf {
                    senders: HashMap::new(),
                };

                let (l_tx, mut l_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) =
                    tokio_channel(*crate::option::UDP_UPLINK_CHANNEL_SIZE);

                // Downlink: replies from the NAT manager back to clients.
                tokio::spawn(async move {
                    while let Some(pkt) = l_rx.recv().await {
                        let dst_addr = pkt.dst_addr.must_ip();
                        if let Err(e) = ls.send_to(&pkt.data[..], &pkt.src_addr, &dst_addr).await {
                            debug!("tproxy udp reply failed: {}", e);
                        }
                    }
                });

                // Uplink: client datagrams into the NAT manager.
                let mut buf = vec![0u8; *crate::option::DATAGRAM_BUFFER_SIZE * 1024];
                loop {
                    match lr.recv_from(&mut buf).await {
                        Err(ProxyError::DatagramFatal(e)) => {
                            warn!("tproxy udp recv fatal: {}", e);
                            break;
                        }
                        Err(ProxyError::DatagramWarn(e)) => {
                            debug!("tproxy udp recv warn: {}", e);
                            continue;
                        }
                        Ok((n, dgram_src, dst_addr)) => {
                            debug!("tproxy udp src={} dst={} len={}", dgram_src.address, dst_addr, n);
                            let pkt = UdpPacket::new(
                                buf[..n].to_vec(),
                                SocksAddr::from(dgram_src.address),
                                dst_addr,
                            );
                            nat_manager
                                .send(None, &dgram_src, &tag, &l_tx, pkt)
                                .await;
                        }
                    }
                }
            }));
        }

        Ok(runners)
    }
}
