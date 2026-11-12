//! kiri's own sockets (WebRTC UDP, TLS transports, HTTPS to registrars,
//! mirrors, config URLs and collectors, the bridge's link to the egress, the
//! NAT probe) go through leaf's outbound socket handling, as leaf's own
//! outbound sockets do: kiri shows each one to a [`SocketProtector`] before
//! it is used, and does not use one it refuses.
//!
//! - `OUTBOUND_INTERFACE` set (`leaf -b IFACE`, or set by leaf's tun setup):
//!   the socket is bound like leaf's own (`bind_socket_to` in
//!   `proxy/mod.rs`): an interface name is bound with `IP_BOUND_IF` /
//!   `IPV6_BOUND_IF` (macOS) or `SO_BINDTODEVICE` (Linux), an address with
//!   `bind(2)`. Interface names are not supported on other platforms
//!   (leaf's own sockets fail the same way); Windows uses addresses (leaf's
//!   tun inbound sets them), there is no `IP_UNICAST_IF` in leaf. kiri's
//!   WebRTC sockets come already bound to their local address: with
//!   addresses only, such a socket passes if it is bound to one of them
//!   (leaf then binds kiri's WebRTC sockets to those addresses, see
//!   `super::settings`), else it is refused.
//! - Android: then leaf's protect callback (`VpnService.protect` through
//!   `mobile::callback::android`), else the protect RPC
//!   (`SOCKET_PROTECT_SERVER` / `SOCKET_PROTECT_PATH`), as leaf's own sockets.
//!   kiri asks synchronously, so the RPC is a short blocking exchange on a
//!   local socket.
//! - Neither: no protector, kiri's sockets are made as before.
//!
//! With a protector, kiri resolves host names (its URLs, STUN servers)
//! itself over sockets shown to it (`kiri_core::resolve`), not with the
//! system resolver, which would answer through leaf's own tun (fake IPs).
//!
//! A refused socket is logged at WARN, the same message at most once a
//! minute (with the number left out since), so a permanently failing
//! interface does not log once per socket per retry.

use std::io;
use std::mem::ManuallyDrop;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use kiri_core::api::RawSocket;
use kiri_core::SocketProtector;

use crate::proxy::OutboundBind;

/// The protector for kiri's sockets in this process (module docs), or
/// `None` when leaf does nothing to its own outbound sockets either. Reads
/// `OUTBOUND_INTERFACE` (once per process, as leaf).
pub fn protector() -> Option<Arc<dyn SocketProtector>> {
    let binds: &'static [OutboundBind] = &crate::option::OUTBOUND_BINDS;
    if binds.is_empty() && !cfg!(target_os = "android") {
        return None;
    }
    Some(Arc::new(LeafProtector { binds }))
}

/// The first interface name among `OUTBOUND_INTERFACE`'s entries, for
/// kiri's WebRTC sockets (`udp_interface`).
pub fn bind_interface() -> Option<String> {
    crate::option::OUTBOUND_BINDS.iter().find_map(|b| match b {
        OutboundBind::Interface(name) => Some(name.clone()),
        OutboundBind::Ip(_) => None,
    })
}

/// The local addresses among `OUTBOUND_INTERFACE`'s entries (port 0), for
/// kiri's WebRTC sockets; empty when it names none.
pub fn bind_addresses() -> Vec<String> {
    crate::option::OUTBOUND_BINDS
        .iter()
        .filter_map(|b| match b {
            OutboundBind::Ip(a) => Some(SocketAddr::new(a.ip(), 0).to_string()),
            OutboundBind::Interface(_) => None,
        })
        .collect()
}

pub struct LeafProtector {
    binds: &'static [OutboundBind],
}

impl LeafProtector {
    #[cfg(test)]
    pub fn with_binds(binds: &'static [OutboundBind]) -> Self {
        Self { binds }
    }

    fn apply(&self, raw: RawSocket) -> io::Result<()> {
        if !self.binds.is_empty() {
            // Borrowed: the socket stays kiri's.
            let socket = ManuallyDrop::new(from_raw(raw));
            bind(&socket, self.binds)?;
        }
        #[cfg(target_os = "android")]
        android_protect(raw)?;
        Ok(())
    }
}

impl SocketProtector for LeafProtector {
    fn protect(&self, socket: RawSocket) -> bool {
        match self.apply(socket) {
            Ok(()) => true,
            Err(e) => {
                let msg = e.to_string();
                match WARNINGS.check(&msg, std::time::Instant::now()) {
                    Some(0) => tracing::warn!("kiri: socket not protected, not used: {}", msg),
                    Some(n) => tracing::warn!(
                        "kiri: socket not protected, not used: {} ({} more since the last warning)",
                        msg,
                        n
                    ),
                    None => {}
                }
                false
            }
        }
    }
}

/// Refused-socket warnings of this process (module docs).
static WARNINGS: WarnLimit = WarnLimit::new(std::time::Duration::from_secs(60));

/// Lets the same message through at most once per `every`, counting the
/// ones held back.
pub struct WarnLimit {
    every: std::time::Duration,
    /// Message → when it was last let through, how many held back since.
    seen: std::sync::Mutex<Option<std::collections::HashMap<String, (std::time::Instant, u64)>>>,
}

impl WarnLimit {
    /// Distinct messages remembered (a flood of distinct ones resets it).
    const CAP: usize = 64;

    pub const fn new(every: std::time::Duration) -> Self {
        Self {
            every,
            seen: std::sync::Mutex::new(None),
        }
    }

    /// `Some(held back since the last one let through)` if `msg` is to be
    /// logged at `now`, `None` if it is held back.
    pub fn check(&self, msg: &str, now: std::time::Instant) -> Option<u64> {
        let mut g = self.seen.lock().unwrap();
        let seen = g.get_or_insert_with(Default::default);
        if let Some((last, held)) = seen.get_mut(msg) {
            if now.duration_since(*last) < self.every {
                *held += 1;
                return None;
            }
            let n = *held;
            *last = now;
            *held = 0;
            return Some(n);
        }
        if seen.len() >= Self::CAP {
            seen.clear();
        }
        seen.insert(msg.to_string(), (now, 0));
        Some(0)
    }
}

#[cfg(unix)]
fn from_raw(raw: RawSocket) -> socket2::Socket {
    use std::os::unix::io::FromRawFd;
    // SAFETY: kiri passes an open socket it owns; the caller never drops it.
    unsafe { socket2::Socket::from_raw_fd(raw) }
}

#[cfg(windows)]
fn from_raw(raw: RawSocket) -> socket2::Socket {
    use std::os::windows::io::FromRawSocket;
    // SAFETY: as above.
    unsafe { socket2::Socket::from_raw_socket(raw) }
}

/// Binds `socket` by `binds` as leaf binds its own outbound sockets for a
/// non-loopback destination of the socket's family.
fn bind(socket: &socket2::Socket, binds: &[OutboundBind]) -> io::Result<()> {
    let local = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not an IP socket"))?;
    let any: IpAddr = match local {
        SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    match super::super::bind_socket_to(socket, &SocketAddr::new(any, 0), binds) {
        Ok(()) => Ok(()),
        // Already bound (kiri's WebRTC sockets): fine on a listed address.
        Err(_)
            if local.port() != 0
                && binds
                    .iter()
                    .any(|b| matches!(b, OutboundBind::Ip(a) if a.ip() == local.ip())) =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// leaf's Android protect (`proxy::protect_socket`), synchronously.
#[cfg(target_os = "android")]
fn android_protect(fd: RawSocket) -> io::Result<()> {
    use std::io::{Read, Write};
    let failed = |e: String| io::Error::new(io::ErrorKind::Other, e);
    if crate::mobile::callback::android::is_protect_socket_callback_set() {
        return crate::mobile::callback::android::protect_socket(fd)
            .map_err(|e| failed(format!("protect callback: {:?}", e)));
    }
    fn rpc(mut s: impl Read + Write, fd: RawSocket) -> io::Result<()> {
        s.write_all(&(fd as i32).to_be_bytes())?;
        let mut answer = [0u8; 4];
        s.read_exact(&mut answer)?;
        if i32::from_be_bytes(answer) != 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "protect RPC refused"));
        }
        Ok(())
    }
    let bound = Some(std::time::Duration::from_secs(2));
    if let Some(addr) = &*crate::option::SOCKET_PROTECT_SERVER {
        let s = std::net::TcpStream::connect_timeout(addr, bound.unwrap())?;
        s.set_read_timeout(bound)?;
        return rpc(s, fd);
    }
    if !crate::option::SOCKET_PROTECT_PATH.is_empty() {
        let s = std::os::unix::net::UnixStream::connect(&*crate::option::SOCKET_PROTECT_PATH)?;
        s.set_read_timeout(bound)?;
        return rpc(s, fd);
    }
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn protector(iface: &str) -> LeafProtector {
        let binds: &'static [OutboundBind] =
            Box::leak(vec![OutboundBind::Interface(iface.into())].into_boxed_slice());
        LeafProtector::with_binds(binds)
    }

    fn raw(s: &impl std::os::unix::io::AsRawFd) -> RawSocket {
        s.as_raw_fd()
    }

    #[tokio::test]
    async fn binding_to_lo0_keeps_loopback_tcp_and_udp_working() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let p = protector("lo0");
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let s = tokio::net::TcpSocket::new_v4().unwrap();
        assert!(p.protect(raw(&s)));
        let mut c = s.connect(l.local_addr().unwrap()).await.unwrap();
        let (mut a, _) = l.accept().await.unwrap();
        c.write_all(b"kiri").await.unwrap();
        let mut b = [0u8; 4];
        a.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"kiri");

        // UDP, already bound (as kiri's WebRTC sockets come).
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let u = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(p.protect(raw(&u)));
        u.send_to(b"ping", peer.local_addr().unwrap())
            .await
            .unwrap();
        let (n, from) = peer.recv_from(&mut b).await.unwrap();
        assert_eq!((&b[..n], from), (&b"ping"[..], u.local_addr().unwrap()));

        // IPv6 takes IPV6_BOUND_IF.
        let s6 = tokio::net::TcpSocket::new_v6().unwrap();
        assert!(p.protect(raw(&s6)));
    }

    #[tokio::test]
    async fn a_missing_interface_refuses_the_socket() {
        let p = protector("nonexist0");
        let s = tokio::net::TcpSocket::new_v4().unwrap();
        assert!(!p.protect(raw(&s)));
        let u = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(!p.protect(raw(&u)));
    }

    #[tokio::test]
    async fn an_address_binds_unbound_sockets_and_passes_sockets_bound_to_it() {
        let binds: &'static [OutboundBind] =
            Box::leak(vec![OutboundBind::Ip("127.0.0.1:0".parse().unwrap())].into_boxed_slice());
        let p = LeafProtector::with_binds(binds);
        let s = tokio::net::TcpSocket::new_v4().unwrap();
        assert!(p.protect(raw(&s)));
        assert_eq!(s.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
        let u = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(p.protect(raw(&u)), "bound to the listed address");
        let other = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        assert!(!p.protect(raw(&other)), "bound elsewhere");
    }
}

#[cfg(test)]
mod warn_tests {
    use super::WarnLimit;
    use std::time::{Duration, Instant};

    /// The same message once a minute with the count held back; another
    /// message is not held back by it. Before, every refused socket logged.
    #[test]
    fn same_warning_at_most_once_a_minute_with_a_count() {
        let w = WarnLimit::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert_eq!(w.check("Device not configured", t0), Some(0));
        for i in 1..=5 {
            assert_eq!(
                w.check("Device not configured", t0 + Duration::from_secs(i)),
                None
            );
        }
        assert_eq!(w.check("other", t0 + Duration::from_secs(2)), Some(0));
        assert_eq!(
            w.check("Device not configured", t0 + Duration::from_secs(61)),
            Some(5)
        );
        assert_eq!(
            w.check("Device not configured", t0 + Duration::from_secs(62)),
            None
        );
        assert_eq!(
            w.check("Device not configured", t0 + Duration::from_secs(200)),
            Some(1)
        );
    }
}
