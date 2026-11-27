//! The async face of the stack: one engine behind a lock, the packet queues
//! to and from the TUN device, and the TCP streams and UDP socket the
//! inbound hands to the dispatcher.
//!
//! Every operation runs against the engine synchronously under the lock and
//! then flushes what it produced — packets to send, connections to wake —
//! so the engine's buffers are the only place data waits. Nothing is copied
//! into a second per-connection buffer on the way to the application.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use futures::Stream;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::proxy::tun::netstack::engine::{Accepted, ConnId, EngineStats, Instant, Limits};
use crate::proxy::tun::netstack::frag::{Reassembler, ReassemblyLimits};
use crate::proxy::tun::netstack::ip;
use crate::proxy::tun::netstack::tcp::TcpEngine;

/// Everything the stack is sized by. The packet queues follow from
/// `limits.memory_budget`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    pub limits: Limits,
    pub reassembly: ReassemblyLimits,
}

/// Counters for the memory and loss checks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StackStats {
    pub engine: EngineStats,
    pub output_queued: usize,
    pub output_queued_bytes: usize,
    pub output_dropped: u64,
    pub udp_queued: usize,
    pub udp_queued_bytes: usize,
    pub udp_dropped: u64,
    pub accept_queued: usize,
    pub fragments_held_bytes: usize,
    pub fragments_dropped: u64,
    /// Packets from the TUN device that were neither TCP nor UDP, or were
    /// malformed.
    pub input_ignored: u64,
}

#[derive(Default)]
struct Wakers {
    read: Option<Waker>,
    write: Option<Waker>,
}

struct Core {
    engine: TcpEngine,
    config: Config,
    reassembler: Reassembler,
    wakers: HashMap<ConnId, Wakers>,
    accepted: VecDeque<Accepted>,
    accept_waker: Option<Waker>,
    output: Output,
    output_waker: Option<Waker>,
    udp_in: VecDeque<Datagram>,
    udp_in_bytes: usize,
    udp_in_cap: usize,
    udp_waker: Option<Waker>,
    udp_dropped: u64,
    next_fragment_id: u32,
    input_ignored: u64,
    shut_down: bool,
    scratch_packets: Vec<Vec<u8>>,
    scratch_ready: Vec<ConnId>,
}

/// One UDP datagram as the application sees it.
pub type Datagram = (Vec<u8>, SocketAddr, SocketAddr);

/// The memory budget the queues are sized from when there is none.
const UNBUDGETED: usize = 16 << 20;

/// What each UDP queue may hold, in bytes: a share of the memory budget, and
/// never less than the largest datagram.
fn udp_queue_bytes(limits: &Limits) -> usize {
    (limits.memory_budget.unwrap_or(UNBUDGETED) / 16).max(128 << 10)
}

/// TCP waiting for the device is bounded by the engine's windows and budget;
/// this only stops a device that takes nothing from letting retransmissions
/// pile up for ever.
fn tcp_backstop_bytes(limits: &Limits) -> usize {
    (limits.memory_budget.unwrap_or(UNBUDGETED) / 4).max(1 << 20)
}

/// UDP packets taken in a row while TCP waits.
const UDP_BURST: u8 = 4;

/// Packets waiting for the TUN device, in two queues. TCP from the engine is
/// never dropped short of the backstop: dropping a segment stalls its
/// connection until the retransmission timer fires, and the engine's windows
/// bound it anyway. UDP is bounded in bytes and kept whole, a datagram's
/// fragments all queued or none; past the bound the oldest datagrams go,
/// the freshest being the ones worth sending. UDP goes out first, so
/// latency-sensitive datagrams do not wait behind a bulk download, but never
/// more than `UDP_BURST` packets in a row while TCP waits, so a stream of
/// datagrams cannot starve the acknowledgements TCP runs on.
struct Output {
    tcp: VecDeque<Vec<u8>>,
    tcp_bytes: usize,
    tcp_cap: usize,
    udp: VecDeque<VecDeque<Vec<u8>>>,
    udp_packets: usize,
    udp_bytes: usize,
    udp_cap: usize,
    udp_streak: u8,
    dropped: u64,
}

impl Output {
    fn new(limits: &Limits) -> Self {
        Output {
            tcp: VecDeque::new(),
            tcp_bytes: 0,
            tcp_cap: tcp_backstop_bytes(limits),
            udp: VecDeque::new(),
            udp_packets: 0,
            udp_bytes: 0,
            udp_cap: udp_queue_bytes(limits),
            udp_streak: 0,
            dropped: 0,
        }
    }

    fn push_tcp(&mut self, packet: Vec<u8>) {
        if self.tcp_bytes + packet.len() > self.tcp_cap {
            self.dropped += 1;
            return;
        }
        self.tcp_bytes += packet.len();
        self.tcp.push_back(packet);
    }

    /// Queues one datagram, as the packets carrying it.
    fn push_udp(&mut self, packets: Vec<Vec<u8>>) {
        let bytes: usize = packets.iter().map(Vec::len).sum();
        if bytes > self.udp_cap {
            self.dropped += packets.len() as u64;
            return;
        }
        while self.udp_bytes + bytes > self.udp_cap {
            let Some(oldest) = self.udp.pop_front() else {
                break;
            };
            self.udp_packets -= oldest.len();
            self.udp_bytes -= oldest.iter().map(Vec::len).sum::<usize>();
            self.dropped += oldest.len() as u64;
        }
        self.udp_packets += packets.len();
        self.udp_bytes += bytes;
        self.udp.push_back(packets.into());
    }

    fn pop(&mut self) -> Option<Vec<u8>> {
        let udp_turn =
            !self.udp.is_empty() && (self.tcp.is_empty() || self.udp_streak < UDP_BURST);
        if udp_turn {
            let datagram = self.udp.front_mut()?;
            let packet = datagram.pop_front()?;
            if datagram.is_empty() {
                self.udp.pop_front();
            }
            self.udp_packets -= 1;
            self.udp_bytes -= packet.len();
            self.udp_streak = self.udp_streak.saturating_add(1);
            return Some(packet);
        }
        let packet = self.tcp.pop_front()?;
        self.tcp_bytes -= packet.len();
        self.udp_streak = 0;
        Some(packet)
    }

    fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.udp.is_empty()
    }

    fn packets(&self) -> usize {
        self.tcp.len() + self.udp_packets
    }

    fn bytes(&self) -> usize {
        self.tcp_bytes + self.udp_bytes
    }
}

impl Core {
    /// Moves what the last engine call produced to where it goes, collecting
    /// the wakers to call once the lock is released.
    fn flush(&mut self, wake: &mut Vec<Waker>) {
        self.engine.drain_output(&mut self.scratch_packets);
        for packet in self.scratch_packets.drain(..) {
            self.output.push_tcp(packet);
        }
        if !self.output.is_empty() {
            wake.extend(self.output_waker.take());
        }
        if !self.udp_in.is_empty() {
            wake.extend(self.udp_waker.take());
        }

        self.engine.drain_ready(&mut self.scratch_ready);
        for id in self.scratch_ready.drain(..) {
            if let Some(w) = self.wakers.get_mut(&id) {
                wake.extend(w.read.take());
                wake.extend(w.write.take());
            }
        }

        let mut accepted_any = false;
        while let Some(conn) = self.engine.accept() {
            if self.shut_down {
                self.engine.abort(Instant::ZERO, conn.id);
                continue;
            }
            self.wakers.insert(conn.id, Wakers::default());
            self.accepted.push_back(conn);
            accepted_any = true;
        }
        if accepted_any {
            wake.extend(self.accept_waker.take());
        }
    }

    fn input(&mut self, now: Instant, packet: &[u8]) {
        let Some(view) = ip::parse(packet) else {
            self.input_ignored += 1;
            return;
        };
        if view.is_fragment() {
            if let Some(whole) = self.reassembler.push(now, &view) {
                self.input_whole(now, &whole);
            }
            return;
        }
        match view.protocol {
            ip::PROTO_TCP => self.engine.input(now, packet),
            ip::PROTO_UDP => self.input_udp(&view),
            _ => self.input_ignored += 1,
        }
    }

    fn input_whole(&mut self, now: Instant, packet: &[u8]) {
        let Some(view) = ip::parse(packet) else {
            self.input_ignored += 1;
            return;
        };
        match view.protocol {
            ip::PROTO_TCP => self.engine.input(now, packet),
            ip::PROTO_UDP => self.input_udp(&view),
            _ => self.input_ignored += 1,
        }
    }

    fn input_udp(&mut self, view: &ip::IpView<'_>) {
        let Some((src_port, dst_port, data)) = ip::parse_udp(view) else {
            self.input_ignored += 1;
            return;
        };
        // Past the bound the oldest go: the freshest are the ones worth having.
        while self.udp_in_bytes + data.len() > self.udp_in_cap {
            let Some((oldest, _, _)) = self.udp_in.pop_front() else {
                break;
            };
            self.udp_in_bytes -= oldest.len();
            self.udp_dropped += 1;
        }
        let src = SocketAddr::new(view.src, src_port);
        let dst = SocketAddr::new(view.dst, dst_port);
        self.udp_in_bytes += data.len();
        self.udp_in.push_back((data.to_vec(), src, dst));
    }

    fn stats(&self) -> StackStats {
        StackStats {
            engine: self.engine.stats(),
            output_queued: self.output.packets(),
            output_queued_bytes: self.output.bytes(),
            output_dropped: self.output.dropped,
            udp_queued: self.udp_in.len(),
            udp_queued_bytes: self.udp_in_bytes,
            udp_dropped: self.udp_dropped,
            accept_queued: self.accepted.len(),
            fragments_held_bytes: self.reassembler.held_bytes(),
            fragments_dropped: self.reassembler.dropped,
            input_ignored: self.input_ignored,
        }
    }
}

struct Shared {
    core: Mutex<Core>,
    epoch: tokio::time::Instant,
    /// Tells the timer task that an application call may have armed an
    /// earlier timer than the one it sleeps on.
    timer: Notify,
}

impl Shared {
    fn now(&self) -> Instant {
        let elapsed = self.epoch.elapsed();
        Instant::from_micros(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX))
    }

    fn deadline(&self, at: Instant) -> tokio::time::Instant {
        self.epoch + Duration::from_micros(at.as_micros())
    }

    /// Runs `f` on the core under the lock, flushes, and wakes whoever the
    /// call made ready once the lock is gone.
    fn with_core<R>(&self, f: impl FnOnce(&mut Core, Instant) -> R) -> R {
        let mut wake = Vec::new();
        let result = {
            let mut core = self.core.lock();
            let now = self.now();
            let result = f(&mut core, now);
            core.flush(&mut wake);
            result
        };
        for waker in wake {
            waker.wake();
        }
        result
    }
}

/// The stack. Dropping it shuts it down: every connection is reset, and the
/// streams, listener and UDP socket still held report the stack gone.
pub struct NetStack {
    shared: Arc<Shared>,
}

/// Builds a stack and the two endpoints the inbound serves from it.
pub fn new(config: Config) -> (NetStack, TcpListener, UdpSocket) {
    let core = Core {
        engine: TcpEngine::new(config.limits),
        config,
        reassembler: Reassembler::new(config.reassembly),
        wakers: HashMap::new(),
        accepted: VecDeque::new(),
        accept_waker: None,
        output: Output::new(&config.limits),
        output_waker: None,
        udp_in: VecDeque::new(),
        udp_in_bytes: 0,
        udp_in_cap: udp_queue_bytes(&config.limits),
        udp_waker: None,
        udp_dropped: 0,
        next_fragment_id: rand::random(),
        input_ignored: 0,
        shut_down: false,
        scratch_packets: Vec::new(),
        scratch_ready: Vec::new(),
    };
    let shared = Arc::new(Shared {
        core: Mutex::new(core),
        epoch: tokio::time::Instant::now(),
        timer: Notify::new(),
    });
    (
        NetStack {
            shared: shared.clone(),
        },
        TcpListener {
            shared: shared.clone(),
        },
        UdpSocket { shared },
    )
}

impl NetStack {
    /// Feeds one IP packet read from the TUN device.
    pub fn input(&self, packet: &[u8]) {
        self.shared.with_core(|core, now| {
            if !core.shut_down {
                core.input(now, packet);
            }
        });
        self.shared.timer.notify_one();
    }

    /// Packets for the TUN device, in order.
    pub fn output(&self) -> PacketStream {
        PacketStream {
            shared: self.shared.clone(),
        }
    }

    /// Runs the engine's timers. Must be polled for as long as the stack is
    /// in use: retransmission, keep-alive and the end of every close happen
    /// here.
    pub fn driver(&self) -> impl Future<Output = ()> + Send + 'static {
        let shared = self.shared.clone();
        async move {
            loop {
                let deadline = {
                    let mut core = shared.core.lock();
                    if core.shut_down {
                        return;
                    }
                    let now = shared.now();
                    let engine_at = core.engine.poll_at(now);
                    let fragments_at = core.reassembler.next_expiry();
                    match (engine_at, fragments_at) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, b) => a.or(b),
                    }
                };
                match deadline {
                    Some(at) => {
                        tokio::select! {
                            _ = tokio::time::sleep_until(shared.deadline(at)) => {}
                            _ = shared.timer.notified() => {}
                        }
                    }
                    None => shared.timer.notified().await,
                }
                shared.with_core(|core, now| {
                    core.engine.poll(now);
                    core.reassembler.expire(now);
                });
            }
        }
    }

    pub fn stats(&self) -> StackStats {
        self.shared.core.lock().stats()
    }
}

impl Drop for NetStack {
    fn drop(&mut self) {
        let mut wake = Vec::new();
        {
            let mut core = self.shared.core.lock();
            core.shut_down = true;
            let now = self.shared.now();
            let ids: Vec<ConnId> = core.wakers.keys().copied().collect();
            for id in ids {
                core.engine.abort(now, id);
            }
            for conn in std::mem::take(&mut core.accepted) {
                core.engine.abort(now, conn.id);
            }
            core.flush(&mut wake);
            // The engine's memory goes now, not with the last stream still
            // held somewhere: an empty engine takes its place, and every
            // path to it checks `shut_down` first.
            core.engine = TcpEngine::new(core.config.limits);
            for w in core.wakers.values_mut() {
                wake.extend(w.read.take());
                wake.extend(w.write.take());
            }
            wake.extend(core.accept_waker.take());
            wake.extend(core.udp_waker.take());
            wake.extend(core.output_waker.take());
        }
        for waker in wake {
            waker.wake();
        }
        self.shared.timer.notify_one();
    }
}

/// Packets the stack wants written to the TUN device. Ends when the stack
/// has shut down and everything queued has been taken.
pub struct PacketStream {
    shared: Arc<Shared>,
}

impl Stream for PacketStream {
    type Item = Vec<u8>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        let mut core = self.shared.core.lock();
        if let Some(packet) = core.output.pop() {
            return Poll::Ready(Some(packet));
        }
        if core.shut_down {
            return Poll::Ready(None);
        }
        core.output_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// Connections the stack accepted, as `(stream, client, target)` — the
/// application's address and the one it was connecting to.
pub struct TcpListener {
    shared: Arc<Shared>,
}

impl Stream for TcpListener {
    type Item = (TcpStream, SocketAddr, SocketAddr);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut core = self.shared.core.lock();
        if let Some(conn) = core.accepted.pop_front() {
            let stream = TcpStream {
                shared: self.shared.clone(),
                id: conn.id,
                client: conn.client,
                target: conn.target,
            };
            return Poll::Ready(Some((stream, conn.client, conn.target)));
        }
        if core.shut_down {
            return Poll::Ready(None);
        }
        core.accept_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// One accepted connection. Dropping it closes the connection; data the
/// application never read resets it, as on a kernel socket.
pub struct TcpStream {
    shared: Arc<Shared>,
    id: ConnId,
    client: SocketAddr,
    target: SocketAddr,
}

impl TcpStream {
    pub fn id(&self) -> ConnId {
        self.id
    }

    /// The application's address.
    pub fn client_addr(&self) -> SocketAddr {
        self.client
    }

    /// The address the application connected to.
    pub fn target_addr(&self) -> SocketAddr {
        self.target
    }

    /// Resets the connection.
    pub fn abort(&self) {
        let id = self.id;
        self.shared
            .with_core(|core, now| core.engine.abort(now, id));
    }
}

fn stack_gone() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "network stack shut down")
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let id = self.id;
        let result = self.shared.with_core(|core, now| {
            if core.shut_down {
                return Poll::Ready(Err(stack_gone()));
            }
            match core.engine.recv(now, id, buf.initialize_unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    Poll::Ready(Ok(()))
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Some(w) = core.wakers.get_mut(&id) {
                        w.read = Some(cx.waker().clone());
                    }
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        });
        // Reading opens the window: the update the engine queued may come
        // with a timer.
        self.shared.timer.notify_one();
        result
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let id = self.id;
        let result = self.shared.with_core(|core, now| {
            if core.shut_down {
                return Poll::Ready(Err(stack_gone()));
            }
            match core.engine.send(now, id, data) {
                Ok(n) => Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Some(w) = core.wakers.get_mut(&id) {
                        w.write = Some(cx.waker().clone());
                    }
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        });
        self.shared.timer.notify_one();
        result
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let id = self.id;
        self.shared.with_core(|core, now| {
            if !core.shut_down {
                core.engine.shutdown_write(now, id);
            }
        });
        self.shared.timer.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let id = self.id;
        self.shared.with_core(|core, now| {
            core.wakers.remove(&id);
            if !core.shut_down {
                core.engine.close(now, id);
            }
        });
        self.shared.timer.notify_one();
    }
}

/// UDP to and from every address behind the TUN device.
pub struct UdpSocket {
    shared: Arc<Shared>,
}

impl UdpSocket {
    pub fn split(self) -> (UdpSendHalf, UdpRecvHalf) {
        (
            UdpSendHalf {
                shared: self.shared.clone(),
            },
            UdpRecvHalf {
                shared: self.shared,
            },
        )
    }
}

pub struct UdpSendHalf {
    shared: Arc<Shared>,
}

impl UdpSendHalf {
    /// Sends `data` to the application at `dst`, as if from `src`.
    pub fn send_to(&self, data: &[u8], src: &SocketAddr, dst: &SocketAddr) -> io::Result<()> {
        let mut wake = Vec::new();
        let result = {
            let mut core = self.shared.core.lock();
            if core.shut_down {
                return Err(stack_gone());
            }
            let mtu = core.config.limits.mtu;
            let mut packets = std::mem::take(&mut core.scratch_packets);
            let mut next_id = core.next_fragment_id;
            let built = ip::build_udp(*src, *dst, data, mtu, &mut next_id, &mut packets);
            core.next_fragment_id = next_id;
            let result = match built {
                Ok(()) => {
                    core.output.push_udp(std::mem::take(&mut packets));
                    Ok(())
                }
                Err(e) => {
                    packets.clear();
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{e:?}"),
                    ))
                }
            };
            core.scratch_packets = packets;
            if !core.output.is_empty() {
                wake.extend(core.output_waker.take());
            }
            result
        };
        for waker in wake {
            waker.wake();
        }
        result
    }
}

/// UDP datagrams from the applications, as `(data, src, dst)`.
pub struct UdpRecvHalf {
    shared: Arc<Shared>,
}

impl Stream for UdpRecvHalf {
    type Item = Datagram;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Datagram>> {
        let mut core = self.shared.core.lock();
        if let Some(datagram) = core.udp_in.pop_front() {
            core.udp_in_bytes -= datagram.0.len();
            return Poll::Ready(Some(datagram));
        }
        if core.shut_down {
            return Poll::Ready(None);
        }
        core.udp_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(budget: usize) -> Limits {
        Limits {
            memory_budget: Some(budget),
            ..Limits::default()
        }
    }

    fn tagged(tag: u8, len: usize) -> Vec<u8> {
        vec![tag; len]
    }

    /// UDP goes first, but TCP is served after every `UDP_BURST` datagram
    /// packets while it waits, and alone once UDP is out.
    #[test]
    fn udp_goes_first_without_starving_tcp() {
        let mut out = Output::new(&limits(16 << 20));
        for _ in 0..3 {
            out.push_tcp(tagged(b't', 100));
        }
        for _ in 0..10 {
            out.push_udp(vec![tagged(b'u', 100)]);
        }
        let order: String = std::iter::from_fn(|| out.pop())
            .map(|p| char::from(p[0]))
            .collect();
        assert_eq!(order, "uuuutuuuutuut");
        assert!(out.is_empty());

        // UDP alone for as long as it lasts, then TCP straight away.
        for _ in 0..1000 {
            out.push_udp(vec![tagged(b'u', 100)]);
        }
        for _ in 0..1000 {
            assert_eq!(out.pop().unwrap()[0], b'u');
        }
        out.push_tcp(tagged(b't', 100));
        out.push_udp(vec![tagged(b'u', 100)]);
        assert_eq!(out.pop().unwrap()[0], b't');
        assert_eq!(out.pop().unwrap()[0], b'u');
        assert_eq!((out.packets(), out.bytes()), (0, 0));
    }

    /// Past its bound the UDP queue drops whole datagrams, oldest first, and
    /// a datagram that could never fit is refused outright.
    #[test]
    fn udp_drops_the_oldest_datagrams_whole() {
        let mut out = Output::new(&limits(2 << 20));
        let cap = udp_queue_bytes(&limits(2 << 20));
        assert_eq!(cap, 128 << 10);
        let fragments = |tag: u8| vec![tagged(tag, 1500); 30];
        out.push_udp(fragments(1));
        out.push_udp(fragments(2));
        assert_eq!((out.packets(), out.dropped), (60, 0));
        out.push_udp(fragments(3));
        assert_eq!(
            (out.packets(), out.dropped),
            (60, 30),
            "the first went, all of it"
        );
        let first = out.pop().unwrap();
        assert_eq!(first[0], 2);
        out.push_udp(vec![tagged(9, 100); (cap / 100) + 1]);
        assert_eq!(out.dropped, 30 + (cap as u64 / 100) + 1);
    }

    /// TCP queues past any count of packets; only the backstop stops it.
    #[test]
    fn tcp_is_held_up_to_the_backstop() {
        let mut out = Output::new(&limits(4 << 20));
        let backstop = tcp_backstop_bytes(&limits(4 << 20));
        let segments = backstop / 1500;
        for _ in 0..segments {
            out.push_tcp(tagged(0, 1500));
        }
        assert_eq!((out.packets(), out.dropped), (segments, 0));
        out.push_tcp(tagged(0, 1500));
        assert_eq!(out.dropped, 1);
    }
}
