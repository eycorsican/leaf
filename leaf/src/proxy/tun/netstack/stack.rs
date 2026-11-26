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

/// Everything the stack is sized by.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub limits: Limits,
    pub reassembly: ReassemblyLimits,
    /// Packets waiting for the TUN device. Beyond it packets are dropped —
    /// TCP retransmits them — rather than queued without bound.
    pub max_output_packets: usize,
    /// UDP datagrams received and not yet taken by the application.
    pub max_udp_queue: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            limits: Limits::default(),
            reassembly: ReassemblyLimits::default(),
            max_output_packets: 512,
            max_udp_queue: 256,
        }
    }
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
    output: VecDeque<Vec<u8>>,
    output_bytes: usize,
    output_waker: Option<Waker>,
    output_dropped: u64,
    udp_in: VecDeque<Datagram>,
    udp_in_bytes: usize,
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

impl Core {
    /// Moves what the last engine call produced to where it goes, collecting
    /// the wakers to call once the lock is released.
    fn flush(&mut self, wake: &mut Vec<Waker>) {
        self.engine.drain_output(&mut self.scratch_packets);
        for packet in self.scratch_packets.drain(..) {
            if self.output.len() >= self.config.max_output_packets {
                self.output_dropped += 1;
                continue;
            }
            self.output_bytes += packet.len();
            self.output.push_back(packet);
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
        if self.udp_in.len() >= self.config.max_udp_queue {
            self.udp_dropped += 1;
            return;
        }
        let src = SocketAddr::new(view.src, src_port);
        let dst = SocketAddr::new(view.dst, dst_port);
        self.udp_in_bytes += data.len();
        self.udp_in.push_back((data.to_vec(), src, dst));
    }

    fn stats(&self) -> StackStats {
        StackStats {
            engine: self.engine.stats(),
            output_queued: self.output.len(),
            output_queued_bytes: self.output_bytes,
            output_dropped: self.output_dropped,
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
        output: VecDeque::new(),
        output_bytes: 0,
        output_waker: None,
        output_dropped: 0,
        udp_in: VecDeque::new(),
        udp_in_bytes: 0,
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
        if let Some(packet) = core.output.pop_front() {
            core.output_bytes -= packet.len();
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
                    // All fragments or none: a partial datagram is useless.
                    if core.output.len() + packets.len() > core.config.max_output_packets {
                        core.output_dropped += packets.len() as u64;
                        packets.clear();
                    }
                    for packet in packets.drain(..) {
                        core.output_bytes += packet.len();
                        core.output.push_back(packet);
                    }
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
