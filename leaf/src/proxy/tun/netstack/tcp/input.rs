//! A packet from the TUN device: the drops IP makes before TCP sees it,
//! finding its connection (or opening one for a SYN), and the connection's
//! state machine.

use std::net::{IpAddr, SocketAddr};

use super::app::Ending;
use super::config::{MSS, WINDOW};
use super::conn::{Connection, Handler, KeepAlive, State};
use super::receive::Chunk;
use super::segment::TcpFlags;
use super::seq::SeqNum;
use super::stack::{Env, Stack};
use crate::proxy::tun::netstack::ip;
use crate::proxy::tun::netstack::wire::{self, TCP_HEADER_LEN};

/// One received segment's header and payload.
pub struct Incoming<'a> {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub seq: SeqNum,
    pub ack: SeqNum,
    pub flags: TcpFlags,
    pub window: u16,
    /// Sequence space taken: payload, plus one for a SYN or FIN.
    pub len: u16,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

/// What processing a segment found, for what follows it.
#[derive(Default)]
pub struct Received<'a> {
    /// An acceptable RST.
    pub reset: bool,
    /// Our FIN was acknowledged in LAST-ACK: the connection is over.
    pub closed: bool,
    pub got_fin: bool,
    /// Bytes newly acknowledged.
    pub acked: u16,
    /// Data now in order, for the application.
    pub data: Vec<Chunk<'a>>,
}

/// The segment in `packet`, or `None` for what IP or TCP would drop.
fn parse(packet: &[u8]) -> Option<Incoming<'_>> {
    let view = ip::parse(packet)?;
    if view.is_fragment() || view.protocol != wire::PROTO_TCP {
        return None;
    }
    if view.src.is_ipv4() && !wire::ipv4_header_checksum_ok(packet) {
        return None;
    }
    let broadcast =
        |a: IpAddr| matches!(a, IpAddr::V4(v4) if v4.is_broadcast() || v4.is_unspecified());
    if broadcast(view.src) || view.src.is_multicast() {
        return None;
    }
    let segment = view.payload;
    if segment.len() < TCP_HEADER_LEN || broadcast(view.dst) || view.dst.is_multicast() {
        return None;
    }
    if !wire::transport_checksum_ok(view.src, view.dst, wire::PROTO_TCP, segment) {
        return None;
    }
    let header = wire::read_tcp(segment)?;
    let flags = TcpFlags::from_header(segment[13]);
    let payload = &segment[header.header_len..];
    let mut len = payload.len() as u16;
    if flags.has_any(TcpFlags::SYN | TcpFlags::FIN) {
        len = len.checked_add(1)?;
    }
    Some(Incoming {
        local: SocketAddr::new(view.dst, header.dst_port),
        remote: SocketAddr::new(view.src, header.src_port),
        seq: SeqNum::new(header.seq),
        ack: SeqNum::new(header.ack),
        flags,
        window: header.window,
        len,
        options: &segment[TCP_HEADER_LEN..header.header_len],
        payload,
    })
}

/// The MSS option among `options`, as lwIP reads it: up to the end-of-list
/// or a malformed option; zero or more than our MSS means our MSS.
fn mss_option(options: &[u8]) -> Option<u16> {
    let mut mss = None;
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            0 => break,
            1 => i += 1,
            2 => {
                if options.get(i + 1) != Some(&4) || i + 4 > options.len() {
                    break;
                }
                let value = u16::from_be_bytes([options[i + 2], options[i + 3]]);
                mss = Some(if value > MSS || value == 0 {
                    MSS
                } else {
                    value
                });
                i += 4;
            }
            _ => match options.get(i + 1) {
                Some(&len) if len >= 2 => i += usize::from(len),
                _ => break,
            },
        }
    }
    mss
}

impl Stack {
    /// Finds the segment's connection and hands it the segment.
    pub fn on_packet(&mut self, packet: &[u8]) {
        let Some(seg) = parse(packet) else {
            return;
        };
        let Some(key) = self.find(seg.local, seg.remote) else {
            self.on_unknown(&seg);
            return;
        };
        self.touch(key);
        self.with_conn(key, |conn, env| {
            if conn.state == State::TimeWait {
                conn.on_time_wait_segment(&seg, env);
            } else {
                conn.on_segment(&seg, env);
            }
        });
    }

    /// A segment for no connection: a SYN opens one, anything else
    /// acknowledging something is answered with a reset.
    fn on_unknown(&mut self, seg: &Incoming<'_>) {
        if seg.flags.has(TcpFlags::RST) {
            return;
        }
        if seg.flags.has(TcpFlags::ACK) {
            self.env
                .net
                .send_reset(seg.local, seg.remote, seg.ack, seg.seq + u32::from(seg.len));
            return;
        }
        if !seg.flags.has(TcpFlags::SYN) {
            return;
        }
        // No room for it: the SYN goes unanswered.
        let Some(key) = self.open() else {
            return;
        };
        let env = &mut self.env;
        let iss = SeqNum::new(env.isn.isn(env.now, seg.remote, seg.local));
        let mut conn = Connection::new(key, seg.local, seg.remote, env.ticks, seg.seq, iss);
        conn.on_syn(seg, env);
        self.adopt(conn);
    }
}

impl Connection {
    /// Answers the SYN that opened the connection.
    fn on_syn(&mut self, seg: &Incoming<'_>, env: &mut Env) {
        if let Some(mss) = mss_option(seg.options) {
            self.mss = mss;
        }
        self.snd.window = seg.window;
        self.snd.max_window = seg.window;
        self.mss = env.net.effective_mss(self.mss, self.remote);
        if self
            .queue_control(TcpFlags::SYN | TcpFlags::ACK, env)
            .is_err()
        {
            self.abandon(false, env);
            return;
        }
        self.output(env);
    }

    /// TIME-WAIT answers anything with sequence space by acknowledging it
    /// again; a FIN restarts the wait, a SYN in the window is reset.
    fn on_time_wait_segment(&mut self, seg: &Incoming<'_>, env: &mut Env) {
        if seg.flags.has(TcpFlags::RST) {
            return;
        }
        if seg.flags.has(TcpFlags::SYN) {
            let window_end = self.rcv.next + u32::from(self.rcv.window);
            if seg.seq.within(self.rcv.next, window_end) {
                env.net.send_reset(
                    self.local,
                    self.remote,
                    seg.ack,
                    seg.seq + u32::from(seg.len),
                );
                return;
            }
        } else if seg.flags.has(TcpFlags::FIN) {
            self.last_activity = env.ticks;
        }
        if seg.len > 0 {
            self.ack.now = true;
            self.output(env);
        }
    }

    /// A segment for a connection past its SYN: the state machine, then the
    /// application hears what it brought, then whatever can go out goes.
    pub fn on_segment<'a>(&mut self, seg: &Incoming<'a>, env: &mut Env) {
        let mut rx = Received::default();
        env.input = Some(self.key);
        env.closed_during_input = false;
        match self.process(seg, &mut rx, env) {
            Some(()) if rx.reset => {
                env.apps.ended(self.handler, Ending::Reset);
                self.retire(env);
            }
            Some(()) => self.deliver(rx, env),
            None => {}
        }
        env.input = None;
    }

    /// The state machine for one segment; `None` if the connection was
    /// aborted on the way.
    fn process<'a>(
        &mut self,
        seg: &Incoming<'a>,
        rx: &mut Received<'a>,
        env: &mut Env,
    ) -> Option<()> {
        if seg.flags.has(TcpFlags::RST) {
            if seg.seq == self.rcv.next {
                rx.reset = true;
                self.ack.delayed = false;
            } else if seg
                .seq
                .within(self.rcv.next, self.rcv.next + u32::from(self.rcv.window))
            {
                // RFC 5961: a RST in the window but not exactly next gets a
                // challenge ACK.
                self.ack.now = true;
            }
            return Some(());
        }
        if seg.flags.has(TcpFlags::SYN) && self.state != State::SynReceived {
            self.ack.now = true;
            return Some(());
        }
        if !self.rx_closed {
            self.last_activity = env.ticks;
        }
        if let Some(keepalive) = self.keepalive.as_mut() {
            keepalive.sent = 0;
        }
        if let Some(persist) = self.persist.as_mut() {
            persist.probes = 0;
        }
        match self.state {
            State::SynReceived => self.on_handshake_segment(seg, rx, env)?,
            State::Established | State::CloseWait => {
                self.on_ack(seg, rx, env);
                self.on_data(seg, rx, env);
                if rx.got_fin {
                    self.ack.now = true;
                    self.state = State::CloseWait;
                }
            }
            State::FinWait1 => {
                self.on_ack(seg, rx, env);
                self.on_data(seg, rx, env);
                let all_acked = self.acks_everything(seg);
                if rx.got_fin {
                    self.ack.now = true;
                    if all_acked {
                        self.enter_time_wait();
                    } else {
                        self.state = State::Closing;
                    }
                } else if all_acked {
                    self.state = State::FinWait2;
                }
            }
            State::FinWait2 => {
                self.on_ack(seg, rx, env);
                self.on_data(seg, rx, env);
                if rx.got_fin {
                    self.ack.now = true;
                    self.enter_time_wait();
                }
            }
            State::Closing => {
                self.on_ack(seg, rx, env);
                self.on_data(seg, rx, env);
                if self.acks_everything(seg) {
                    self.enter_time_wait();
                }
            }
            State::LastAck => {
                self.on_ack(seg, rx, env);
                self.on_data(seg, rx, env);
                if self.acks_everything(seg) {
                    rx.closed = true;
                }
            }
            State::TimeWait | State::Closed => {}
        }
        Some(())
    }

    /// The segment acknowledges all we have sent, FIN included, with
    /// nothing left unsent.
    fn acks_everything(&self, seg: &Incoming<'_>) -> bool {
        seg.flags.has(TcpFlags::ACK) && seg.ack == self.snd.next && self.snd.unsent.is_empty()
    }

    /// SYN-RECEIVED: a repeated SYN gets the SYN-ACK again; the ACK of ours
    /// completes the handshake and hands the connection to the
    /// application — or resets it if the application holds too many.
    fn on_handshake_segment<'a>(
        &mut self,
        seg: &Incoming<'a>,
        rx: &mut Received<'a>,
        env: &mut Env,
    ) -> Option<()> {
        if seg.flags.has(TcpFlags::SYN) {
            if seg.seq == self.rcv.next - 1 {
                self.retransmit_oldest();
            }
            return Some(());
        }
        if !seg.flags.has(TcpFlags::ACK) {
            return Some(());
        }
        if !seg.ack.within(self.snd.acked + 1, self.snd.next) {
            env.net.send_reset(
                self.local,
                self.remote,
                seg.ack,
                seg.seq + u32::from(seg.len),
            );
            return Some(());
        }
        self.state = State::Established;
        let Some(id) = env.apps.accept(self.key, self.remote, self.local) else {
            self.abort(env);
            return None;
        };
        self.handler = Handler::App(id);
        self.nodelay = true;
        if env.keepalive_idle_ms != 0 {
            self.keepalive = Some(KeepAlive::default());
        }
        self.on_ack(seg, rx, env);
        self.on_data(seg, rx, env);
        // The SYN-ACK counted as one acknowledged byte.
        rx.acked = rx.acked.saturating_sub(1);
        self.rtx.cwnd = initial_cwnd(self.mss);
        if rx.got_fin {
            self.ack.now = true;
            self.state = State::CloseWait;
        }
        Some(())
    }

    fn enter_time_wait(&mut self) {
        self.purge();
        self.state = State::TimeWait;
    }

    /// After the state machine: the application hears what was
    /// acknowledged, the data, and the FIN, in that order; then the
    /// connection ends if it is over, or sends what it can.
    fn deliver<'a>(&mut self, mut rx: Received<'a>, env: &mut Env) {
        if rx.acked > 0 {
            env.apps.wake(self.handler);
            rx.acked = 0;
        }
        if self.close_if_over(&rx, env) {
            return;
        }
        if !rx.data.is_empty() && !self.give_data(&rx.data, env) {
            return;
        }
        if rx.got_fin {
            if self.rcv.window != WINDOW {
                self.rcv.window += 1;
            }
            if !self.give_fin(env) {
                return;
            }
        }
        env.input = None;
        if self.close_if_over(&rx, env) {
            return;
        }
        self.output(env);
    }

    /// Ends the connection if it is over: closed in LAST-ACK, or reset by
    /// a close while the segment was processed.
    fn close_if_over(&mut self, rx: &Received<'_>, env: &mut Env) -> bool {
        if !rx.closed && !env.closed_during_input {
            return false;
        }
        if !self.rx_closed {
            env.apps.ended(self.handler, Ending::Closed);
        }
        self.retire(env);
        true
    }

    /// In-order data to whoever handles the connection; false if that
    /// aborted it.
    fn give_data(&mut self, data: &[Chunk<'_>], env: &mut Env) -> bool {
        if self.rx_closed {
            self.abort(env);
            return false;
        }
        match self.handler {
            Handler::Unaccepted => {
                let len: usize = data.iter().map(|c| c.bytes().len()).sum();
                self.app_read(len as u16, env);
                true
            }
            Handler::Released => {
                self.abort(env);
                false
            }
            Handler::App(id) => {
                for chunk in data {
                    env.apps.data(id, chunk.bytes());
                }
                true
            }
        }
    }

    /// The peer's FIN to whoever handles the connection; false if that
    /// aborted it.
    fn give_fin(&mut self, env: &mut Env) -> bool {
        match self.handler {
            Handler::Unaccepted => {
                self.close(env);
                true
            }
            Handler::Released => true,
            Handler::App(id) => {
                env.apps.fin(id);
                if matches!(self.state, State::Closing | State::TimeWait) {
                    env.apps.hand_over(id);
                    self.handler = Handler::Released;
                }
                true
            }
        }
    }
}

/// The congestion window a connection starts with (RFC 3390).
fn initial_cwnd(mss: u16) -> u16 {
    let mss = u32::from(mss);
    (4 * mss).min((2 * mss).max(4380)) as u16
}
