//! The stack around the connections: where they are kept and found, the
//! order lwIP walks them in, the timer that drives them, the pools that
//! bound them, and what every operation on one of them shares (`Env`).
//!
//! A connection being worked on is taken out of the table and handed to its
//! own methods with the `Env`; `settle` puts it back and brings the lists,
//! the demultiplexer and the pool counts up to date with what the operation
//! did. One operation only ever changes the one connection, so deferring
//! that bookkeeping to the end of it leaves every list in the order lwIP's
//! immediate updates would.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use super::app::Apps;
use super::config::{
    CONNECTION_POOL, PBUF_POOL_BUFSIZE, PBUF_POOL_SIZE, TIMER_INTERVAL_MS, TWO_MSL_TICKS,
};
use super::conn::{Connection, State};
use super::segment::TcpFlags;
use super::seq::{Millis, SeqNum, Ticks};
use crate::proxy::tun::netstack::engine::Instant;
use crate::proxy::tun::netstack::isn::IsnGenerator;
use crate::proxy::tun::netstack::wire::{
    self, Ipv4Fields, IPV4_HEADER_LEN, IPV6_HEADER_LEN, PROTO_TCP, TCP_HEADER_LEN,
};

/// Names a connection for as long as it lives; a freed slot's next tenant
/// gets a new generation, so a stale key misses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnKey {
    index: u32,
    generation: u32,
}

struct Slot {
    generation: u32,
    conn: Option<Box<Connection>>,
}

/// The connections, by key.
#[derive(Default)]
struct Slab {
    slots: Vec<Slot>,
    vacant: Vec<u32>,
    /// Keys handed out and not freed: connections, in the table or being
    /// worked on.
    live: usize,
}

impl Slab {
    fn reserve(&mut self) -> ConnKey {
        self.live += 1;
        match self.vacant.pop() {
            Some(index) => ConnKey {
                index,
                generation: self.slots[index as usize].generation,
            },
            None => {
                self.slots.push(Slot {
                    generation: 0,
                    conn: None,
                });
                ConnKey {
                    index: (self.slots.len() - 1) as u32,
                    generation: 0,
                }
            }
        }
    }

    fn slot(&mut self, key: ConnKey) -> Option<&mut Slot> {
        self.slots
            .get_mut(key.index as usize)
            .filter(|s| s.generation == key.generation)
    }

    fn take(&mut self, key: ConnKey) -> Option<Box<Connection>> {
        self.slot(key)?.conn.take()
    }

    fn get_mut(&mut self, key: ConnKey) -> Option<&mut Connection> {
        self.slot(key)?.conn.as_deref_mut()
    }

    fn get(&self, key: ConnKey) -> Option<&Connection> {
        self.slots
            .get(key.index as usize)
            .filter(|s| s.generation == key.generation)?
            .conn
            .as_deref()
    }

    fn put(&mut self, conn: Box<Connection>) {
        if let Some(slot) = self.slot(conn.key) {
            slot.conn = Some(conn);
        }
    }

    fn free(&mut self, key: ConnKey) {
        if let Some(slot) = self.slot(key) {
            slot.generation = slot.generation.wrapping_add(1);
            slot.conn = None;
            self.vacant.push(key.index);
            self.live -= 1;
        }
    }

    fn key_at(&self, index: u32) -> Option<ConnKey> {
        let slot = self.slots.get(index as usize)?;
        Some(ConnKey {
            index,
            generation: slot.generation,
        })
    }

    fn values(&self) -> impl Iterator<Item = &Connection> {
        self.slots.iter().filter_map(|s| s.conn.as_deref())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListKind {
    Active,
    TimeWait,
}

#[derive(Clone, Copy, Default)]
struct Link {
    list: Option<ListKind>,
    prev: Option<u32>,
    next: Option<u32>,
}

/// lwIP's two connection lists, which it pushes onto at the head and walks
/// from it; the order decides which connection's segments a timer tick
/// sends first. Linked through slot indices, so every operation is O(1).
#[derive(Default)]
struct Lists {
    active: Option<u32>,
    time_wait: Option<u32>,
    active_len: usize,
    time_wait_len: usize,
    links: Vec<Link>,
}

impl Lists {
    fn link(&mut self, index: u32) -> &mut Link {
        let i = index as usize;
        if self.links.len() <= i {
            self.links.resize(i + 1, Link::default());
        }
        &mut self.links[i]
    }

    fn list_of(&self, index: u32) -> Option<ListKind> {
        self.links.get(index as usize).and_then(|l| l.list)
    }

    fn head(&self, kind: ListKind) -> Option<u32> {
        match kind {
            ListKind::Active => self.active,
            ListKind::TimeWait => self.time_wait,
        }
    }

    fn next(&self, index: u32) -> Option<u32> {
        self.links.get(index as usize).and_then(|l| l.next)
    }

    fn push_front(&mut self, kind: ListKind, index: u32) {
        self.remove(index);
        let old = self.head(kind);
        if let Some(old) = old {
            self.link(old).prev = Some(index);
        }
        *self.link(index) = Link {
            list: Some(kind),
            prev: None,
            next: old,
        };
        match kind {
            ListKind::Active => {
                self.active = Some(index);
                self.active_len += 1;
            }
            ListKind::TimeWait => {
                self.time_wait = Some(index);
                self.time_wait_len += 1;
            }
        }
    }

    fn remove(&mut self, index: u32) {
        let Some(link) = self.links.get(index as usize).copied() else {
            return;
        };
        let Some(kind) = link.list else {
            return;
        };
        match link.prev {
            Some(p) => self.link(p).next = link.next,
            None => match kind {
                ListKind::Active => self.active = link.next,
                ListKind::TimeWait => self.time_wait = link.next,
            },
        }
        if let Some(n) = link.next {
            self.link(n).prev = link.prev;
        }
        *self.link(index) = Link::default();
        match kind {
            ListKind::Active => self.active_len -= 1,
            ListKind::TimeWait => self.time_wait_len -= 1,
        }
    }

    fn is_empty(&self) -> bool {
        self.active_len == 0 && self.time_wait_len == 0
    }

    /// The indices of a list, head first.
    fn indices(&self, kind: ListKind) -> Vec<u32> {
        let mut out = Vec::new();
        let mut cursor = self.head(kind);
        while let Some(index) = cursor {
            out.push(index);
            cursor = self.next(index);
        }
        out
    }
}

/// Packets on their way to the TUN device.
pub struct Net {
    pub packets: Vec<Vec<u8>>,
    /// The IPv4 identification of the next packet.
    ip_id: u16,
    pub mtu: u16,
}

/// A TCP header's fields, for `Net::send`.
pub struct Header {
    pub seq: SeqNum,
    pub ack: SeqNum,
    pub flags: TcpFlags,
    pub window: u16,
    pub mss_option: Option<u16>,
}

impl Net {
    /// The MSS for a peer at `remote`: `wanted`, capped by the link.
    pub fn effective_mss(&self, wanted: u16, remote: SocketAddr) -> u16 {
        if self.mtu == 0 {
            return wanted;
        }
        let headers = if remote.is_ipv6() { 60 } else { 40 };
        wanted.min(self.mtu.saturating_sub(headers))
    }

    /// One segment from `local` to `remote`, wrapped in IP.
    pub fn send(&mut self, local: SocketAddr, remote: SocketAddr, header: &Header, payload: &[u8]) {
        let ip_header = match (local.ip(), remote.ip()) {
            (IpAddr::V4(_), IpAddr::V4(_)) => IPV4_HEADER_LEN,
            (IpAddr::V6(_), IpAddr::V6(_)) => IPV6_HEADER_LEN,
            _ => return,
        };
        let options_len = if header.mss_option.is_some() { 4 } else { 0 };
        let header_len = TCP_HEADER_LEN + options_len;
        let mut packet = vec![0u8; ip_header + header_len + payload.len()];
        let segment = &mut packet[ip_header..];
        segment[0..2].copy_from_slice(&local.port().to_be_bytes());
        segment[2..4].copy_from_slice(&remote.port().to_be_bytes());
        segment[4..8].copy_from_slice(&header.seq.raw().to_be_bytes());
        segment[8..12].copy_from_slice(&header.ack.raw().to_be_bytes());
        segment[12] = ((header_len / 4) as u8) << 4;
        segment[13] = header.flags.bits();
        segment[14..16].copy_from_slice(&header.window.to_be_bytes());
        if let Some(mss) = header.mss_option {
            segment[20..24].copy_from_slice(&(0x0204_0000u32 | u32::from(mss)).to_be_bytes());
        }
        segment[header_len..].copy_from_slice(payload);
        wire::fill_transport_checksum(local.ip(), remote.ip(), PROTO_TCP, segment, 16);
        let segment_len = segment.len();
        match (local.ip(), remote.ip()) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                wire::write_ipv4(
                    &mut packet,
                    &Ipv4Fields {
                        src,
                        dst,
                        protocol: PROTO_TCP,
                        total_len: (IPV4_HEADER_LEN + segment_len) as u16,
                        ident: self.ip_id,
                        dont_fragment: false,
                        more_fragments: false,
                        fragment_offset: 0,
                        ttl: super::config::TTL,
                    },
                );
                self.ip_id = self.ip_id.wrapping_add(1);
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                wire::write_ipv6(
                    &mut packet,
                    src,
                    dst,
                    PROTO_TCP,
                    segment_len as u16,
                    super::config::TTL,
                );
            }
            _ => return,
        }
        self.packets.push(packet);
    }

    /// A reset, from no connection in particular.
    pub fn send_reset(&mut self, local: SocketAddr, remote: SocketAddr, seq: SeqNum, ack: SeqNum) {
        let window = super::config::WINDOW;
        let header = Header {
            seq,
            ack,
            flags: TcpFlags::RST | TcpFlags::ACK,
            window,
            mss_option: None,
        };
        self.send(local, remote, &header, &[]);
    }
}

/// The memory budget, as it stands for the connection being worked on.
pub struct Budget {
    cap: Option<usize>,
    /// Bytes queued by every connection but the one being worked on.
    others: usize,
}

impl Budget {
    /// Whether `more` bytes may be queued. What the connection being
    /// worked on already holds is not counted.
    pub fn allows(&self, more: usize) -> bool {
        self.cap.is_none_or(|cap| self.others + more <= cap)
    }
}

/// What every operation on a connection shares.
pub struct Env {
    pub now: Instant,
    pub ticks: Ticks,
    pub net: Net,
    pub apps: Apps,
    pub isn: IsnGenerator,
    /// Keep-alive idle time set on accept; 0 for none.
    pub keepalive_idle_ms: u32,
    pub budget: Budget,
    /// The connection a segment is being processed for: its output waits
    /// until the processing is done.
    pub input: Option<ConnKey>,
    /// A close during that processing reset the connection; it is freed
    /// once the processing is done.
    pub closed_during_input: bool,
}

impl Env {
    pub fn holds_output(&self, key: ConnKey) -> bool {
        self.input == Some(key)
    }
}

pub struct Stack {
    conns: Slab,
    lists: Lists,
    /// (local, remote) → the connection in either list.
    demux: HashMap<(SocketAddr, SocketAddr), ConnKey>,
    /// When the TCP timer next runs; `None` while there is nothing to time.
    timer_due: Option<Millis>,
    now_ms: Millis,
    /// The TCP timer's next run is a slow tick as well as a fast one.
    slow_tick_next: bool,
    /// Pool pbufs held by out-of-order segments.
    pool_in_use: usize,
    /// The pool ran dry: the next packet or timer run frees out-of-order
    /// data to make room.
    pool_exhausted: bool,
    /// Payload bytes queued across every connection in the table.
    queued_total: usize,
    pub env: Env,
}

/// What `settle` compares a connection against.
struct Before {
    out_of_order: usize,
    queued: usize,
}

impl Stack {
    pub fn new(
        isn: IsnGenerator,
        mtu: u16,
        keepalive_idle_ms: u32,
        max_connections: usize,
        budget: Option<usize>,
    ) -> Stack {
        Stack {
            conns: Slab::default(),
            lists: Lists::default(),
            demux: HashMap::new(),
            timer_due: None,
            now_ms: Millis::default(),
            slow_tick_next: true,
            pool_in_use: 0,
            pool_exhausted: false,
            queued_total: 0,
            env: Env {
                now: Instant::ZERO,
                ticks: Ticks::default().next(),
                net: Net {
                    packets: Vec::new(),
                    ip_id: 0,
                    mtu,
                },
                apps: Apps::new(max_connections),
                isn,
                keepalive_idle_ms,
                budget: Budget {
                    cap: budget,
                    others: 0,
                },
                input: None,
                closed_during_input: false,
            },
        }
    }

    pub fn set_now(&mut self, now: Instant) {
        self.env.now = now;
        self.now_ms = Millis::from_instant(now);
    }

    // ---- Connections ------------------------------------------------------

    /// Runs `f` on a connection taken out of the table, then settles it.
    pub fn with_conn<R>(
        &mut self,
        key: ConnKey,
        f: impl FnOnce(&mut Connection, &mut Env) -> R,
    ) -> Option<R> {
        let mut conn = self.conns.take(key)?;
        let before = self.lend(&conn);
        let result = f(&mut conn, &mut self.env);
        self.settle(conn, before);
        Some(result)
    }

    fn lend(&mut self, conn: &Connection) -> Before {
        let before = Before {
            out_of_order: conn.rcv.out_of_order.len(),
            queued: conn.buffered(),
        };
        self.env.budget.others = self.queued_total - before.queued;
        before
    }

    /// Puts a connection back after an operation, or lets it go, and
    /// brings the lists and counts in line with what it now is.
    fn settle(&mut self, conn: Box<Connection>, before: Before) {
        self.pool_in_use -= before.out_of_order;
        self.queued_total -= before.queued;
        let key = conn.key;
        let pair = (conn.local, conn.remote);
        if conn.forget {
            self.lists.remove(key.index);
            if self.demux.get(&pair) == Some(&key) {
                self.demux.remove(&pair);
            }
            self.conns.free(key);
            return;
        }
        self.pool_in_use += conn.rcv.out_of_order.len();
        self.queued_total += conn.buffered();
        match (self.lists.list_of(key.index), conn.state) {
            (Some(ListKind::Active), State::TimeWait) => {
                self.lists.push_front(ListKind::TimeWait, key.index);
                self.timer_needed();
            }
            (None, _) => {
                self.lists.push_front(ListKind::Active, key.index);
                self.demux.insert(pair, key);
                self.timer_needed();
            }
            _ => {}
        }
        self.conns.put(conn);
    }

    /// A key for a new connection, freeing an old one first if the pool is
    /// full, as lwIP does: one pending close, the longest-idle TIME-WAIT,
    /// LAST-ACK and CLOSING connection in turn. `None` when none of that
    /// made room.
    fn allocate(&mut self) -> Option<ConnKey> {
        if self.conns.live >= CONNECTION_POOL {
            self.finish_pending_closes();
            self.abandon_longest_idle(ListKind::TimeWait, None, true);
            for state in [State::LastAck, State::Closing] {
                if self.conns.live >= CONNECTION_POOL {
                    self.abandon_longest_idle(ListKind::Active, Some(state), false);
                }
            }
            if self.conns.live >= CONNECTION_POOL {
                return None;
            }
        }
        Some(self.conns.reserve())
    }

    /// A key for a connection a SYN is opening, or `None` when the pool
    /// has no room. lwIP registers the connection at once, which starts the
    /// TCP timer if it was idle — even if the connection goes again before
    /// `adopt` — so that happens here.
    pub fn open(&mut self) -> Option<ConnKey> {
        let key = self.allocate()?;
        if self.timer_due.is_none() {
            self.timer_due = Some(self.now_ms.after(TIMER_INTERVAL_MS));
        }
        self.env.budget.others = self.queued_total;
        Some(key)
    }

    /// Takes in the connection `open` was for, set up, or lets its key go
    /// if setting it up failed.
    pub fn adopt(&mut self, conn: Connection) {
        if conn.forget {
            self.conns.free(conn.key);
            return;
        }
        let before = Before {
            out_of_order: 0,
            queued: 0,
        };
        self.settle(Box::new(conn), before);
    }

    pub fn find(&self, local: SocketAddr, remote: SocketAddr) -> Option<ConnKey> {
        self.demux.get(&(local, remote)).copied()
    }

    /// Moves a connection a segment arrived for to the head of its list.
    pub fn touch(&mut self, key: ConnKey) {
        if self.lists.list_of(key.index) == Some(ListKind::Active) {
            self.lists.push_front(ListKind::Active, key.index);
        }
    }

    fn finish_pending_closes(&mut self) {
        for index in self.lists.indices(ListKind::Active) {
            let Some(key) = self.conns.key_at(index) else {
                continue;
            };
            self.with_conn(key, |conn, env| {
                if conn.close_pending {
                    conn.close_pending = false;
                    conn.close_with_fin(env);
                }
            });
        }
    }

    /// Of the connections in `kind` (in `state`, if given), the one heard
    /// from longest ago — the later one of a tie — abandoned, or aborted
    /// with a reset.
    fn abandon_longest_idle(&mut self, kind: ListKind, state: Option<State>, reset: bool) {
        let ticks = self.env.ticks;
        let mut longest = 0u32;
        let mut chosen = None;
        for index in self.lists.indices(kind) {
            let Some(conn) = self.conns.key_at(index).and_then(|k| self.conns.get(k)) else {
                continue;
            };
            if state.is_some_and(|s| conn.state != s) {
                continue;
            }
            let idle = ticks.since(conn.last_activity);
            if idle >= longest {
                longest = idle;
                chosen = Some(conn.key);
            }
        }
        if let Some(key) = chosen {
            self.with_conn(key, |conn, env| conn.abandon(reset, env));
        }
    }

    // ---- The pbuf pool ------------------------------------------------------

    /// After the pool ran dry, the out-of-order data of the first active
    /// connection (in list order) that holds some is dropped.
    fn free_out_of_order_if_exhausted(&mut self) {
        if !std::mem::take(&mut self.pool_exhausted) {
            return;
        }
        for index in self.lists.indices(ListKind::Active) {
            let Some(conn) = self.conns.key_at(index).and_then(|k| self.conns.get_mut(k)) else {
                continue;
            };
            if conn.rcv.out_of_order.is_empty() {
                continue;
            }
            let bytes: usize = conn.rcv.out_of_order.iter().map(|s| s.data.len()).sum();
            self.pool_in_use -= conn.rcv.out_of_order.len();
            self.queued_total -= bytes;
            conn.rcv.out_of_order.clear();
            return;
        }
    }

    /// A packet from the TUN device, read into pool pbufs: dropped when
    /// there are not enough free.
    pub fn receive_packet(&mut self, packet: &[u8]) {
        if packet.len() > 0xffff {
            return;
        }
        self.free_out_of_order_if_exhausted();
        let needed = packet.len().div_ceil(PBUF_POOL_BUFSIZE).max(1);
        if self.pool_in_use + needed > PBUF_POOL_SIZE {
            self.pool_exhausted = true;
            return;
        }
        self.on_packet(packet);
    }

    // ---- The timer ----------------------------------------------------------

    fn timer_needed(&mut self) {
        if self.timer_due.is_none() && !self.lists.is_empty() {
            self.timer_due = Some(self.now_ms.after(TIMER_INTERVAL_MS));
        }
    }

    pub fn timer_due(&self) -> Option<Millis> {
        self.timer_due
    }

    pub fn now_ms(&self) -> Millis {
        self.now_ms
    }

    /// Runs the TCP timer if it is due; it reschedules itself while any
    /// connection is left.
    pub fn poll(&mut self) {
        self.free_out_of_order_if_exhausted();
        while let Some(due) = self.timer_due {
            if due.is_after(self.now_ms) {
                return;
            }
            self.timer_due = None;
            self.run_timer();
            if !self.lists.is_empty() {
                self.timer_due = Some(self.now_ms.after(TIMER_INTERVAL_MS));
            }
        }
    }

    /// One run of the TCP timer: a fast tick for every active connection,
    /// and every other run a slow tick.
    fn run_timer(&mut self) {
        for key in self.keys(ListKind::Active) {
            self.with_conn(key, |conn, env| conn.on_fast_tick(env));
        }
        let slow = self.slow_tick_next;
        self.slow_tick_next = !slow;
        if !slow {
            return;
        }
        self.env.ticks = self.env.ticks.next();
        for key in self.keys(ListKind::Active) {
            self.with_conn(key, |conn, env| conn.on_slow_tick(env));
        }
        let ticks = self.env.ticks;
        for key in self.keys(ListKind::TimeWait) {
            self.with_conn(key, |conn, _| {
                if ticks.since(conn.last_activity) > TWO_MSL_TICKS {
                    conn.forget = true;
                }
            });
        }
    }

    /// The keys of a list, head first, as they stand now.
    fn keys(&self, kind: ListKind) -> Vec<ConnKey> {
        self.lists
            .indices(kind)
            .into_iter()
            .filter_map(|i| self.conns.key_at(i))
            .collect()
    }

    // ---- Accounting ---------------------------------------------------------

    pub fn connections(&self) -> usize {
        self.lists.active_len + self.lists.time_wait_len
    }

    pub fn buffered(&self) -> usize {
        self.conns.values().map(Connection::buffered).sum()
    }

    /// Gives back what tables and queues hold beyond a few times their
    /// contents, once connections have gone.
    pub fn shrink(&mut self) {
        let shrink = crate::proxy::tun::netstack::buf::should_shrink;
        if shrink(self.demux.len(), self.demux.capacity()) {
            self.demux.shrink_to(self.demux.len() * 2);
        }
        let packets = &mut self.env.net.packets;
        if shrink(packets.len(), packets.capacity()) {
            packets.shrink_to(packets.len() * 2);
        }
        self.env.apps.shrink();
    }
}
