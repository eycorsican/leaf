//! The receive side of a segment: what its ACK says about our data, and
//! where its data goes — to the application in order, into the out-of-order
//! queue, or nowhere — and the window and ACK that follow.

use super::config::{
    ACK_PUSHED_AT_ONCE, OUT_OF_ORDER_MAX_BYTES, OUT_OF_ORDER_MAX_SEGMENTS, WINDOW,
    WINDOW_UPDATE_THRESHOLD,
};
use super::conn::{Connection, Receiver, State};
use super::input::{Incoming, Received};
use super::segment::{Segment, TcpFlags};
use super::seq::SeqNum;
use super::stack::Env;

/// A received segment's payload as it is trimmed to fit, still borrowed
/// from the packet.
pub struct InSeg<'a> {
    pub seq: SeqNum,
    pub flags: TcpFlags,
    pub data: &'a [u8],
}

impl InSeg<'_> {
    fn len(&self) -> u16 {
        self.data.len() as u16
    }

    fn seq_len(&self) -> u32 {
        u32::from(self.len()) + u32::from(self.flags.has_any(TcpFlags::SYN | TcpFlags::FIN))
    }

    fn truncate(&mut self, len: u16) {
        self.data = &self.data[..usize::from(len).min(self.data.len())];
    }

    fn to_segment(&self) -> Segment {
        let mut seg = Segment::data(self.seq, self.data.to_vec());
        seg.flags = self.flags;
        seg
    }
}

/// Data for the application: borrowed from the packet when it arrived in
/// order, owned when it waited in the out-of-order queue.
pub enum Chunk<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl Chunk<'_> {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Chunk::Borrowed(b) => b,
            Chunk::Owned(v) => v,
        }
    }
}

impl Receiver {
    /// Moves the announced window up to what is free, once that has grown
    /// by enough to be worth announcing; otherwise keeps the edge already
    /// promised. Returns how far the edge moved.
    pub fn update_announced(&mut self, mss: u16) -> u32 {
        let new_edge = self.next + u32::from(self.window);
        let threshold = u32::from((WINDOW / 2).min(mss));
        if new_edge >= self.announced_edge + threshold {
            self.announced = self.window;
            return new_edge.since(self.announced_edge);
        }
        self.announced = if self.next > self.announced_edge {
            0
        } else {
            self.announced_edge.since(self.next) as u16
        };
        0
    }

    /// The window holds `[next, next + window - 1]`.
    fn window_holds(&self, seq: SeqNum) -> bool {
        seq.within(self.next, self.next + u32::from(self.window) - 1)
    }
}

impl Connection {
    /// The application read `len` bytes: the window reopens by as much,
    /// announced at once if it moved far enough.
    pub fn app_read(&mut self, len: u16, env: &mut Env) {
        let window = self.rcv.window.wrapping_add(len);
        self.rcv.window = if window > WINDOW || window < self.rcv.window {
            WINDOW
        } else {
            window
        };
        if self.rcv.update_announced(self.mss) >= WINDOW_UPDATE_THRESHOLD {
            self.ack.now = true;
            self.output(env);
        }
    }

    /// The ACK half of a segment: the send window, then what it
    /// acknowledges — new data, or a duplicate.
    pub fn on_ack(&mut self, seg: &Incoming<'_>, rx: &mut Received<'_>, env: &mut Env) {
        if !seg.flags.has(TcpFlags::ACK) {
            return;
        }
        let ack = seg.ack;
        let right_edge = self.snd.window_ack + u32::from(self.snd.window);
        let newer = self.snd.window_seq < seg.seq
            || (self.snd.window_seq == seg.seq && self.snd.window_ack < ack)
            || (self.snd.window_ack == ack && seg.window > self.snd.window)
            // An ACK that moves `acked` updates the window too, as Linux
            // does (lwIP does not).
            || (self.snd.acked < ack && ack <= self.snd.next);
        if newer {
            self.snd.window = seg.window;
            self.snd.max_window = self.snd.max_window.max(seg.window);
            self.snd.window_seq = seg.seq;
            self.snd.window_ack = ack;
        }
        if ack <= self.snd.acked {
            let pure_duplicate = seg.len == 0
                && self.snd.window_ack + u32::from(self.snd.window) == right_edge
                && self.rtx.timer.is_running()
                && self.snd.acked == ack;
            if pure_duplicate {
                self.on_duplicate_ack();
            }
        } else if ack.within(self.snd.acked + 1, self.snd.next) {
            self.on_new_ack(ack, rx);
        } else {
            self.send_ack(env);
        }
        if let Some((sent_at, seq)) = self.rtx.timing {
            if seq < ack {
                self.rtx.rtt.sample(env.ticks.since(sent_at) as i16);
                self.rtx.rto = self.rtx.rtt.rto();
                self.rtx.timing = None;
            }
        }
    }

    fn on_duplicate_ack(&mut self) {
        self.rtx.dupacks = self.rtx.dupacks.saturating_add(1);
        if self.rtx.dupacks > 3 {
            grow(&mut self.rtx.cwnd, self.mss);
        }
        if self.rtx.dupacks >= 3 {
            self.fast_retransmit();
        }
    }

    /// An ACK for data not acknowledged before: leave fast recovery, grow
    /// the congestion window, free what is acknowledged.
    fn on_new_ack(&mut self, ack: SeqNum, rx: &mut Received<'_>) {
        if self.rtx.fast_recovery {
            self.rtx.fast_recovery = false;
            self.rtx.cwnd = self.rtx.ssthresh;
            self.rtx.bytes_acked = 0;
        }
        self.rtx.count = 0;
        self.rtx.rto = self.rtx.rtt.rto();
        let acked = ack.since(self.snd.acked) as u16;
        self.rtx.dupacks = 0;
        self.snd.acked = ack;
        if self.state.is_synchronized() {
            if self.rtx.cwnd < self.rtx.ssthresh {
                let segments: u16 = if self.rtx.rto_recovery_end.is_some() {
                    1
                } else {
                    2
                };
                grow(
                    &mut self.rtx.cwnd,
                    acked.min(segments.wrapping_mul(self.mss)),
                );
            } else {
                grow(&mut self.rtx.bytes_acked, acked);
                if self.rtx.bytes_acked >= self.rtx.cwnd {
                    self.rtx.bytes_acked -= self.rtx.cwnd;
                    grow(&mut self.rtx.cwnd, self.mss);
                }
            }
        }
        rx.acked = rx.acked.wrapping_add(self.free_acknowledged(ack, true));
        rx.acked = rx.acked.wrapping_add(self.free_acknowledged(ack, false));
        if self.snd.unacked.is_empty() {
            self.rtx.timer.stop();
        } else {
            self.rtx.timer.restart();
        }
        if self.snd.unsent.is_empty() {
            self.snd.oversize = 0;
        }
        self.snd.space = self.snd.space.wrapping_add(rx.acked);
        if let Some(end) = self.rtx.rto_recovery_end {
            let done = match (self.snd.unacked.front(), self.snd.unsent.front()) {
                (None, None) => true,
                (None, Some(next)) | (Some(next), _) => end <= next.seq,
            };
            if done {
                self.rtx.rto_recovery_end = None;
            }
        }
    }

    /// Drops the segments `ack` covers from the front of the in-flight
    /// (`unacked`) or the unsent queue; returns their payload bytes.
    fn free_acknowledged(&mut self, ack: SeqNum, unacked: bool) -> u16 {
        let queue = if unacked {
            &mut self.snd.unacked
        } else {
            &mut self.snd.unsent
        };
        let mut freed: u16 = 0;
        while queue.front().is_some_and(|seg| seg.end() <= ack) {
            let Some(seg) = queue.pop_front() else {
                break;
            };
            self.snd.queued_pbufs = self.snd.queued_pbufs.wrapping_sub(seg.pbufs.count());
            freed = freed.wrapping_add(seg.len());
        }
        freed
    }

    /// The data half of a segment.
    pub fn on_data<'a>(&mut self, seg: &Incoming<'a>, rx: &mut Received<'a>, env: &mut Env) {
        if seg.len == 0 || !self.state.receives_data() {
            if !self.rcv.window_holds(seg.seq) {
                self.ack.now = true;
            }
            return;
        }
        let mut inseg = InSeg {
            seq: seg.seq,
            flags: seg.flags,
            data: seg.payload,
        };
        let seg_last = seg.seq + u32::from(seg.len) - 1;
        if self.rcv.next.within(seg.seq + 1, seg_last) {
            // It starts before what is expected: drop what was had already.
            let off = self.rcv.next.since(seg.seq) as usize;
            inseg.data = inseg.data.get(off..).unwrap_or(&[]);
            inseg.seq = self.rcv.next;
        } else if seg.seq < self.rcv.next {
            self.ack.now = true;
        }
        if !self.rcv.window_holds(inseg.seq) {
            self.send_ack(env);
            return;
        }
        if inseg.seq == self.rcv.next {
            self.receive_in_order(inseg, seg.flags, rx);
        } else {
            self.queue_out_of_order(inseg, seg.len);
            self.send_ack(env);
        }
    }

    fn receive_in_order<'a>(
        &mut self,
        mut inseg: InSeg<'a>,
        seg_flags: TcpFlags,
        rx: &mut Received<'a>,
    ) {
        let seq = inseg.seq;
        let mut len = inseg.seq_len() as u16;
        if len > self.rcv.window {
            inseg.flags.remove(TcpFlags::FIN);
            let mut fits = self.rcv.window;
            if inseg.flags.has(TcpFlags::SYN) {
                fits = fits.wrapping_sub(1);
            }
            inseg.truncate(fits);
            len = inseg.seq_len() as u16;
        }
        if !self.rcv.out_of_order.is_empty() {
            if inseg.flags.has(TcpFlags::FIN) {
                self.rcv.out_of_order.clear();
            } else {
                while let Some(next) = self.rcv.out_of_order.front() {
                    if seq + u32::from(len) < next.data_end() {
                        break;
                    }
                    if next.flags.has(TcpFlags::FIN) && !inseg.flags.has(TcpFlags::SYN) {
                        // The FIN stays where the peer put it: nothing past
                        // it can be data.
                        inseg.truncate(next.data_end().since(seq) as u16);
                        inseg.flags.insert(TcpFlags::FIN);
                        len = inseg.seq_len() as u16;
                        self.rcv.out_of_order.clear();
                        break;
                    }
                    self.rcv.out_of_order.pop_front();
                }
                if let Some(next) = self.rcv.out_of_order.front() {
                    if seq + u32::from(len) > next.seq {
                        let mut fits = next.seq.since(seq) as u16;
                        if inseg.flags.has(TcpFlags::SYN) {
                            fits = fits.wrapping_sub(1);
                        }
                        inseg.truncate(fits);
                        len = inseg.seq_len() as u16;
                    }
                }
            }
        }
        self.rcv.next = seq + u32::from(len);
        self.rcv.window = self.rcv.window.wrapping_sub(len);
        self.rcv.update_announced(self.mss);
        if !inseg.data.is_empty() {
            rx.data.push(Chunk::Borrowed(inseg.data));
        }
        if inseg.flags.has(TcpFlags::FIN) {
            rx.got_fin = true;
        }
        while self
            .rcv
            .out_of_order
            .front()
            .is_some_and(|s| s.seq == self.rcv.next)
        {
            let Some(next) = self.rcv.out_of_order.pop_front() else {
                break;
            };
            let len = next.seq_len();
            self.rcv.next = self.rcv.next + len;
            self.rcv.window = self.rcv.window.wrapping_sub(len as u16);
            self.rcv.update_announced(self.mss);
            let fin = next.flags.has(TcpFlags::FIN);
            if !next.data.is_empty() {
                rx.data.push(Chunk::Owned(next.data));
            }
            if fin {
                rx.got_fin = true;
                if self.state == State::Established {
                    self.state = State::CloseWait;
                }
            }
        }
        if ACK_PUSHED_AT_ONCE && seg_flags.has(TcpFlags::PSH) {
            self.ack.now = true;
        } else {
            self.ack.owe();
        }
    }

    /// Files a segment past a hole among the ones already waiting: trimmed
    /// where it overlaps them, replacing a shorter one at the same place,
    /// clipped to the window at the end. Then the queue is cut back to its
    /// byte and segment limits.
    fn queue_out_of_order(&mut self, inseg: InSeg<'_>, seg_len: u16) {
        let seq = inseg.seq;
        let queue = &mut self.rcv.out_of_order;
        if queue.is_empty() {
            queue.push_back(inseg.to_segment());
        } else {
            let mut prev: Option<usize> = None;
            let mut i = 0;
            while i < queue.len() {
                let next_seq = queue[i].seq;
                let is_last = i + 1 == queue.len();
                if seq == next_seq {
                    // Same start: keep the longer, unless the one queued is
                    // last — then it was cut to the window, and stays.
                    if inseg.len() > queue[i].len() && !is_last {
                        let rest = queue.split_off(i);
                        queue.extend(cover(seq, inseg.to_segment(), rest));
                    }
                    break;
                }
                match prev {
                    None if seq < next_seq => {
                        let rest = std::mem::take(queue);
                        *queue = cover(seq, inseg.to_segment(), rest);
                        break;
                    }
                    Some(p) if seq.within(queue[p].seq + 1, next_seq - 1) => {
                        let before = &mut queue[p];
                        if before.data_end() > seq {
                            let fits = seq.since(before.seq) as u16;
                            before.truncate(fits);
                        }
                        let rest = queue.split_off(i);
                        queue.extend(cover(seq, inseg.to_segment(), rest));
                        break;
                    }
                    _ => {}
                }
                prev = Some(i);
                if is_last && seq > next_seq {
                    let last = &mut queue[i];
                    if last.flags.has(TcpFlags::FIN) {
                        break;
                    }
                    if last.data_end() > seq {
                        let fits = seq.since(last.seq) as u16;
                        last.truncate(fits);
                    }
                    let mut tail = inseg.to_segment();
                    let window_end = self.rcv.next + u32::from(self.rcv.window);
                    if seq + u32::from(seg_len) > window_end {
                        tail.flags.remove(TcpFlags::FIN);
                        tail.truncate(window_end.since(seq) as u16);
                    }
                    queue.push_back(tail);
                    break;
                }
                i += 1;
            }
        }
        let mut bytes: u32 = 0;
        let mut segments: u16 = 0;
        let cut = queue.iter().position(|seg| {
            bytes = bytes.wrapping_add(u32::from(seg.len()));
            segments = segments.wrapping_add(seg.pbufs.count());
            bytes > OUT_OF_ORDER_MAX_BYTES || segments > OUT_OF_ORDER_MAX_SEGMENTS
        });
        if let Some(cut) = cut {
            queue.truncate(cut);
        }
    }
}

/// `seg` placed ahead of `rest`: the queued segments it covers whole go, and
/// it is cut short of the next one. A FIN-carrying `seg` ends the queue; a
/// FIN it covers stays where it was, `seg` ending there and the queue too.
fn cover(
    seq: SeqNum,
    mut seg: Segment,
    mut rest: std::collections::VecDeque<Segment>,
) -> std::collections::VecDeque<Segment> {
    if seg.flags.has(TcpFlags::FIN) {
        rest.clear();
    } else {
        while let Some(next) = rest.front() {
            if seq + u32::from(seg.len()) < next.data_end() {
                break;
            }
            if next.flags.has(TcpFlags::FIN) {
                seg.truncate(next.data_end().since(seq) as u16);
                seg.flags.insert(TcpFlags::FIN);
                rest.clear();
                break;
            }
            rest.pop_front();
        }
        if let Some(next) = rest.front() {
            if seq + u32::from(seg.len()) > next.seq {
                seg.truncate(next.seq.since(seq) as u16);
            }
        }
    }
    rest.push_front(seg);
    rest
}

/// Adds to a window, saturating at its largest value.
fn grow(window: &mut u16, by: u16) {
    let sum = window.wrapping_add(by);
    *window = if sum >= *window { sum } else { u16::MAX };
}
