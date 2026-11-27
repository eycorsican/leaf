//! The send side: queueing what the application writes in segments, and
//! sending what the windows allow.

use super::config::{SEND_QUEUE_LIMIT, SEND_QUEUE_PBUFS};
use super::conn::Connection;
use super::segment::{oversize_for, Segment, TcpFlags};
use super::seq::SeqNum;
use super::stack::{Env, Header};

/// Queueing failed for want of memory (the budget or the send queue).
#[derive(Debug, PartialEq, Eq)]
pub struct NoMemory;

#[derive(Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The connection no longer takes data.
    Closed,
    NoMemory,
}

impl Connection {
    /// What the application writes, as much as the send buffer takes in one
    /// queueing — halved until it fits the send queue — then sent as far as
    /// the windows allow. Returns the bytes taken.
    pub fn write(&mut self, data: &[u8], env: &mut Env) -> usize {
        let mut n = data.len().min(usize::from(self.snd.space)).min(0xffff);
        while n > 0 {
            match self.queue_write(&data[..n], env) {
                Ok(()) => break,
                Err(WriteError::NoMemory) => n /= 2,
                Err(WriteError::Closed) => return 0,
            }
        }
        self.output(env);
        n
    }

    /// Segments `data` onto the send queue: first into the room the last
    /// unsent segment has left, then in new segments of at most an MSS (or
    /// half the largest window the peer has offered). All or nothing.
    fn queue_write(&mut self, data: &[u8], env: &mut Env) -> Result<(), WriteError> {
        let len = data.len() as u16;
        let mut mss = self.mss.min(self.snd.max_window / 2);
        if mss == 0 {
            mss = self.mss;
        }
        if !self.state.accepts_writes() {
            return Err(WriteError::Closed);
        }
        if len == 0 {
            return Ok(());
        }
        if len > self.snd.space || self.snd.queued_pbufs >= SEND_QUEUE_PBUFS {
            self.write_failed = true;
            return Err(WriteError::NoMemory);
        }
        let mut pbufs = self.snd.queued_pbufs;
        let mut pos: u16 = 0;
        let mut oversize: u16 = 0;
        let mut oversize_used: u16 = 0;
        let mut appended: Option<u16> = None;
        // Where PSH goes: the last segment this write touched.
        let mut pushed: Option<PushTarget> = None;

        if let Some(last) = self.snd.unsent.back() {
            // A segment queued while the MSS was larger has no space left,
            // rather than a wrapped-around amount of it.
            let mut space = mss.saturating_sub(last.len().saturating_add(last.options_len()));
            oversize = self.snd.oversize;
            if oversize > 0 {
                pushed = Some(PushTarget::LastUnsent);
                oversize_used = space.min(oversize.min(len));
                pos += oversize_used;
                oversize -= oversize_used;
                space -= oversize_used;
            }
            if pos < len && space > 0 && last.len() > 0 {
                let seglen = space.min(len - pos);
                pushed = Some(PushTarget::LastUnsent);
                oversize = self.pbuf_spare(seglen, space, true, env)?;
                appended = Some(seglen);
                pbufs = pbufs.wrapping_add(1);
                pos += seglen;
            }
        }
        let appended_at = oversize_used;

        let mut queue: Vec<Segment> = Vec::new();
        while pos < len {
            let seglen = (len - pos).min(mss);
            oversize = self.pbuf_spare(seglen, mss, queue.is_empty(), env)?;
            pbufs = pbufs.wrapping_add(1);
            if pbufs > SEND_QUEUE_LIMIT {
                self.write_failed = true;
                return Err(WriteError::NoMemory);
            }
            let range = usize::from(pos)..usize::from(pos + seglen);
            queue.push(Segment::data(
                self.snd.queued_end + u32::from(pos),
                data[range].to_vec(),
            ));
            pushed = Some(PushTarget::New(queue.len() - 1));
            pos += seglen;
        }

        if let Some(last) = self.snd.unsent.back_mut() {
            if oversize_used > 0 {
                last.data
                    .extend_from_slice(&data[..usize::from(oversize_used)]);
                last.pbufs.grow_last(oversize_used);
            }
            if let Some(n) = appended {
                let start = usize::from(appended_at);
                last.data
                    .extend_from_slice(&data[start..start + usize::from(n)]);
                last.pbufs.push(n);
            }
        }
        self.snd.oversize = oversize;
        let first_new = self.snd.unsent.len();
        self.snd.unsent.extend(queue);
        self.snd.queued_end = self.snd.queued_end + u32::from(len);
        self.snd.space = self.snd.space.wrapping_sub(len);
        self.snd.queued_pbufs = pbufs;
        let target = match pushed {
            Some(PushTarget::New(i)) => Some(first_new + i),
            Some(PushTarget::LastUnsent) => first_new.checked_sub(1),
            None => None,
        };
        if let Some(seg) = target.and_then(|i| self.snd.unsent.get_mut(i)) {
            seg.flags.insert(TcpFlags::PSH);
        }
        Ok(())
    }

    /// The spare room of a pbuf for `length` bytes of a write — some when
    /// Nagle may hold the segment for more — or `NoMemory` past the budget.
    fn pbuf_spare(
        &mut self,
        length: u16,
        max_length: u16,
        first_segment: bool,
        env: &Env,
    ) -> Result<u16, WriteError> {
        let may_grow = !self.nodelay
            && (!first_segment || !self.snd.unsent.is_empty() || !self.snd.unacked.is_empty());
        let spare = if length < max_length && may_grow {
            oversize_for(length, max_length)
        } else {
            0
        };
        if !env.budget.allows(usize::from(length)) {
            self.write_failed = true;
            return Err(WriteError::NoMemory);
        }
        Ok(spare)
    }

    /// Splits the first unsent segment so its first part fits `size`; PSH
    /// and FIN move to the second (a FIN left on the first would end the
    /// stream at the split point). False when there is none to split, or no
    /// memory to split it.
    pub fn fit_unsent_head(&mut self, size: u16, env: &Env) -> bool {
        let Some(head) = self.snd.unsent.front() else {
            return false;
        };
        if size == 0 {
            return false;
        }
        if head.len() <= size {
            return true;
        }
        let remainder = head.len() - size;
        if !env.budget.allows(usize::from(remainder)) {
            return false;
        }
        let mut moved = TcpFlags::NONE;
        for flag in [TcpFlags::PSH, TcpFlags::FIN] {
            if head.flags.has(flag) {
                moved.insert(flag);
            }
        }
        let mut tail = Segment::data(
            head.seq + u32::from(size),
            head.data[usize::from(size)..].to_vec(),
        );
        tail.flags = moved;
        tail.mss_option = head.mss_option;
        let Some(head) = self.snd.unsent.front_mut() else {
            return false;
        };
        self.snd.queued_pbufs = self.snd.queued_pbufs.wrapping_sub(head.pbufs.count());
        head.truncate(size);
        head.flags.remove(moved);
        self.snd.queued_pbufs = self
            .snd
            .queued_pbufs
            .wrapping_add(head.pbufs.count())
            .wrapping_add(tail.pbufs.count());
        self.snd.unsent.insert(1, tail);
        if self.snd.unsent.len() == 2 {
            self.snd.oversize = 0;
        }
        true
    }

    /// Queues a FIN: on the last unsent segment if it can carry one, else
    /// on its own.
    pub fn queue_fin(&mut self, env: &Env) -> Result<(), NoMemory> {
        if let Some(last) = self.snd.unsent.back_mut() {
            if !last
                .flags
                .has_any(TcpFlags::SYN | TcpFlags::FIN | TcpFlags::RST)
            {
                last.flags.insert(TcpFlags::FIN);
                self.fin_queued = true;
                return Ok(());
            }
        }
        self.queue_control(TcpFlags::FIN, env)
    }

    /// Queues a segment of control bits alone (a SYN-ACK or a FIN).
    pub fn queue_control(&mut self, flags: TcpFlags, env: &Env) -> Result<(), NoMemory> {
        if !env.budget.allows(0) {
            self.write_failed = true;
            return Err(NoMemory);
        }
        self.snd
            .unsent
            .push_back(Segment::control(self.snd.queued_end, flags));
        self.snd.oversize = 0;
        if flags.has_any(TcpFlags::SYN | TcpFlags::FIN) {
            self.snd.queued_end = self.snd.queued_end + 1;
        }
        if flags.has(TcpFlags::FIN) {
            self.fin_queued = true;
        }
        self.snd.queued_pbufs = self.snd.queued_pbufs.wrapping_add(1);
        Ok(())
    }

    /// Nagle: hold back a small segment while data is unacknowledged,
    /// unless there is reason not to.
    fn nagle_lets_go(&self) -> bool {
        self.snd.unacked.is_empty()
            || self.nodelay
            || self.rtx.fast_recovery
            || self
                .snd
                .unsent
                .front()
                .is_some_and(|u| self.snd.unsent.len() > 1 || u.len() >= self.mss)
            || self.snd.space == 0
            || self.snd.queued_pbufs >= SEND_QUEUE_PBUFS
    }

    /// Sends what the congestion and send windows allow from the unsent
    /// queue, or an owed ACK if nothing can go. A segment that does not fit
    /// a window that is not the congestion window's doing starts the
    /// persist timer. Held while a segment for this connection is being
    /// processed.
    pub fn output(&mut self, env: &mut Env) {
        if env.holds_output(self.key) {
            return;
        }
        let window = u32::from(self.snd.window.min(self.rtx.cwnd));
        let needed = |seg: &Segment, acked: SeqNum| seg.data_end().since(acked);
        let Some(first) = self.snd.unsent.front() else {
            if self.ack.now {
                self.send_ack(env);
            } else {
                self.write_failed = false;
            }
            return;
        };
        if needed(first, self.snd.acked) > window {
            if window == u32::from(self.snd.window)
                && self.snd.unacked.is_empty()
                && self.persist.is_none()
            {
                self.persist = Some(super::conn::Persist {
                    ticks: 0,
                    round: 1,
                    probes: 0,
                });
            }
            if self.ack.now {
                self.send_ack(env);
            } else {
                self.write_failed = false;
            }
            return;
        }
        self.persist = None;
        while let Some(seg) = self.snd.unsent.front() {
            if needed(seg, self.snd.acked) > window {
                break;
            }
            if !self.nagle_lets_go() && !self.write_failed && !self.fin_queued {
                break;
            }
            let Some(mut seg) = self.snd.unsent.pop_front() else {
                break;
            };
            seg.flags.insert(TcpFlags::ACK);
            self.send_segment(&seg, env);
            self.ack.sent();
            if self.snd.next < seg.end() {
                self.snd.next = seg.end();
            }
            if seg.seq_len() > 0 {
                self.add_unacked(seg);
            }
        }
        if self.snd.unsent.is_empty() {
            self.snd.oversize = 0;
        }
        self.write_failed = false;
    }

    /// Files a sent segment in sequence order; it usually goes last.
    fn add_unacked(&mut self, seg: Segment) {
        let goes_before_last = self.snd.unacked.back().is_some_and(|u| seg.seq < u.seq);
        if goes_before_last {
            let at = self
                .snd
                .unacked
                .iter()
                .position(|u| u.seq >= seg.seq)
                .unwrap_or(self.snd.unacked.len());
            self.snd.unacked.insert(at, seg);
        } else {
            self.snd.unacked.push_back(seg);
        }
    }

    /// One queued segment on the wire, with the current ACK and window; it
    /// starts the retransmission timer and, if none is running, an RTT
    /// measurement.
    fn send_segment(&mut self, seg: &Segment, env: &mut Env) {
        let mss_option = seg
            .mss_option
            .then(|| env.net.effective_mss(super::config::MSS, self.remote));
        self.rcv.announced_edge = self.rcv.next + u32::from(self.rcv.announced);
        self.rtx.timer.start_if_stopped();
        if self.rtx.timing.is_none() {
            self.rtx.timing = Some((env.ticks, seg.seq));
        }
        let header = Header {
            seq: seg.seq,
            ack: self.rcv.next,
            flags: seg.flags,
            window: self.rcv.announced,
            mss_option,
        };
        env.net.send(self.local, self.remote, &header, &seg.data);
    }

    /// A segment that is not queued, carrying the current ACK and window;
    /// the window is then the one announced.
    fn send_unqueued(&mut self, seq: SeqNum, flags: TcpFlags, payload: &[u8], env: &mut Env) {
        let header = Header {
            seq,
            ack: self.rcv.next,
            flags,
            window: self.rcv.announced,
            mss_option: None,
        };
        self.rcv.announced_edge = self.rcv.next + u32::from(self.rcv.announced);
        env.net.send(self.local, self.remote, &header, payload);
    }

    /// An ACK alone.
    pub fn send_ack(&mut self, env: &mut Env) {
        self.send_unqueued(self.snd.next, TcpFlags::ACK, &[], env);
        self.ack.sent();
    }

    /// A keep-alive probe: an ACK for old sequence space, which the peer
    /// must answer.
    pub fn send_keepalive(&mut self, env: &mut Env) {
        self.send_unqueued(self.snd.next - 1, TcpFlags::ACK, &[], env);
    }

    /// Probes a closed window with the first byte of the unsent queue (or
    /// its FIN, if that is all it holds).
    pub fn send_window_probe(&mut self, env: &mut Env) {
        let Some(seg) = self.snd.unsent.front() else {
            return;
        };
        let is_fin = seg.flags.has(TcpFlags::FIN) && seg.len() == 0;
        let seq = seg.seq;
        let byte = [seg.data.first().copied().unwrap_or(0)];
        let payload: &[u8] = if is_fin { &[] } else { &byte };
        if let Some(persist) = self.persist.as_mut() {
            persist.probes = persist.probes.saturating_add(1);
        }
        let probe_end = seq + 1;
        if self.snd.next < probe_end {
            self.snd.next = probe_end;
        }
        let flags = if is_fin {
            TcpFlags::ACK | TcpFlags::FIN
        } else {
            TcpFlags::ACK
        };
        self.send_unqueued(seq, flags, payload, env);
    }
}

enum PushTarget {
    LastUnsent,
    New(usize),
}
