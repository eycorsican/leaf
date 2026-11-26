//! Sending again what was lost: the oldest segment on a duplicate ACK or a
//! repeated SYN, everything in flight on a timeout.

use super::conn::Connection;

impl Connection {
    /// Moves the oldest in-flight segment back among the unsent, where the
    /// next output sends it again. False when nothing is in flight.
    pub fn retransmit_oldest(&mut self) -> bool {
        let Some(seg) = self.snd.unacked.pop_front() else {
            return false;
        };
        let at = self
            .snd
            .unsent
            .iter()
            .position(|u| u.seq >= seg.seq)
            .unwrap_or(self.snd.unsent.len());
        self.snd.unsent.insert(at, seg);
        if at + 1 == self.snd.unsent.len() {
            self.snd.oversize = 0;
        }
        self.rtx.count = self.rtx.count.saturating_add(1);
        self.rtx.timing = None;
        true
    }

    /// Third duplicate ACK: retransmit the oldest segment and enter fast
    /// recovery with the congestion window halved.
    pub fn fast_retransmit(&mut self) {
        if self.snd.unacked.is_empty() || self.rtx.fast_recovery || !self.retransmit_oldest() {
            return;
        }
        let rtx = &mut self.rtx;
        rtx.ssthresh = rtx.cwnd.min(self.snd.window) / 2;
        if u32::from(rtx.ssthresh) < 2 * u32::from(self.mss) {
            rtx.ssthresh = self.mss.wrapping_mul(2);
        }
        rtx.cwnd = rtx.ssthresh.wrapping_add(self.mss.wrapping_mul(3));
        rtx.fast_recovery = true;
        rtx.timer.restart();
    }

    /// Puts everything in flight back at the head of the unsent queue, to
    /// be sent again from the first unacknowledged byte. False when nothing
    /// is in flight.
    pub fn requeue_in_flight(&mut self) -> bool {
        let Some(last) = self.snd.unacked.back() else {
            return false;
        };
        self.rtx.rto_recovery_end = Some(last.end());
        let mut requeued = std::mem::take(&mut self.snd.unacked);
        requeued.append(&mut self.snd.unsent);
        self.snd.unsent = requeued;
        self.rtx.timing = None;
        true
    }
}
