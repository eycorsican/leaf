//! What each connection does on the TCP timer: delayed ACKs and pending
//! closes on every (fast) tick; retransmission, window probes, keep-alive
//! and the state timeouts on every slow tick.

use super::app::Ending;
use super::config::{
    FIN_WAIT_2_TIMEOUT_TICKS, KEEPALIVE_INTERVAL_MS, KEEPALIVE_PROBES, MAX_RETRANSMITS,
    OUT_OF_ORDER_TIMEOUT_RTOS, PERSIST_BACKOFF, RTO_BACKOFF, SLOW_TICK_MS,
    SYN_RECEIVED_TIMEOUT_TICKS, TWO_MSL_TICKS,
};
use super::conn::{Connection, State};
use super::stack::Env;

/// Why a slow tick ends a connection.
enum GiveUp {
    /// Silently: retransmissions or probes unanswered, or a state timed out.
    Quietly,
    /// With a reset: keep-alive found the peer gone.
    WithReset,
}

impl Connection {
    pub fn on_fast_tick(&mut self, env: &mut Env) {
        if self.ack.delayed {
            self.ack.now = true;
            self.output(env);
            self.ack.sent();
        }
        if self.close_pending {
            self.close_pending = false;
            self.close_with_fin(env);
        }
    }

    pub fn on_slow_tick(&mut self, env: &mut Env) {
        let idle = env.ticks.since(self.last_activity);
        let mut give_up = None;

        if self.rtx.count >= MAX_RETRANSMITS {
            give_up = Some(GiveUp::Quietly);
        } else if let Some(persist) = self.persist {
            if persist.probes >= MAX_RETRANSMITS {
                give_up = Some(GiveUp::Quietly);
            } else {
                self.persist_tick(env);
            }
        } else {
            self.retransmit_tick(env);
        }
        if self.state == State::FinWait2 && self.rx_closed && idle > FIN_WAIT_2_TIMEOUT_TICKS {
            give_up = Some(GiveUp::Quietly);
        }
        if let Some(keepalive) = self.keepalive {
            if matches!(self.state, State::Established | State::CloseWait) {
                let idle_ms = env.keepalive_idle_ms;
                let all_probes = KEEPALIVE_PROBES.wrapping_mul(KEEPALIVE_INTERVAL_MS);
                let sent_probes = u32::from(keepalive.sent).wrapping_mul(KEEPALIVE_INTERVAL_MS);
                if idle > idle_ms.wrapping_add(all_probes) / SLOW_TICK_MS {
                    give_up = Some(GiveUp::WithReset);
                } else if idle > idle_ms.wrapping_add(sent_probes) / SLOW_TICK_MS {
                    self.send_keepalive(env);
                    if let Some(keepalive) = self.keepalive.as_mut() {
                        keepalive.sent = keepalive.sent.wrapping_add(1);
                    }
                }
            }
        }
        let rtos = (self.rtx.rto as u32).wrapping_mul(OUT_OF_ORDER_TIMEOUT_RTOS);
        if !self.rcv.out_of_order.is_empty() && idle >= rtos {
            self.rcv.out_of_order.clear();
        }
        if self.state == State::SynReceived && idle > SYN_RECEIVED_TIMEOUT_TICKS {
            give_up = Some(GiveUp::Quietly);
        }
        if self.state == State::LastAck && idle > TWO_MSL_TICKS {
            give_up = Some(GiveUp::Quietly);
        }

        match give_up {
            Some(how) => {
                let handler = self.handler;
                self.purge();
                if matches!(how, GiveUp::WithReset) {
                    env.net
                        .send_reset(self.local, self.remote, self.snd.next, self.rcv.next);
                }
                self.forget = true;
                env.apps.ended(handler, Ending::Reset);
            }
            None => {
                env.apps.wake(self.handler);
                self.output(env);
            }
        }
    }

    /// A slow tick while the window is too small for the next segment: when
    /// the round's ticks are up, probe a closed window or send what fits an
    /// open one, then wait a longer round.
    fn persist_tick(&mut self, env: &mut Env) {
        let Some(persist) = self.persist.as_mut() else {
            return;
        };
        let round_ticks = PERSIST_BACKOFF[usize::from(persist.round - 1)];
        if persist.ticks < round_ticks {
            persist.ticks += 1;
        }
        if persist.ticks < round_ticks {
            return;
        }
        let mut next_round = true;
        if self.snd.window == 0 {
            self.send_window_probe(env);
        } else if self.fit_unsent_head(self.snd.window, env) {
            self.output(env);
            next_round = false;
        }
        if next_round {
            if let Some(persist) = self.persist.as_mut() {
                persist.ticks = 0;
                if usize::from(persist.round) < PERSIST_BACKOFF.len() {
                    persist.round += 1;
                }
            }
        }
    }

    /// A slow tick of the retransmission timer: once it reaches the RTO,
    /// everything in flight goes again, the RTO backs off and the
    /// congestion window restarts from one segment.
    fn retransmit_tick(&mut self, env: &mut Env) {
        self.rtx.timer.tick();
        if !self.rtx.timer.reached(self.rtx.rto) {
            return;
        }
        let something_to_send = self.requeue_in_flight()
            || (self.snd.unacked.is_empty() && !self.snd.unsent.is_empty());
        if !something_to_send {
            return;
        }
        let backoff = RTO_BACKOFF[usize::from(self.rtx.count).min(RTO_BACKOFF.len() - 1)];
        let base = i32::from(self.rtx.rtt.sa >> 3) + i32::from(self.rtx.rtt.sv);
        self.rtx.rto = (base << backoff).min(0x7FFF) as i16;
        self.rtx.timer.restart();
        let flight_window = self.rtx.cwnd.min(self.snd.window);
        self.rtx.ssthresh = (flight_window >> 1).max(self.mss << 1);
        self.rtx.cwnd = self.mss;
        self.rtx.bytes_acked = 0;
        self.rtx.count = self.rtx.count.saturating_add(1);
        self.output(env);
    }
}
