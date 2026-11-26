//! One connection's state, grouped by what each part is for. The logic
//! lives beside it, by side: `receive`, `send`, `input`, `timer`.

use std::collections::VecDeque;
use std::net::SocketAddr;

use super::config::{INITIAL_MSS, INITIAL_RTO_TICKS, SEND_BUFFER, WINDOW};
use super::segment::Segment;
use super::seq::{SeqNum, Ticks};
use super::stack::ConnKey;
use crate::proxy::tun::netstack::engine::ConnId;

/// The TCP states a passive connection goes through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

impl State {
    /// Past the handshake.
    pub fn is_synchronized(self) -> bool {
        !matches!(self, State::SynReceived | State::Closed)
    }

    /// Still taking data from the peer: no FIN received yet.
    pub fn receives_data(self) -> bool {
        matches!(
            self,
            State::SynReceived | State::Established | State::FinWait1 | State::FinWait2
        )
    }

    /// The application may still queue data.
    pub fn accepts_writes(self) -> bool {
        matches!(
            self,
            State::Established | State::CloseWait | State::SynReceived
        )
    }
}

/// Who hears about the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handler {
    /// Not accepted yet: data is consumed on the application's behalf and
    /// a FIN closes the connection.
    Unaccepted,
    /// Held by the application as this id.
    App(ConnId),
    /// The application let go: data resets the connection, and nothing is
    /// reported.
    Released,
}

impl Handler {
    pub fn app(self) -> Option<ConnId> {
        match self {
            Handler::App(id) => Some(id),
            _ => None,
        }
    }
}

/// An ACK owed to the peer. lwIP keeps "owed, may wait for the fast timer"
/// and "send now" apart: both can be set, and the fast timer acts on the
/// first whether or not the second is set.
#[derive(Clone, Copy, Debug, Default)]
pub struct AckState {
    pub delayed: bool,
    pub now: bool,
}

impl AckState {
    /// One more segment to acknowledge: the second in a row is answered at
    /// once.
    pub fn owe(&mut self) {
        if self.delayed {
            self.delayed = false;
            self.now = true;
        } else {
            self.delayed = true;
        }
    }

    pub fn sent(&mut self) {
        *self = AckState::default();
    }
}

/// The receive half.
#[derive(Debug)]
pub struct Receiver {
    pub next: SeqNum,
    /// Room left in the window, data received and not yet read counted out.
    pub window: u16,
    /// The window last put in a segment.
    pub announced: u16,
    /// Where the last announced window ends.
    pub announced_edge: SeqNum,
    /// Segments past a hole, in sequence order.
    pub out_of_order: VecDeque<Segment>,
}

/// The send half. `unacked` holds what is in flight, `unsent` what the
/// windows have not let out yet, both in sequence order.
#[derive(Debug)]
pub struct Sender {
    /// Everything before this is acknowledged.
    pub acked: SeqNum,
    pub next: SeqNum,
    /// One past the last byte the application queued.
    pub queued_end: SeqNum,
    pub window: u16,
    pub max_window: u16,
    /// The segment that last updated `window` (its sequence and ACK).
    pub window_seq: SeqNum,
    pub window_ack: SeqNum,
    /// Bytes the application may still queue.
    pub space: u16,
    /// Pbufs the queues hold.
    pub queued_pbufs: u16,
    /// Spare room of the last unsent segment's pbuf.
    pub oversize: u16,
    pub unsent: VecDeque<Segment>,
    pub unacked: VecDeque<Segment>,
}

/// The retransmission timer, in slow ticks since it was (re)started;
/// stopped is below every RTO but a negative one.
#[derive(Clone, Copy, Debug)]
pub struct RetransmitTimer(i16);

impl RetransmitTimer {
    pub const STOPPED: RetransmitTimer = RetransmitTimer(-1);

    pub fn restart(&mut self) {
        self.0 = 0;
    }

    pub fn stop(&mut self) {
        *self = Self::STOPPED;
    }

    pub fn start_if_stopped(&mut self) {
        if self.0 < 0 {
            self.0 = 0;
        }
    }

    pub fn is_running(self) -> bool {
        self.0 >= 0
    }

    pub fn tick(&mut self) {
        if self.0 >= 0 && self.0 < i16::MAX {
            self.0 += 1;
        }
    }

    pub fn reached(self, rto: i16) -> bool {
        self.0 >= rto
    }
}

/// Jacobson's estimator, in ticks scaled as lwIP scales them: `sa` holds
/// eight times the mean, `sv` four times the deviation.
#[derive(Clone, Copy, Debug)]
pub struct RttEstimator {
    pub sa: i16,
    pub sv: i16,
}

impl RttEstimator {
    pub fn rto(self) -> i16 {
        (i32::from(self.sa >> 3) + i32::from(self.sv)) as i16
    }

    pub fn sample(&mut self, rtt_ticks: i16) {
        let mut m = rtt_ticks;
        m = (i32::from(m) - i32::from(self.sa >> 3)) as i16;
        self.sa = (i32::from(self.sa) + i32::from(m)) as i16;
        if m < 0 {
            m = (-i32::from(m)) as i16;
        }
        m = (i32::from(m) - i32::from(self.sv >> 2)) as i16;
        self.sv = (i32::from(self.sv) + i32::from(m)) as i16;
    }
}

/// Retransmission and congestion state.
#[derive(Debug)]
pub struct Retransmission {
    pub timer: RetransmitTimer,
    pub rto: i16,
    pub rtt: RttEstimator,
    /// The segment being timed: when it was sent and where it starts.
    pub timing: Option<(Ticks, SeqNum)>,
    /// Retransmissions since the last new ACK.
    pub count: u8,
    pub dupacks: u8,
    pub cwnd: u16,
    pub ssthresh: u16,
    pub bytes_acked: u16,
    pub fast_recovery: bool,
    /// After an RTO, the end of what was in flight: slow start grows by one
    /// segment per ACK until it is acknowledged.
    pub rto_recovery_end: Option<SeqNum>,
}

/// Probing a window too small for the next segment.
#[derive(Clone, Copy, Debug)]
pub struct Persist {
    /// Slow ticks counted toward the next probe.
    pub ticks: u8,
    /// Which probe interval (1-based, into `PERSIST_BACKOFF`).
    pub round: u8,
    /// Zero-window probes sent unanswered.
    pub probes: u8,
}

/// Keep-alive probing; how long to wait is the engine's, not the
/// connection's.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeepAlive {
    /// Probes sent unanswered.
    pub sent: u8,
}

pub struct Connection {
    pub key: ConnKey,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: State,
    pub handler: Handler,
    pub mss: u16,
    /// When the peer was last heard from (kept still once the application
    /// has stopped reading).
    pub last_activity: Ticks,
    pub ack: AckState,
    /// Nagle is off.
    pub nodelay: bool,
    /// The application will read no more.
    pub rx_closed: bool,
    /// A FIN is queued.
    pub fin_queued: bool,
    /// A close waits for memory to queue its FIN.
    pub close_pending: bool,
    /// A write failed for want of memory: send what is queued regardless of
    /// Nagle.
    pub write_failed: bool,
    pub rcv: Receiver,
    pub snd: Sender,
    pub rtx: Retransmission,
    pub persist: Option<Persist>,
    pub keepalive: Option<KeepAlive>,
    /// The stack has let it go; it is dropped instead of put back.
    pub forget: bool,
}

impl Connection {
    /// A connection for a SYN from `remote` to `local`, our ISN `iss`.
    pub fn new(
        key: ConnKey,
        local: SocketAddr,
        remote: SocketAddr,
        now: Ticks,
        peer_isn: SeqNum,
        iss: SeqNum,
    ) -> Connection {
        let rcv_next = peer_isn + 1;
        Connection {
            key,
            local,
            remote,
            state: State::SynReceived,
            handler: Handler::Unaccepted,
            mss: INITIAL_MSS,
            last_activity: now,
            ack: AckState::default(),
            nodelay: false,
            rx_closed: false,
            fin_queued: false,
            close_pending: false,
            write_failed: false,
            rcv: Receiver {
                next: rcv_next,
                window: WINDOW,
                announced: WINDOW,
                announced_edge: rcv_next,
                out_of_order: VecDeque::new(),
            },
            snd: Sender {
                acked: iss,
                next: iss,
                queued_end: iss,
                window: 0,
                max_window: 0,
                window_seq: peer_isn - 1,
                window_ack: iss,
                space: SEND_BUFFER,
                queued_pbufs: 0,
                oversize: 0,
                unsent: VecDeque::new(),
                unacked: VecDeque::new(),
            },
            rtx: Retransmission {
                timer: RetransmitTimer::STOPPED,
                rto: INITIAL_RTO_TICKS,
                rtt: RttEstimator {
                    sa: 0,
                    sv: INITIAL_RTO_TICKS,
                },
                timing: None,
                count: 0,
                dupacks: 0,
                cwnd: 1,
                ssthresh: SEND_BUFFER,
                bytes_acked: 0,
                fast_recovery: false,
                rto_recovery_end: None,
            },
            persist: None,
            keepalive: None,
            forget: false,
        }
    }

    /// Payload bytes the queues hold.
    pub fn buffered(&self) -> usize {
        let sum = |q: &VecDeque<Segment>| q.iter().map(|s| s.data.len()).sum::<usize>();
        sum(&self.snd.unsent) + sum(&self.snd.unacked) + sum(&self.rcv.out_of_order)
    }

    /// Drops every queued segment of a connection that is going away.
    pub fn purge(&mut self) {
        if !matches!(self.state, State::Closed | State::TimeWait) {
            self.rcv.out_of_order.clear();
            self.rtx.timer.stop();
            self.snd.unsent.clear();
            self.snd.unacked.clear();
            self.snd.oversize = 0;
        }
    }
}
