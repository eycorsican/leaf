//! The two clocks of TCP's arithmetic, both modulo 2^32: sequence numbers
//! and timer ticks.

use std::cmp::Ordering;
use std::ops::{Add, Sub};

/// A TCP sequence number. Ordered by the sign of the 32-bit difference, so
/// it orders correctly across wrap-around within half the number space.
/// Exactly half a space apart, `a < b` and `b < a` both hold, as in every
/// TCP that compares this way.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SeqNum(u32);

impl SeqNum {
    pub const fn new(raw: u32) -> Self {
        SeqNum(raw)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    /// How far past `earlier` this is.
    pub fn since(self, earlier: SeqNum) -> u32 {
        self.0.wrapping_sub(earlier.0)
    }

    /// `low <= self <= high`.
    pub fn within(self, low: SeqNum, high: SeqNum) -> bool {
        self >= low && self <= high
    }

    fn before(self, other: SeqNum) -> bool {
        (self.0.wrapping_sub(other.0) as i32) < 0
    }
}

impl PartialOrd for SeqNum {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some((self.0.wrapping_sub(other.0) as i32).cmp(&0))
    }

    fn lt(&self, other: &Self) -> bool {
        self.before(*other)
    }

    fn le(&self, other: &Self) -> bool {
        !other.before(*self)
    }

    fn gt(&self, other: &Self) -> bool {
        other.before(*self)
    }

    fn ge(&self, other: &Self) -> bool {
        !self.before(*other)
    }
}

impl Add<u32> for SeqNum {
    type Output = SeqNum;

    fn add(self, n: u32) -> SeqNum {
        SeqNum(self.0.wrapping_add(n))
    }
}

impl Sub<u32> for SeqNum {
    type Output = SeqNum;

    fn sub(self, n: u32) -> SeqNum {
        SeqNum(self.0.wrapping_sub(n))
    }
}

/// The slow timer's count: every timeout, the RTO and RTT samples are kept
/// in these half-second ticks, not in time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ticks(u32);

impl Ticks {
    pub fn next(self) -> Ticks {
        Ticks(self.0.wrapping_add(1))
    }

    /// Ticks elapsed since `earlier`.
    pub fn since(self, earlier: Ticks) -> u32 {
        self.0.wrapping_sub(earlier.0)
    }
}

/// The stack's millisecond clock, on which the TCP timer is scheduled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Millis(u32);

impl Millis {
    pub fn from_instant(now: crate::proxy::tun::netstack::engine::Instant) -> Millis {
        Millis(now.as_millis() as u32)
    }

    pub fn after(self, ms: u32) -> Millis {
        Millis(self.0.wrapping_add(ms))
    }

    /// Whether this time is still ahead of `now`.
    pub fn is_after(self, now: Millis) -> bool {
        (now.0.wrapping_sub(self.0) as i32) < 0
    }

    /// Milliseconds from `now` until this time; zero once it has passed.
    pub fn until(self, now: Millis) -> u32 {
        let ahead = self.0.wrapping_sub(now.0);
        if (ahead as i32) < 0 {
            0
        } else {
            ahead
        }
    }
}
