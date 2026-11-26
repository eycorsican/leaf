//! IPv4 and IPv6 fragment reassembly, ahead of every backend.
//!
//! Bounded in count, bytes and time: fragments are input the network
//! controls, and the stack runs where memory is the scarcest resource.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::proxy::tun::netstack::engine::Instant;
use crate::proxy::tun::netstack::ip::{self, IpView};
use crate::proxy::tun::netstack::wire;

/// The largest payload a datagram can reassemble to and still be one packet:
/// IPv4's total length counts its header, IPv6's payload length does not.
fn max_payload(addr: IpAddr) -> usize {
    match addr {
        IpAddr::V4(_) => usize::from(u16::MAX) - wire::IPV4_HEADER_LEN,
        IpAddr::V6(_) => usize::from(u16::MAX),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReassemblyLimits {
    /// Datagrams being reassembled at once.
    pub max_datagrams: usize,
    /// Payload bytes held across all of them.
    pub max_bytes: usize,
    /// How long an incomplete datagram is kept.
    pub timeout: Duration,
}

impl Default for ReassemblyLimits {
    fn default() -> Self {
        ReassemblyLimits {
            max_datagrams: 32,
            max_bytes: 256 * 1024,
            timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Key {
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    id: u32,
}

struct Partial {
    data: Vec<u8>,
    /// Received byte ranges, sorted and disjoint.
    received: Vec<(usize, usize)>,
    /// Payload length, known once the last fragment has arrived.
    total: Option<usize>,
    expires: Instant,
}

impl Partial {
    /// Records `[offset, offset + chunk.len())`. False when it overlaps data
    /// already received with different bytes — the datagram is then dropped
    /// (RFC 5722), since no answer about which copy is right is safe.
    fn insert(&mut self, offset: usize, chunk: &[u8]) -> bool {
        let end = offset + chunk.len();
        for &(start, stop) in &self.received {
            if offset < stop && start < end {
                let overlap_start = offset.max(start);
                let overlap_end = end.min(stop);
                let old = &self.data[overlap_start..overlap_end];
                let new = &chunk[overlap_start - offset..overlap_end - offset];
                if old != new {
                    return false;
                }
            }
        }
        if self.data.len() < end {
            self.data.resize(end, 0);
        }
        self.data[offset..end].copy_from_slice(chunk);
        self.received.push((offset, end));
        self.received.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.received.len());
        for &(start, stop) in &self.received {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(stop),
                _ => merged.push((start, stop)),
            }
        }
        self.received = merged;
        true
    }

    fn is_complete(&self) -> bool {
        match (self.total, self.received.as_slice()) {
            (Some(total), [(0, end)]) => *end == total,
            _ => false,
        }
    }
}

#[derive(Default)]
pub struct Reassembler {
    limits: ReassemblyLimits,
    partials: HashMap<Key, Partial>,
    bytes: usize,
    /// Datagrams given up on: evicted, timed out, overlapping or malformed.
    pub dropped: u64,
}

impl Reassembler {
    pub fn new(limits: ReassemblyLimits) -> Self {
        Reassembler {
            limits,
            ..Default::default()
        }
    }

    pub fn held_bytes(&self) -> usize {
        self.bytes
    }

    /// Takes one fragment. Returns the whole datagram, rebuilt as a single IP
    /// packet without options, once its last missing piece arrives.
    pub fn push(&mut self, now: Instant, view: &IpView<'_>) -> Option<Vec<u8>> {
        let fragment = view.fragment?;
        let key = Key {
            src: view.src,
            dst: view.dst,
            protocol: view.protocol,
            id: fragment.id,
        };
        let end = fragment.offset + view.payload.len();
        let misaligned = fragment.more && !view.payload.len().is_multiple_of(8);
        if end > max_payload(key.src) || misaligned || view.payload.is_empty() {
            self.drop_datagram(&key);
            self.dropped += 1;
            return None;
        }

        if !self.partials.contains_key(&key) {
            self.expire(now);
            if self.partials.len() >= self.limits.max_datagrams {
                self.evict_oldest();
            }
            self.partials.insert(
                key,
                Partial {
                    data: Vec::new(),
                    received: Vec::new(),
                    total: None,
                    expires: now + self.limits.timeout,
                },
            );
        }

        let grows_by = {
            let partial = self.partials.get(&key)?;
            end.saturating_sub(partial.data.len())
        };
        while self.bytes + grows_by > self.limits.max_bytes && self.partials.len() > 1 {
            if !self.evict_oldest_except(&key) {
                break;
            }
        }
        if self.bytes + grows_by > self.limits.max_bytes {
            self.drop_datagram(&key);
            self.dropped += 1;
            return None;
        }

        let partial = self.partials.get_mut(&key)?;
        let total_conflicts = match partial.total {
            Some(total) => end > total || (!fragment.more && end != total),
            None => !fragment.more && partial.received.iter().any(|&(_, stop)| stop > end),
        };
        let before = partial.data.len();
        if total_conflicts || !partial.insert(fragment.offset, view.payload) {
            self.drop_datagram(&key);
            self.dropped += 1;
            return None;
        }
        if !fragment.more {
            partial.total = Some(end);
        }
        self.bytes += partial.data.len() - before;
        if !partial.is_complete() {
            return None;
        }

        let partial = self.partials.remove(&key)?;
        self.bytes -= partial.data.len();
        ip::build_packet(key.src, key.dst, key.protocol, &partial.data)
    }

    /// Drops the datagrams whose time is up.
    pub fn expire(&mut self, now: Instant) {
        let before = self.partials.len();
        let mut freed = 0;
        self.partials.retain(|_, partial| {
            let keep = partial.expires > now;
            if !keep {
                freed += partial.data.len();
            }
            keep
        });
        self.bytes -= freed;
        self.dropped += (before - self.partials.len()) as u64;
    }

    /// When the oldest incomplete datagram times out.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.partials.values().map(|p| p.expires).min()
    }

    fn drop_datagram(&mut self, key: &Key) {
        if let Some(partial) = self.partials.remove(key) {
            self.bytes -= partial.data.len();
        }
    }

    fn evict_oldest(&mut self) -> bool {
        let oldest = self
            .partials
            .iter()
            .min_by_key(|(_, p)| p.expires)
            .map(|(k, _)| *k);
        match oldest {
            Some(key) => {
                self.drop_datagram(&key);
                self.dropped += 1;
                true
            }
            None => false,
        }
    }

    fn evict_oldest_except(&mut self, keep: &Key) -> bool {
        let oldest = self
            .partials
            .iter()
            .filter(|(k, _)| *k != keep)
            .min_by_key(|(_, p)| p.expires)
            .map(|(k, _)| *k);
        match oldest {
            Some(key) => {
                self.drop_datagram(&key);
                self.dropped += 1;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::proxy::tun::netstack::ip::Fragment;

    /// Two fragments whose payload ends at `end`: one big piece, then the rest.
    fn reassemble(src: &str, dst: &str, end: usize) -> (Option<Vec<u8>>, Reassembler) {
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        let payload = vec![7u8; end];
        let split = 65_504;
        let now = Instant::from_micros(1000);
        let mut result = None;
        for (offset, more) in [(0, true), (split, false)] {
            let stop = if more { split } else { end };
            let view = IpView {
                src: src.parse().unwrap(),
                dst: dst.parse().unwrap(),
                protocol: ip::PROTO_UDP,
                payload: &payload[offset..stop],
                fragment: Some(Fragment {
                    id: 1,
                    offset,
                    more,
                }),
            };
            result = reassembler.push(now, &view);
        }
        (result, reassembler)
    }

    #[test]
    fn an_ipv4_datagram_reassembles_up_to_what_one_packet_holds() {
        let (packet, reassembler) = reassemble("10.0.0.2", "10.0.0.1", 65_515);
        assert_eq!(packet.map(|p| p.len()), Some(65_535));
        assert_eq!(reassembler.dropped, 0);
    }

    #[test]
    fn an_ipv4_datagram_past_one_packet_is_counted_as_dropped() {
        let (packet, reassembler) = reassemble("10.0.0.2", "10.0.0.1", 65_520);
        assert!(packet.is_none());
        assert_eq!(reassembler.dropped, 1);
        assert_eq!(reassembler.held_bytes(), 0);
    }

    #[test]
    fn an_ipv6_payload_may_fill_its_whole_length_field() {
        let (packet, reassembler) = reassemble("fd00::2", "fd00::1", 65_520);
        assert_eq!(packet.map(|p| p.len()), Some(40 + 65_520));
        assert_eq!(reassembler.dropped, 0);
    }
}
