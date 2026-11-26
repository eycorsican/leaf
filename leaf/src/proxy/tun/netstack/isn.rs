//! Initial sequence numbers (RFC 6528): a keyed hash of the connection's
//! addresses plus a clock ticking every 4 µs, keyed by a random secret.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::SocketAddr;

use crate::proxy::tun::netstack::engine::Instant;

#[derive(Clone, Copy, Debug)]
pub struct IsnGenerator {
    secret: [u64; 2],
}

impl IsnGenerator {
    pub fn new() -> Self {
        IsnGenerator {
            secret: [rand::random(), rand::random()],
        }
    }

    pub fn isn(&self, now: Instant, client: SocketAddr, target: SocketAddr) -> u32 {
        // `DefaultHasher::new()` has fixed keys; the secret goes into the
        // input, which keys it just the same.
        let mut h = DefaultHasher::new();
        self.secret.hash(&mut h);
        (client, target).hash(&mut h);
        (h.finish() as u32).wrapping_add((now.as_micros() / 4) as u32)
    }
}
