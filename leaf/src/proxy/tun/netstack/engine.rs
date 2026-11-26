//! The types the TCP engine and the stack around it share: the clock it is
//! handed, connection ids, the limits it runs within and what it reports.

use std::net::SocketAddr;
use std::time::Duration;

/// Time since the stack was created. Engines never read a clock of their own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    pub const ZERO: Instant = Instant(0);

    pub const fn from_micros(micros: u64) -> Self {
        Instant(micros)
    }

    pub const fn as_micros(self) -> u64 {
        self.0
    }

    pub const fn as_millis(self) -> u64 {
        self.0 / 1000
    }
}

impl std::ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Instant {
        let micros = u64::try_from(rhs.as_micros()).unwrap_or(u64::MAX);
        Instant(self.0.saturating_add(micros))
    }
}

/// Identifies one accepted connection for its whole life. Never reused, so a
/// stale id can only ever miss, never reach a newer connection.
pub type ConnId = u64;

/// A connection whose handshake has completed and that the application has
/// not picked up yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub id: ConnId,
    /// The application's end, behind the TUN device.
    pub client: SocketAddr,
    /// Where the application was connecting to.
    pub target: SocketAddr,
}

/// Bounds on what one engine may hold. Per connection the sizes are lwIP's,
/// fixed (a 32-segment window, a 16-segment send buffer, 12
/// retransmissions), so the stack-wide bounds are here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Connections in any state, the half-open ones included. A SYN beyond it
    /// is answered with RST.
    pub max_connections: usize,
    /// Idle time before a keep-alive probe; `None` sends none.
    pub keepalive: Option<Duration>,
    /// The MTU of the link; segments are sized to fit it.
    pub mtu: usize,
    /// Payload bytes buffered across all connections together. Past it
    /// windows close and writes block, so the whole stack stays within it
    /// whatever the number of connections. `None` leaves only the
    /// per-connection bounds. Backends that allocate whole buffers up front
    /// cannot honour it and ignore it.
    pub memory_budget: Option<usize>,
}

impl Default for Limits {
    /// Sized for where the stack runs. On iOS the packet tunnel extension is
    /// killed past 50 MB, so everything buffered across all connections
    /// shares a 4 MiB budget there.
    fn default() -> Self {
        #[cfg(target_os = "ios")]
        let budget = 4 << 20;
        #[cfg(not(target_os = "ios"))]
        let budget = 16 << 20;
        Limits {
            max_connections: 1024,
            keepalive: Some(Duration::from_secs(60)),
            mtu: 1500,
            memory_budget: Some(budget),
        }
    }
}

/// What an engine reports about itself, for the memory and leak checks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EngineStats {
    /// Connections the engine still holds state for, in any TCP state.
    pub connections: usize,
    /// Connections the application still holds a handle to.
    pub open_handles: usize,
    /// Payload bytes buffered in either direction across all connections.
    pub buffered_bytes: usize,
}
