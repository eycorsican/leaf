#[cfg(target_os = "ios")]
mod ios;

#[cfg(target_os = "ios")]
pub use ios::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use unix::*;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::*;

/// Uplink timeout after downlink EOF.
pub static TCP_UPLINK_TIMEOUT: u64 = 2;

/// Downlink timeout after uplink EOF.
pub static TCP_DOWNLINK_TIMEOUT: u64 = 4;

/// Maximum outbound dial concurrency.
pub static OUTBOUND_DIAL_CONCURRENCY: usize = 1;

/// UDP session timeout. A UDP session shall be terminated if there are no
/// activities in this period. The timeouts are observed only when a check
/// is happened.
pub static UDP_SESSION_TIMEOUT: u64 = 30;

/// UDP session timeout check interval. The interval to check for UDP session
/// timeouts.
pub static UDP_SESSION_TIMEOUT_CHECK_INTERVAL: u64 = 10;

/// Maximum retries for a specific DNS query for the built-in DNS client.
pub static MAX_DNS_RETRIES: usize = 4;

/// Timeout for a DNS query for the built-in DNS client.
pub static DNS_TIMEOUT: u64 = 4;
