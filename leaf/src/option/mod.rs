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
