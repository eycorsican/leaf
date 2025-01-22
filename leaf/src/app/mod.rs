use std::sync::Arc;

use tokio::sync::RwLock;

pub mod dispatcher;
pub mod dns_client;
pub mod inbound;
pub mod logger;
pub mod nat_manager;
pub mod outbound;
pub mod router;

#[cfg(feature = "stat")]
pub mod stat_manager;

#[cfg(feature = "api")]
pub mod api;

#[cfg(any(
    target_os = "ios",
    target_os = "android",
    target_os = "macos",
    target_os = "linux"
))]
pub mod fake_dns;

#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    target_os = "linux"
))]
pub mod process_finder;

pub type SyncDnsClient = Arc<RwLock<dns_client::DnsClient>>;

#[cfg(feature = "stat")]
pub type SyncStatManager = Arc<RwLock<stat_manager::StatManager>>;
