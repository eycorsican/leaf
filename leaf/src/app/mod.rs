use std::sync::Arc;

use tokio::sync::RwLock;

pub mod dispatcher;
pub mod dns_client;
pub mod inbound;
pub mod logger;
pub mod nat_manager;
pub mod outbound;
pub mod router;

#[cfg(feature = "api")]
pub mod api;

#[cfg(any(
    target_os = "ios",
    target_os = "android",
    target_os = "macos",
    target_os = "linux"
))]
pub mod fake_dns;

pub type SyncDnsClient = Arc<RwLock<dns_client::DnsClient>>;
