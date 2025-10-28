use std::sync::Arc;

use tokio::sync::RwLock;

pub mod dispatcher;
pub mod dns_client;
pub mod inbound;
pub mod logger;
pub mod nat_manager;
pub mod outbound;
pub mod router;
pub mod stat_manager;
pub mod healthcheck;

#[cfg(feature = "api")]
pub mod api;

pub mod fake_dns;

pub type SyncDnsClient = Arc<RwLock<dns_client::DnsClient>>;

pub type SyncStatManager = Arc<RwLock<stat_manager::StatManager>>;
