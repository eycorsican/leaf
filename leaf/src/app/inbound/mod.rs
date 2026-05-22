pub mod network_listener;

#[cfg(feature = "inbound-tun")]
mod tun_listener;

#[cfg(feature = "inbound-cat")]
mod cat_listener;

#[cfg(all(feature = "inbound-tproxy", target_os = "linux"))]
mod tproxy_listener;

pub mod manager;

#[cfg(feature = "inbound-nf")]
pub use network_listener::get_network_listen_addr;
