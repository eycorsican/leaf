mod network_listener;

#[cfg(all(
    feature = "inbound-tun",
    any(target_os = "ios", target_os = "macos", target_os = "linux")
))]
mod tun_listener;

pub mod manager;

use crate::Runner;

trait InboundListener {
    fn listen(&self) -> Vec<Runner>;
}
