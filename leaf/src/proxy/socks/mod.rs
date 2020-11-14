#[cfg(feature = "inbound-socks")]
pub mod inbound;
#[cfg(feature = "outbound-socks")]
pub mod outbound;

pub static NAME: &str = "socks";
