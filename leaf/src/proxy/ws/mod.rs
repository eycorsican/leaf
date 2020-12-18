#[cfg(feature = "inbound-ws")]
pub mod inbound;
#[cfg(feature = "outbound-ws")]
pub mod outbound;

mod stream;

pub static NAME: &str = "ws";
