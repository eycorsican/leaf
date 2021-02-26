mod crypto;
mod shadow;

#[cfg(feature = "inbound-shadowsocks")]
pub mod inbound;
#[cfg(feature = "outbound-shadowsocks")]
pub mod outbound;

pub static NAME: &str = "shadowsocks";
