pub mod datagram;
pub mod stream;

pub use datagram::{build_vless_udp_header, VlessDatagram};
pub use stream::{build_vless_tcp_header, VlessStream};

#[cfg(feature = "outbound-vless")]
pub mod outbound;
