pub mod datagram;
pub mod stream;

pub use datagram::{VlessDatagram, build_vless_udp_header};
pub use stream::{VlessStream, build_vless_tcp_header};

#[cfg(feature = "outbound-vless")]
pub mod outbound;
