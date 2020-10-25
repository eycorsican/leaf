mod stream;
pub use stream::*;

pub mod tcp;
pub mod udp;

pub use tcp::Handler as TcpHandler;
pub use udp::Handler as UdpHandler;

pub static NAME: &str = "vless";
