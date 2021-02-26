pub mod tcp;
pub mod udp;

pub use tcp::Handler as TcpHandler;
pub use udp::Handler as UdpHandler;

use super::shadow;

pub static NAME: &str = "shadowsocks";
