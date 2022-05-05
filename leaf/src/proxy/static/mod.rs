pub mod tcp;
pub mod udp;

pub use tcp::Handler as TcpHandler;
pub use udp::Handler as UdpHandler;

pub(self) enum Method {
    Random,
    RandomOnce,
    RoundRobin,
}
