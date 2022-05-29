pub mod stream;
pub mod datagram;

pub use stream::Handler as StreamHandler;
pub use datagram::Handler as DatagramHandler;

pub(self) enum Method {
    Random,
    RandomOnce,
    RoundRobin,
}
