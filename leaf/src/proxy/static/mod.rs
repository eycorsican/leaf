pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

enum Method {
    Random,
    RandomOnce,
    RoundRobin,
}
