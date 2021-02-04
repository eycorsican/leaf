pub mod tcp;

pub use tcp::Handler as TcpHandler;

pub static NAME: &str = "tls";

mod stream;
