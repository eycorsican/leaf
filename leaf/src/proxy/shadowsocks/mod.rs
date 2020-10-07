mod crypto;
mod protocol;
mod shadow;

pub use crypto::{list_ciphers, AeadCipher, Cipher};
pub use protocol::SocksAddr;
pub use shadow::{
    ShadowedDatagram, ShadowedDatagramRecvHalf, ShadowedDatagramSendHalf, ShadowedStream,
};

pub mod tcp;
pub mod udp;

pub use tcp::Handler as TcpHandler;
pub use udp::Handler as UdpHandler;

pub static NAME: &'static str = "shadowsocks";
