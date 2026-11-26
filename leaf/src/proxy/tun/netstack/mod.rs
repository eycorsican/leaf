//! A userspace network stack for the TUN inbound: IP packets in and out on
//! one side, accepted TCP streams and UDP datagrams on the other.
//!
//! IP parsing, fragment reassembly, UDP and the async driver around a TCP
//! engine written in Rust (`tcp`).

mod buf;
mod engine;
mod frag;
mod ip;
mod isn;
mod stack;
mod tcp;
mod wire;

pub use stack::{new, Config, TcpStream, UdpSocket};
