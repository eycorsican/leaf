use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;

use crate::{
    proxy::{ProxyDatagram, ProxyStream, ProxyUdpHandler, UdpTransportType},
    session::Session,
};

pub struct Handler {
    pub path: String,
}

#[async_trait]
impl ProxyUdpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn udp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        None
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Stream
    }

    async fn connect<'a>(
        &'a self,
        _sess: &'a Session,
        _datagram: Option<Box<dyn ProxyDatagram>>,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyDatagram>> {
        unimplemented!()
    }
}
