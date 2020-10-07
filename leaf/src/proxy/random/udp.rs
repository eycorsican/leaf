use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{
    proxy::{ProxyDatagram, ProxyHandler, ProxyStream, ProxyUdpHandler, UdpTransportType},
    session::Session,
};

pub struct Handler {
    pub actors: Vec<Arc<dyn ProxyHandler>>,
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
        UdpTransportType::Unknown
    }

    async fn connect<'a>(
        &'a self,
        sess: &'a Session,
        _datagram: Option<Box<dyn ProxyDatagram>>,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyDatagram>> {
        let mut rng = StdRng::from_entropy();
        let i: usize = rng.gen_range(0, self.actors.len());
        self.actors[i].connect(sess, None, None).await
    }
}
