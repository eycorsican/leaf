use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use log::*;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundHandler, OutboundTransport, UdpOutboundHandler,
        UdpTransportType,
    },
    session::Session,
};

pub struct Handler {
    pub actors: Vec<Arc<dyn OutboundHandler>>,
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn udp_connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Unknown
    }

    async fn handle_udp<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<OutboundTransport>,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        let mut rng = StdRng::from_entropy();
        let i: usize = rng.gen_range(0..self.actors.len());
        debug!(
            "random handles udp [{}] to [{}]",
            sess.destination,
            self.actors[i].tag()
        );
        self.actors[i].handle_udp(sess, None).await
    }
}
