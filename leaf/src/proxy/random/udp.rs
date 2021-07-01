use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use log::*;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundHandler, OutboundTransport, UdpOutboundHandler,
        DatagramTransportType,
    },
    session::Session,
};

pub struct Handler {
    pub actors: Vec<Arc<dyn OutboundHandler>>,
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Undefined
    }

    async fn handle<'a>(
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
        UdpOutboundHandler::handle(self.actors[i].as_ref(), sess, None).await
    }
}
