use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use log::*;

use crate::{
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundHandler, OutboundTransport, UdpOutboundHandler,
        UdpTransportType,
    },
    session::Session,
};

pub struct Handler {
    pub actors: Vec<Arc<dyn OutboundHandler>>,
    pub next: AtomicUsize,
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
        let current = self.next.load(Ordering::Relaxed);
        let a = &self.actors[current];
        let next = if current >= self.actors.len() - 1 {
            0
        } else {
            current + 1
        };
        self.next.store(next, Ordering::Relaxed);
        debug!("rr handles tcp [{}] to [{}]", sess.destination, a.tag());
        a.handle_udp(sess, None).await
    }
}
