use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use log::*;

use crate::{
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundHandler, OutboundTransport, UdpOutboundHandler,
        DatagramTransportType,
    },
    session::Session,
};

pub struct Handler {
    pub actors: Vec<Arc<dyn OutboundHandler>>,
    pub next: AtomicUsize,
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
        let current = self.next.load(Ordering::Relaxed);
        let a = &self.actors[current];
        let next = if current >= self.actors.len() - 1 {
            0
        } else {
            current + 1
        };
        self.next.store(next, Ordering::Relaxed);
        debug!("rr handles tcp [{}] to [{}]", sess.destination, a.tag());
        UdpOutboundHandler::handle(a.as_ref(), sess, None).await
    }
}
