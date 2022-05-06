use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use crate::{proxy::*, session::Session};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    pub selected: Arc<AtomicUsize>,
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        let a = &self.actors[self.selected.load(Ordering::Relaxed)];
        match a.udp() {
            Ok(h) => return h.connect_addr(),
            _ => match a.tcp() {
                Ok(h) => return h.connect_addr(),
                _ => (),
            },
        }
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        let a = &self.actors[self.selected.load(Ordering::Relaxed)];
        a.udp()
            .map(|x| x.transport_type())
            .unwrap_or(DatagramTransportType::Unknown)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let a = &self.actors[self.selected.load(Ordering::Relaxed)];
        log::debug!("select handles to [{}]", a.tag());
        a.udp()?.handle(sess, transport).await
    }
}
