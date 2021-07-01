use std::sync::atomic::{AtomicUsize, Ordering};
use std::{io, sync::Arc};

use async_trait::async_trait;
use log::*;

use crate::{
    proxy::{OutboundConnect, OutboundHandler, ProxyStream, TcpOutboundHandler},
    session::Session,
};

pub struct Handler {
    pub actors: Vec<Arc<dyn OutboundHandler>>,
    pub next: AtomicUsize,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        let current = self.next.load(Ordering::Relaxed);
        let a = &self.actors[current];
        let next = if current >= self.actors.len() - 1 {
            0
        } else {
            current + 1
        };
        self.next.store(next, Ordering::Relaxed);
        debug!("rr handles tcp [{}] to [{}]", sess.destination, a.tag());
        TcpOutboundHandler::handle(a.as_ref(), sess, None).await
    }
}
