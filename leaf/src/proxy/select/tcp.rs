use std::sync::atomic::{AtomicUsize, Ordering};
use std::{io, sync::Arc};

use async_trait::async_trait;

use crate::{proxy::*, session::Session};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    pub selected: Arc<AtomicUsize>,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        let a = &self.actors[self.selected.load(Ordering::Relaxed)];
        match a.tcp() {
            Ok(h) => return h.connect_addr(),
            _ => match a.udp() {
                Ok(h) => return h.connect_addr(),
                _ => (),
            },
        }
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let a = &self.actors[self.selected.load(Ordering::Relaxed)];
        log::debug!("select handles to [{}]", a.tag());
        a.tcp()?.handle(sess, stream).await
    }
}
