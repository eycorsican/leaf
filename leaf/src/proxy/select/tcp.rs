use std::{io, sync::Arc};

use async_trait::async_trait;
use log::*;
use tokio::sync::RwLock;

use crate::{app::outbound::selector::OutboundSelector, proxy::*, session::Session};

pub struct Handler {
    pub selector: Arc<RwLock<OutboundSelector>>,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        if let Some(a) = self.selector.read().await.get_selected() {
            debug!("select handles tcp [{}] to [{}]", sess.destination, a.tag());
            TcpOutboundHandler::handle(a.as_ref(), sess, stream).await
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "no selected outbound"))
        }
    }
}
