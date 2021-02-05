use std::{io, sync::Arc};

use async_trait::async_trait;
use log::*;

use crate::{
    proxy::{OutboundConnect, OutboundHandler, ProxyStream, TcpOutboundHandler},
    session::Session,
};

pub struct Handler {
    pub actors: Vec<Arc<dyn OutboundHandler>>,
    pub attempts: usize,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        for _ in 0..self.attempts {
            for a in self.actors.iter() {
                debug!(
                    "{} handles tcp [{}] to [{}]",
                    self.name(),
                    sess.destination,
                    a.tag()
                );
                match a.handle_tcp(sess, None).await {
                    Ok(s) => return Ok(s),
                    Err(_) => continue,
                }
            }
        }
        Err(io::Error::new(io::ErrorKind::Other, "all attempts failed"))
    }
}
