use std::io;

use async_trait::async_trait;
use log::*;

use crate::{app::SyncDnsClient, proxy::*, session::Session};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    pub attempts: usize,
    pub dns_client: SyncDnsClient,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    type Stream = AnyStream;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _stream: Option<Self::Stream>,
    ) -> io::Result<Self::Stream> {
        for _ in 0..self.attempts {
            for a in self.actors.iter() {
                debug!("retry handles tcp [{}] to [{}]", sess.destination, a.tag());
                let stream =
                    crate::proxy::connect_tcp_outbound(sess, self.dns_client.clone(), a).await?;
                match TcpOutboundHandler::handle(a.as_ref(), sess, stream).await {
                    Ok(s) => return Ok(s),
                    Err(_) => continue,
                }
            }
        }
        Err(io::Error::new(io::ErrorKind::Other, "all attempts failed"))
    }
}
