use std::io;

use async_trait::async_trait;
use log::*;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{app::SyncDnsClient, proxy::*, session::Session};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
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
        let mut rng = StdRng::from_entropy();
        let i: usize = rng.gen_range(0..self.actors.len());
        debug!(
            "random handles tcp [{}] to [{}]",
            sess.destination,
            self.actors[i].tag()
        );
        let stream =
            crate::proxy::connect_tcp_outbound(sess, self.dns_client.clone(), &self.actors[i])
                .await?;
        TcpOutboundHandler::handle(self.actors[i].as_ref(), sess, stream).await
    }
}
