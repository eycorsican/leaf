use std::io;

use async_trait::async_trait;

use crate::{proxy::*, session::Session};

use super::fold::{fold, Folded};
use super::Incoming;

pub struct Handler {
    pub actors: Vec<AnyInboundHandler>,
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        match fold(
            AnyBaseInboundTransport::Stream(stream, sess),
            &self.actors,
            None,
        )
        .await?
        {
            Folded::Done(AnyBaseInboundTransport::Stream(stream, sess)) => {
                Ok(InboundTransport::Stream(stream, sess))
            }
            Folded::Done(AnyBaseInboundTransport::Datagram(socket, sess)) => {
                Ok(InboundTransport::Datagram(socket, sess))
            }
            Folded::Done(AnyBaseInboundTransport::Empty) => {
                Err(io::Error::other("the chain produced nothing"))
            }
            // The actors that have not run belong to each transport this one
            // yields, not to the thing yielding them.
            Folded::Incoming(incoming, next) => Ok(InboundTransport::Incoming(Box::new(
                Incoming::new(incoming, self.actors[next..].to_vec()),
            ))),
        }
    }
}
