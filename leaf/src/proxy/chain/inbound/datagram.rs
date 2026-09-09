use std::io;

use async_trait::async_trait;

use crate::proxy::*;

use super::fold::{fold, Folded};
use super::Incoming;

pub struct Handler {
    pub actors: Vec<AnyInboundHandler>,
}

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound datagram");
        match fold(
            AnyBaseInboundTransport::Datagram(socket, None),
            &self.actors,
            None,
        )
        .await?
        {
            Folded::Done(AnyBaseInboundTransport::Datagram(socket, sess)) => {
                Ok(InboundTransport::Datagram(socket, sess))
            }
            // A datagram actor that hands back a stream: the chain ends there,
            // with the stream, rather than panicking as it used to.
            Folded::Done(AnyBaseInboundTransport::Stream(stream, sess)) => {
                Ok(InboundTransport::Stream(stream, sess))
            }
            Folded::Done(AnyBaseInboundTransport::Empty) => {
                Err(io::Error::other("the chain produced nothing"))
            }
            Folded::Incoming(incoming, next) => Ok(InboundTransport::Incoming(Box::new(
                Incoming::new(incoming, self.actors[next..].to_vec()),
            ))),
        }
    }
}
