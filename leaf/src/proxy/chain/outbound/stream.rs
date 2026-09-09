use std::io;

use async_trait::async_trait;
use tracing::Instrument;

use crate::{proxy::*, session::Session};

use super::plan::Plan;

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        Plan::for_stream(&self.actors).dial
    }

    /// Runs each actor over what the one before it produced.
    ///
    /// The plan has already decided what each actor is told to reach; all that
    /// is left here is the I/O, in order, with each actor's failure named
    /// after it.
    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        mut lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let plan = Plan::for_stream(&self.actors);
        let last = plan.last();
        let mut stream = stream;

        for stage in &plan.stages {
            // Only the actor that talks to the destination is shown the
            // client's side of the connection: it is the one that can read the
            // first payload and put it in its own handshake.
            let lhs = if stage.index == last {
                lhs.take()
            } else {
                None
            };
            let actor = &self.actors[stage.index];
            let handled = actor
                .stream()
                .map_err(|err| stage.error(err))?
                .handle(&stage.session(sess), lhs, stream.take())
                .instrument(sess.span())
                .await
                .map_err(|err| stage.error(err))?;
            stream.replace(handled);
        }

        stream.ok_or_else(|| io::Error::other("a chain with no actors carries nothing"))
    }
}
