use std::{io, pin::Pin, time::Duration};

use futures::stream::{FuturesUnordered, Stream};
use futures::{
    future::BoxFuture,
    task::{Context, Poll},
};
use tracing::debug;

use crate::proxy::*;

mod datagram;
mod fold;
mod stream;

use fold::{fold, Folded};

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

enum State {
    Running,
    Closed,
}

pub struct Incoming {
    incoming: AnyIncomingTransport,
    actors: Vec<AnyInboundHandler>,
    pending: FuturesUnordered<BoxFuture<'static, io::Result<AnyBaseInboundTransport>>>,
    state: State,
}

impl Incoming {
    pub fn new(incoming: AnyIncomingTransport, actors: Vec<AnyInboundHandler>) -> Self {
        Incoming {
            incoming,
            actors,
            pending: FuturesUnordered::new(),
            state: State::Running,
        }
    }
}

/// Runs the actors that had not run when a multiplexed transport appeared,
/// once for every transport it yields.
async fn run_actors(
    transport: AnyBaseInboundTransport,
    actors: Vec<AnyInboundHandler>,
    handshake_timeout: Duration,
) -> io::Result<AnyBaseInboundTransport> {
    match fold(transport, &actors, Some(handshake_timeout)).await? {
        Folded::Done(transport) => Ok(transport),
        // Neither shape of chain unwraps one of these inside another, and a
        // silent failure here would look like a connection that never arrived.
        Folded::Incoming(..) => Err(io::Error::other(
            "a multiplexed transport inside another one is not supported",
        )),
    }
}

impl Stream for Incoming {
    // TODO io::Result<(...)>
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let max_concurrency = (*crate::option::INCOMING_ACCEPT_CONCURRENCY).max(1);
        let handshake_timeout = Duration::from_secs(*crate::option::INBOUND_ACCEPT_TIMEOUT);

        loop {
            while matches!(self.state, State::Running) && self.pending.len() < max_concurrency {
                match Stream::poll_next(Pin::new(&mut self.incoming), cx) {
                    Poll::Ready(Some(transport)) => {
                        let actors = self.actors.clone();
                        self.pending.push(Box::pin(run_actors(
                            transport,
                            actors,
                            handshake_timeout,
                        )));
                    }
                    Poll::Ready(None) => {
                        self.state = State::Closed;
                        break;
                    }
                    Poll::Pending => break,
                }
            }

            match Stream::poll_next(Pin::new(&mut self.pending), cx) {
                Poll::Ready(Some(Ok(transport))) => {
                    return Poll::Ready(Some(transport));
                }
                Poll::Ready(Some(Err(e))) => {
                    debug!("chain inbound incoming error: {}", e);
                    continue;
                }
                Poll::Ready(None) if matches!(self.state, State::Closed) => {
                    return Poll::Ready(None);
                }
                Poll::Ready(None) | Poll::Pending => {
                    if matches!(self.state, State::Closed) && self.pending.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use futures::StreamExt;
    use tokio::io::duplex;
    use tokio::time::timeout;

    use crate::proxy::inbound::Handler as InboundHandlerImpl;
    use crate::session::StreamId;

    use super::*;

    struct DelayByStreamIdHandler;

    #[async_trait]
    impl InboundStreamHandler for DelayByStreamIdHandler {
        async fn handle<'a>(
            &'a self,
            sess: Session,
            stream: AnyStream,
        ) -> io::Result<AnyInboundTransport> {
            let delay = match sess.stream_id {
                Some(StreamId::U64(1)) => Duration::from_millis(200),
                Some(StreamId::U64(2)) => Duration::from_millis(10),
                _ => Duration::from_millis(0),
            };
            tokio::time::sleep(delay).await;
            Ok(InboundTransport::Stream(stream, sess))
        }
    }

    #[tokio::test]
    async fn incoming_does_not_block_fast_streams_behind_slow_ones() {
        let actor: AnyInboundHandler = Arc::new(InboundHandlerImpl::new(
            "mock".to_string(),
            Some(Arc::new(DelayByStreamIdHandler)),
            None,
        ));
        let actors = vec![actor];

        let (stream1, _) = duplex(64);
        let (stream2, _) = duplex(64);

        let mut sess1 = Session::default();
        sess1.stream_id = Some(StreamId::U64(1));
        let mut sess2 = Session::default();
        sess2.stream_id = Some(StreamId::U64(2));

        let incoming = futures::stream::iter(vec![
            AnyBaseInboundTransport::Stream(Box::new(stream1), sess1),
            AnyBaseInboundTransport::Stream(Box::new(stream2), sess2),
        ]);
        let mut incoming = Incoming::new(Box::new(incoming), actors);

        let first = timeout(Duration::from_millis(100), incoming.next())
            .await
            .expect("fast stream should not be blocked")
            .expect("stream should be yielded");

        match first {
            AnyBaseInboundTransport::Stream(_, sess) => {
                assert_eq!(sess.stream_id, Some(StreamId::U64(2)));
            }
            _ => panic!("expected stream transport"),
        }
    }
}
