use std::{io, pin::Pin};

use futures::stream::Stream;
use futures::{
    future::BoxFuture,
    ready,
    task::{Context, Poll},
};
use tracing::{debug, warn};

use crate::proxy::*;

mod datagram;
mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

enum State {
    WaitingIncoming,
    Pending(usize, BoxFuture<'static, io::Result<AnyInboundTransport>>),
}

pub struct Incoming {
    incoming: AnyIncomingTransport,
    actors: Vec<AnyInboundHandler>,
    state: State,
}

impl Incoming {
    pub fn new(incoming: AnyIncomingTransport, actors: Vec<AnyInboundHandler>) -> Self {
        Incoming {
            incoming,
            actors,
            state: State::WaitingIncoming,
        }
    }
}

impl Stream for Incoming {
    // TODO io::Result<(...)>
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.state {
                // Polling for the underlying transport.
                State::WaitingIncoming => {
                    let transport = ready!(Stream::poll_next(Pin::new(&mut self.incoming), cx));
                    match transport {
                        // Only reliable transports are eligible to handle TCP requests.
                        Some(AnyBaseInboundTransport::Stream(stream, sess)) => {
                            assert!(!self.actors.is_empty()); // FIXME
                            let sess = sess.clone();
                            let a = self.actors[0].clone();
                            // Create the task for handling the first actor.
                            let t = Box::pin(async move { a.stream()?.handle(sess, stream).await });
                            self.state = State::Pending(0, t);
                        }
                        Some(_) => {
                            warn!("unexpected non-stream chain inbound incoming transport");
                            continue;
                        }
                        None => {
                            return Poll::Ready(None);
                        }
                    }
                }
                // Polling for output transport from actors[idx].
                State::Pending(idx, ref mut task) => {
                    match ready!(task.as_mut().poll(cx)) {
                        Ok(InboundTransport::Stream(new_stream, new_sess)) => {
                            // If this is the output transport from the task of the last actor,
                            // return it.
                            if idx + 1 >= self.actors.len() {
                                self.state = State::WaitingIncoming;
                                return Poll::Ready(Some(AnyBaseInboundTransport::Stream(
                                    new_stream, new_sess,
                                )));
                            }
                            // Otherwise proceed with a new task for the next actor.
                            let new_sess = new_sess.clone();
                            let a = self.actors[idx + 1].clone();
                            let t =
                                Box::pin(
                                    async move { a.stream()?.handle(new_sess, new_stream).await },
                                );
                            self.state = State::Pending(idx + 1, t);
                        }
                        Ok(InboundTransport::Datagram(socket, sess)) => {
                            // FIXME Assume the last one, but not necessary the last one?
                            self.state = State::WaitingIncoming;
                            return Poll::Ready(Some(AnyBaseInboundTransport::Datagram(
                                socket, sess,
                            )));
                        }
                        Err(e) => {
                            debug!("chain inbound incoming error: {}", e);
                            self.state = State::WaitingIncoming;
                            continue;
                        }
                        _ => {
                            warn!("unexpected chain inbound incoming transport");
                            self.state = State::WaitingIncoming;
                            return Poll::Ready(None);
                        }
                    }
                }
            }
        }
    }
}
