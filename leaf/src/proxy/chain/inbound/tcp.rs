use std::sync::Arc;
use std::{io, pin::Pin};

use async_trait::async_trait;
use futures::stream::Stream;
use futures::{
    future::BoxFuture,
    ready,
    task::{Context, Poll},
};

use crate::{
    proxy::{
        InboundHandler, InboundTransport, IncomingTransport, ProxyStream, SingleInboundTransport,
        TcpInboundHandler,
    },
    session::Session,
};

enum State {
    WaitingIncoming,
    Pending(usize, BoxFuture<'static, io::Result<InboundTransport>>),
}

pub struct Incoming {
    incoming: IncomingTransport,
    actors: Vec<Arc<dyn InboundHandler>>,
    state: State,
}

impl Incoming {
    pub fn new(incoming: IncomingTransport, actors: Vec<Arc<dyn InboundHandler>>) -> Self {
        Incoming {
            incoming,
            actors,
            state: State::WaitingIncoming,
        }
    }
}

impl Stream for Incoming {
    // TODO io::Result<(...)>
    type Item = SingleInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.state {
                // Polling for the underlying transport.
                State::WaitingIncoming => {
                    let transport = ready!(Stream::poll_next(Pin::new(&mut self.incoming), cx));
                    match transport {
                        // Only reliable transports are eligible to handle TCP requests.
                        Some(SingleInboundTransport::Stream(stream, sess)) => {
                            assert!(self.actors.len() > 0); // FIXME
                            let sess = sess.clone();
                            let a = self.actors[0].clone();
                            // Create the task for handling the first actor.
                            let t = Box::pin(async move { a.handle_tcp(sess, stream).await });
                            self.state = State::Pending(0, t);
                        }
                        Some(_) => {
                            return Poll::Ready(None);
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
                                return Poll::Ready(Some(SingleInboundTransport::Stream(
                                    new_stream, new_sess,
                                )));
                            }
                            // Otherwise proceed with a new task for the next actor.
                            let new_sess = new_sess.clone();
                            let a = self.actors[idx + 1].clone();
                            let t =
                                Box::pin(async move { a.handle_tcp(new_sess, new_stream).await });
                            self.state = State::Pending(idx + 1, t);
                        }
                        Ok(InboundTransport::Datagram(socket)) => {
                            // FIXME Assume the last one, but not necessary the last one?
                            self.state = State::WaitingIncoming;
                            return Poll::Ready(Some(SingleInboundTransport::Datagram(socket)));
                        }
                        _ => {
                            log::warn!("unexpected non-stream transport");
                            self.state = State::WaitingIncoming;
                            return Poll::Ready(None);
                        }
                    }
                }
            }
        }
    }
}

pub struct Handler {
    pub actors: Vec<Arc<dyn InboundHandler>>,
}

#[async_trait]
impl TcpInboundHandler for Handler {
    async fn handle_tcp<'a>(
        &'a self,
        mut sess: Session,
        mut stream: Box<dyn ProxyStream>,
    ) -> std::io::Result<InboundTransport> {
        for (i, a) in self.actors.iter().enumerate() {
            let transport = a.handle_tcp(sess.clone(), stream).await?;
            match transport {
                InboundTransport::Stream(new_stream, new_sess) => {
                    stream = new_stream;
                    sess = new_sess;
                }
                InboundTransport::Datagram(socket) => {
                    // If the input stream has been converted to a datagram,
                    // we assume it's the last actor. Because we can not convert
                    // a datagram back to stream, and can't chain multiple
                    // inbound datagrams for a stream-initiated transport
                    // on a single node.
                    //
                    // TODO Warns if there are further actors in the chain.
                    return Ok(InboundTransport::Datagram(socket));
                }
                InboundTransport::Incoming(incoming) => {
                    return Ok(InboundTransport::Incoming(Box::new(Incoming::new(
                        incoming,
                        self.actors[i + 1..].to_vec(), // FIXME oob check
                    ))));
                }
                _ => {
                    return Err(io::Error::new(io::ErrorKind::Other, "invalid transport"));
                }
            }
        }
        Ok(InboundTransport::Stream(stream, sess))
    }
}
