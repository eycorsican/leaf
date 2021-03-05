use std::sync::Arc;
use std::{io, pin::Pin};

use async_trait::async_trait;
use futures::stream::Stream;
use futures::{
    ready,
    task::{Context, Poll},
    Future,
};

use crate::{
    proxy::{
        InboundHandler, InboundTransport, IncomingTransport, ProxyStream, SingleInboundTransport,
        TcpInboundHandler,
    },
    session::Session,
};

pub struct Incoming {
    incoming: IncomingTransport,
    actors: Vec<Arc<dyn InboundHandler>>,
}

impl Incoming {
    pub fn new(incoming: IncomingTransport, actors: Vec<Arc<dyn InboundHandler>>) -> Self {
        Incoming { incoming, actors }
    }
}

impl Stream for Incoming {
    // TODO io::Result<(...)>
    type Item = SingleInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let transport = ready!(Stream::poll_next(Pin::new(&mut self.incoming), cx));
        match transport {
            Some(SingleInboundTransport::Stream(mut stream, mut sess)) => {
                for (_, a) in self.actors.iter().enumerate() {
                    match ready!(Pin::new(&mut a.handle_tcp(sess, stream)).poll(cx)) {
                        Ok(InboundTransport::Stream(new_stream, new_sess)) => {
                            stream = new_stream;
                            sess = new_sess;
                        }
                        Ok(InboundTransport::Datagram(socket)) => {
                            // Assume the last one.
                            return Poll::Ready(Some(SingleInboundTransport::Datagram(socket)));
                        }
                        _ => {
                            log::warn!("unexpected non-stream transport");
                            return Poll::Ready(None);
                        }
                    }
                }
                Poll::Ready(Some(SingleInboundTransport::Stream(stream, sess)))
            }
            None => Poll::Ready(None),
            _ => {
                log::warn!("invalid incoming transport");
                Poll::Ready(None)
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
