use std::sync::Arc;
use std::{io, pin::Pin};

use async_trait::async_trait;
use futures::stream::Stream;
use futures::{
    ready,
    task::{Context, Poll},
};

use crate::{
    proxy::{
        InboundHandler, InboundTransport, ProxyStream, SimpleProxyStream, SingleInboundTransport,
        TcpInboundHandler,
    },
    session::Session,
};

use super::MuxAcceptor;
use super::MuxSession;

pub struct Incoming {
    sess: Session,
    acceptor: MuxAcceptor,
}

impl Incoming {
    pub fn new(sess: Session, conn: Box<dyn ProxyStream>) -> Self {
        Incoming {
            sess,
            acceptor: MuxSession::acceptor(conn),
        }
    }
}

impl Stream for Incoming {
    type Item = SingleInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(
            ready!(Pin::new(&mut self.acceptor).poll_next(cx)).map(|stream| {
                let mut sess = self.sess.clone();
                sess.stream_id = Some(stream.id());
                SingleInboundTransport::Stream(Box::new(SimpleProxyStream(stream)), sess)
            }),
        )
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
    ) -> io::Result<InboundTransport> {
        for (_, a) in self.actors.iter().enumerate() {
            match a.handle_tcp(sess, stream).await? {
                InboundTransport::Stream(new_stream, new_sess) => {
                    stream = new_stream;
                    sess = new_sess;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "invalid amux transport",
                    ));
                }
            }
        }
        Ok(InboundTransport::Incoming(Box::new(Incoming::new(
            sess, stream,
        ))))
    }
}
