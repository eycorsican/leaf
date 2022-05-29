use std::io;

use async_trait::async_trait;

use crate::{proxy::*, session::Session};

use super::Incoming;

pub struct Handler {
    pub actors: Vec<AnyInboundHandler>,
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        for (i, a) in self.actors.iter().enumerate() {
            let transport = a.stream()?.handle(sess.clone(), stream).await?;
            match transport {
                InboundTransport::Stream(new_stream, new_sess) => {
                    stream = new_stream;
                    sess = new_sess;
                }
                InboundTransport::Datagram(socket, sess) => {
                    // If the input stream has been converted to a datagram,
                    // we assume it's the last actor. Because we can not convert
                    // a datagram back to stream, and can't chain multiple
                    // inbound datagrams for a stream-initiated transport
                    // on a single node.
                    //
                    // TODO Warns if there are further actors in the chain.
                    return Ok(InboundTransport::Datagram(socket, sess));
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
