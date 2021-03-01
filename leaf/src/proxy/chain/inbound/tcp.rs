use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    proxy::{InboundHandler, InboundTransport, ProxyStream, TcpInboundHandler},
    session::Session,
};

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
        for (_, a) in self.actors.iter().enumerate() {
            let transport = a.handle_tcp(sess, stream).await?;
            match transport {
                InboundTransport::Stream(new_stream, new_sess) => {
                    stream = new_stream;
                    sess = new_sess;
                }
                InboundTransport::Datagram(socket) => {
                    // If the input stream has been converted to a datagram,
                    // we assume it's the last actor.
                    return Ok(InboundTransport::Datagram(socket));
                }
                _ => {
                    return Err(io::Error::new(io::ErrorKind::Other, "invalid transport"));
                }
            }
        }
        Ok(InboundTransport::Stream(stream, sess))
    }
}
