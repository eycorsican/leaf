use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use crate::proxy::InboundHandler;
use crate::proxy::{InboundTransport, TcpInboundHandler};

pub struct Handler {
    pub actors: Vec<Arc<dyn InboundHandler>>,
}

#[async_trait]
impl TcpInboundHandler for Handler {
    async fn handle_tcp<'a>(
        &'a self,
        transport: InboundTransport,
    ) -> std::io::Result<InboundTransport> {
        match transport {
            InboundTransport::Stream(mut stream, mut sess) => {
                for (_, a) in self.actors.iter().enumerate() {
                    let transport = a.handle_tcp(InboundTransport::Stream(stream, sess)).await?;
                    match transport {
                        InboundTransport::Stream(new_stream, new_sess) => {
                            stream = new_stream;
                            sess = new_sess;
                        }
                        InboundTransport::Datagram(socket) => {
                            // FIXME here assumes it's the last actor, it's definitly a wrong assumption,
                            // it's only used for testing the ws+trojan setup
                            return Ok(InboundTransport::Datagram(socket));
                        }
                        _ => {
                            return Err(io::Error::new(io::ErrorKind::Other, "invalid transport"));
                        }
                    }
                }
                Ok(InboundTransport::Stream(stream, sess))
            }
            _ => {
                return Err(io::Error::new(io::ErrorKind::Other, "invalid transport"));
            }
        }
    }
}
