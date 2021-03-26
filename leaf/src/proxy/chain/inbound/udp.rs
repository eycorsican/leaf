use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use crate::proxy::{InboundDatagram, InboundHandler, InboundTransport, UdpInboundHandler};

use super::Incoming;

pub struct Handler {
    pub actors: Vec<Arc<dyn InboundHandler>>,
}

#[async_trait]
impl UdpInboundHandler for Handler {
    async fn handle_udp<'a>(
        &'a self,
        mut socket: Box<dyn InboundDatagram>,
    ) -> io::Result<InboundTransport> {
        for (i, a) in self.actors.iter().enumerate() {
            let transport = a.handle_udp(socket).await?;
            match transport {
                InboundTransport::Stream(..) => {
                    unimplemented!();
                }
                InboundTransport::Datagram(new_socket) => {
                    socket = new_socket;
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
        Ok(InboundTransport::Datagram(socket))
    }
}
