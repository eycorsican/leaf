use std::io;

use async_trait::async_trait;

use crate::proxy::*;

use super::Incoming;

pub struct Handler {
    pub actors: Vec<AnyInboundHandler>,
}

#[async_trait]
impl UdpInboundHandler for Handler {
    type UStream = AnyStream;
    type UDatagram = AnyInboundDatagram;

    async fn handle<'a>(
        &'a self,
        mut socket: Self::UDatagram,
    ) -> io::Result<InboundTransport<Self::UStream, Self::UDatagram>> {
        for (i, a) in self.actors.iter().enumerate() {
            let transport = UdpInboundHandler::handle(a.as_ref(), socket).await?;
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
