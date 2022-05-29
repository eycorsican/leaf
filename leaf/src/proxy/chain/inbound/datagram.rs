use std::io;

use async_trait::async_trait;

use crate::proxy::*;

use super::Incoming;

pub struct Handler {
    pub actors: Vec<AnyInboundHandler>,
}

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut socket: AnyInboundDatagram,
    ) -> io::Result<AnyInboundTransport> {
        let mut sess: Option<Session> = None;
        for (i, a) in self.actors.iter().enumerate() {
            let transport = a.datagram()?.handle(socket).await?;
            match transport {
                InboundTransport::Stream(..) => {
                    unimplemented!();
                }
                InboundTransport::Datagram(new_socket, new_sess) => {
                    socket = new_socket;
                    sess = new_sess;
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
        Ok(InboundTransport::Datagram(socket, sess))
    }
}
