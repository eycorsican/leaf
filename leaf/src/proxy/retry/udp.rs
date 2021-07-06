use std::io;

use async_trait::async_trait;
use log::*;

use crate::{app::SyncDnsClient, proxy::*, session::Session};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    pub attempts: usize,
    pub dns_client: SyncDnsClient,
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    type UStream = AnyStream;
    type Datagram = AnyOutboundDatagram;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Undefined
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<OutboundTransport<Self::UStream, Self::Datagram>>,
    ) -> io::Result<Self::Datagram> {
        for _ in 0..self.attempts {
            for a in self.actors.iter() {
                debug!("retry handles tcp [{}] to [{}]", sess.destination, a.tag());
                let transport =
                    crate::proxy::connect_udp_outbound(sess, self.dns_client.clone(), a).await?;
                match UdpOutboundHandler::handle(a.as_ref(), sess, transport).await {
                    Ok(s) => return Ok(s),
                    Err(_) => continue,
                }
            }
        }
        Err(io::Error::new(io::ErrorKind::Other, "all attempts failed"))
    }
}
