use std::io;

use async_trait::async_trait;
use futures::future::select_ok;

use crate::{app::SyncDnsClient, proxy::*, session::Session};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    pub delay_base: u32,
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
        let mut tasks = Vec::new();
        for (i, a) in self.actors.iter().enumerate() {
            let t = async move {
                if self.delay_base > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        (self.delay_base * i as u32) as u64,
                    ))
                    .await;
                }
                let transport =
                    crate::proxy::connect_udp_outbound(sess, self.dns_client.clone(), a).await?;
                UdpOutboundHandler::handle(a.as_ref(), sess, transport).await
            };
            tasks.push(Box::pin(t));
        }
        match select_ok(tasks.into_iter()).await {
            Ok(v) => Ok(v.0),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("all outbound attempts failed, last error: {}", e),
            )),
        }
    }
}
