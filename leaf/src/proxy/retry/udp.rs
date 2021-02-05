use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use log::*;

use crate::{
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundHandler, OutboundTransport, UdpOutboundHandler,
        UdpTransportType,
    },
    session::Session,
};

pub struct Handler {
    pub actors: Vec<Arc<dyn OutboundHandler>>,
    pub attempts: usize,
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn udp_connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Unknown
    }

    async fn handle_udp<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<OutboundTransport>,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        for _ in 0..self.attempts {
            for a in self.actors.iter() {
                debug!(
                    "{} handles tcp [{}] to [{}]",
                    self.name(),
                    sess.destination,
                    a.tag()
                );
                match a.handle_udp(sess, None).await {
                    Ok(s) => return Ok(s),
                    Err(_) => continue,
                }
            }
        }
        Err(io::Error::new(io::ErrorKind::Other, "all attempts failed"))
    }
}
