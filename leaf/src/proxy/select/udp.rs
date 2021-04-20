use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use log::*;
use tokio::sync::RwLock;

use crate::{
    app::outbound::selector::OutboundSelector,
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundTransport, UdpOutboundHandler, UdpTransportType,
    },
    session::Session,
};

pub struct Handler {
    pub selector: Arc<RwLock<OutboundSelector>>,
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn udp_connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Unknown
    }

    async fn handle_udp<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport>,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        if let Some(a) = self.selector.read().await.get_selected() {
            debug!("select handles tcp [{}] to [{}]", sess.destination, a.tag());
            a.handle_udp(sess, transport).await
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "no selected outbound"))
        }
    }
}
