use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use crate::proxy::{InboundDatagram, InboundHandler, UdpInboundHandler};

pub struct Handler {
    pub actors: Vec<Arc<dyn InboundHandler>>,
}

#[async_trait]
impl UdpInboundHandler for Handler {
    async fn handle_udp<'a>(
        &'a self,
        mut socket: Box<dyn InboundDatagram>,
    ) -> io::Result<Box<dyn InboundDatagram>> {
        for (_, a) in self.actors.iter().enumerate() {
            socket = a.handle_udp(socket).await?;
        }
        Ok(socket)
    }
}
