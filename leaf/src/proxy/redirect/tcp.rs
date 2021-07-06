use std::io;

use async_trait::async_trait;

use crate::{proxy::*, session::Session};

/// Handler with a redirect target address.
pub struct Handler {
    pub address: String,
    pub port: u16,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    type Stream = AnyStream;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Proxy(self.address.clone(), self.port))
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        stream: Option<Self::Stream>,
    ) -> io::Result<Self::Stream> {
        stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))
    }
}
