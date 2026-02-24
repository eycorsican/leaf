use std::io;

use async_trait::async_trait;

use crate::{proxy::*, session::*};

/// Handler with a redirect target address.
pub struct Handler {
    pub address: String,
    pub port: u16,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, self.address.clone(), self.port)
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream session: {:?}", _sess);
        stream.ok_or_else(|| io::Error::other("invalid input"))
    }
}
