use std::io;

use async_trait::async_trait;

use crate::{proxy::*, session::Session};

pub struct Handler;

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Direct
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))
    }
}
