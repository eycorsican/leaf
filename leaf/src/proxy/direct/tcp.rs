use std::io;

use async_trait::async_trait;

use crate::{proxy::*, session::Session};

pub struct Handler;

#[async_trait]
impl TcpOutboundHandler for Handler {
    type Stream = AnyStream;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Direct)
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        stream: Option<Self::Stream>,
    ) -> io::Result<Self::Stream> {
        stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))
    }
}
