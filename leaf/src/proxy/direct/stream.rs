use std::io;

use async_trait::async_trait;

use crate::{proxy::*, session::Session};

pub struct Handler {
    pub interface: Option<String>,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Direct(self.interface.as_ref().map(|x| x.as_str().into()))
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))
    }
}
