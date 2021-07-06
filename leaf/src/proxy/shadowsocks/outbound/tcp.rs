use std::io;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;

use super::shadow::ShadowedStream;
use crate::{
    proxy::*,
    session::{Session, SocksAddrWireType},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    type Stream = AnyStream;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Proxy(self.address.clone(), self.port))
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Self::Stream>,
    ) -> io::Result<Self::Stream> {
        let stream = stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))?;
        let mut stream = ShadowedStream::new(stream, &self.cipher, &self.password)?;
        let mut buf = BytesMut::new();
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortLast)?;
        // FIXME combine header and first payload
        stream.write_all(&buf).await?;
        Ok(Box::new(stream))
    }
}
