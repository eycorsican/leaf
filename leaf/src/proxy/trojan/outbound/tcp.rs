use std::io;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;

use crate::{
    proxy::*,
    session::{Session, SocksAddrWireType},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
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
        let mut stream =
            stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))?;
        let mut buf = BytesMut::new();
        let password = Sha224::digest(self.password.as_bytes());
        let password = hex::encode(&password[..]);
        buf.put_slice(password.as_bytes());
        buf.put_slice(b"\r\n");
        buf.put_u8(0x01); // tcp
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortLast)?;
        buf.put_slice(b"\r\n");
        // FIXME combine header and first payload
        stream.write_all(&buf).await?;
        Ok(Box::new(stream))
    }
}
