use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;

use crate::{
    app::SyncDnsClient,
    proxy::{OutboundConnect, ProxyStream, SimpleProxyStream, TcpConnector, TcpOutboundHandler},
    session::{Session, SocksAddrWireType},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub password: String,
    pub bind_addr: SocketAddr,
    pub dns_client: SyncDnsClient,
}

impl TcpConnector for Handler {}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Proxy(
            self.address.clone(),
            self.port,
            self.bind_addr,
        ))
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        let mut stream = if let Some(stream) = stream {
            stream
        } else {
            self.dial_tcp_stream(
                self.dns_client.clone(),
                &self.bind_addr,
                &self.address,
                &self.port,
            )
            .await?
        };
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
        Ok(Box::new(SimpleProxyStream(stream)))
    }
}
