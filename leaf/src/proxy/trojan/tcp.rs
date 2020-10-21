use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;

use crate::{
    common::dns_client::DnsClient,
    proxy::{ProxyStream, ProxyTcpHandler},
    session::{Session, SocksAddrWireType},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub password: String,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

#[async_trait]
impl ProxyTcpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        Some((self.address.clone(), self.port, self.bind_addr.clone()))
    }

    async fn handle<'a>(
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
        stream.write_all(&buf[..]).await?;
        Ok(stream)
    }
}
