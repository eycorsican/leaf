use std::{io, net::SocketAddr};

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;

use super::shadow::ShadowedStream;
use crate::{
    app::SyncDnsClient,
    proxy::{OutboundConnect, ProxyStream, SimpleProxyStream, TcpConnector, TcpOutboundHandler},
    session::{Session, SocksAddrWireType},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    pub bind_addr: SocketAddr,
    pub dns_client: SyncDnsClient,
}

impl TcpConnector for Handler {}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        if !self.address.is_empty() && self.port != 0 {
            Some(OutboundConnect::Proxy(
                self.address.clone(),
                self.port,
                self.bind_addr,
            ))
        } else {
            None
        }
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        let stream = if let Some(stream) = stream {
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
        let mut stream = ShadowedStream::new(stream, &self.cipher, &self.password)?;
        let mut buf = BytesMut::new();
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortLast)?;
        // FIXME combine header and first payload
        stream.write_all(&buf).await?;
        Ok(Box::new(SimpleProxyStream(stream)))
    }
}
