use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::BytesMut;

use super::shadow::ShadowedStream;
use crate::{
    app::dns_client::DnsClient,
    proxy::{BufHeadProxyStream, OutboundConnect, ProxyStream, TcpConnector, TcpOutboundHandler},
    session::{Session, SocksAddrWireType},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

impl TcpConnector for Handler {}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

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
        let stream = ShadowedStream::new(stream, &self.cipher, &self.password).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("create shadowsocks stream failed: {}", e),
            )
        })?;
        let mut buf = BytesMut::new();
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortLast)?;
        // FIXME receive-only conns
        Ok(Box::new(BufHeadProxyStream::new(stream, buf.freeze())))
    }
}
