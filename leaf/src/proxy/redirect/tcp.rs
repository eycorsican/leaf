use std::io::Result;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::{
    proxy::{stream::SimpleProxyStream, OutboundConnect, ProxyStream, TcpOutboundHandler},
    session::Session,
};

/// Handler with a redirect target address.
pub struct Handler {
    pub address: String,
    pub port: u16,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    async fn handle_tcp<'a>(
        &'a self,
        _sess: &'a Session,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> Result<Box<dyn ProxyStream>> {
        let stream = TcpStream::connect(format!("{}:{}", self.address, self.port)).await?;
        Ok(Box::new(SimpleProxyStream(stream)))
    }
}
