use std::io::Result;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::{
    proxy::{stream::SimpleStream, ProxyStream, ProxyTcpHandler},
    session::Session,
};

/// Handler with a redirect target address.
pub struct Handler {
    pub address: String,
    pub port: u16,
}

#[async_trait]
impl ProxyTcpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        None
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> Result<Box<dyn ProxyStream>> {
        let stream = TcpStream::connect(format!("{}:{}", self.address, self.port)).await?;
        Ok(Box::new(SimpleStream(stream)))
    }
}
