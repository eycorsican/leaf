use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;

use crate::{
    proxy::{ProxyStream, ProxyTcpHandler},
    session::Session,
};

pub struct Handler {}

#[async_trait]
impl ProxyTcpHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        None
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        Err(io::Error::new(io::ErrorKind::Other, "dropped"))
    }
}
