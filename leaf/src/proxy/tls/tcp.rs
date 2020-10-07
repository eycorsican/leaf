use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use log::*;

use crate::{
    common::tls::wrap_tls,
    proxy::{ProxyStream, ProxyTcpHandler, SimpleStream},
    session::Session,
};

pub struct Handler {
    pub server_name: String,
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
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        // TODO optimize, dont need copy
        let name = if !&self.server_name.is_empty() {
            self.server_name.clone()
        } else {
            sess.destination.host()
        };
        trace!("wrapping tls with name {}", &name);
        match stream {
            Some(stream) => {
                let tls_stream = wrap_tls(stream, &name).await?;
                return Ok(Box::new(SimpleStream(tls_stream)));
            }
            None => Err(io::Error::new(io::ErrorKind::Other, "invalid tls input")),
        }
    }
}
