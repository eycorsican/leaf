use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use futures::TryFutureExt;
use log::*;

use crate::{
    common::tls,
    proxy::{ProxyStream, ProxyTcpHandler},
    session::Session,
};

pub struct Handler {
    pub server_name: String,
    pub alpns: Vec<String>,
}

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
                let tls_stream = tls::wrapper::wrap_tls(stream, &name, self.alpns.clone())
                    .map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, format!("wrap tls failed: {}", e))
                    })
                    .await?;
                Ok(tls_stream)
            }
            None => Err(io::Error::new(io::ErrorKind::Other, "invalid tls input")),
        }
    }
}
