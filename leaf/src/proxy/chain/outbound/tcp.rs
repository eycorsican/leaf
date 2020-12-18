use std::convert::TryFrom;
use std::net::SocketAddr;
use std::{io, sync::Arc};

use async_trait::async_trait;

use crate::{
    app::dns_client::DnsClient,
    proxy::{stream::SimpleProxyStream, OutboundHandler, ProxyStream, TcpOutboundHandler},
    session::{Session, SocksAddr},
};

pub struct Handler {
    pub actors: Vec<Arc<dyn OutboundHandler>>,
    pub dns_client: Arc<DnsClient>,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        for a in self.actors.iter() {
            if let Some(addr) = a.tcp_connect_addr() {
                return Some(addr);
            }
        }
        None
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        if let Some(mut stream) = stream {
            for (i, a) in self.actors.iter().enumerate() {
                let mut new_sess = sess.clone();
                for j in (i + 1)..self.actors.len() {
                    if let Some((connect_addr, port, _)) = self.actors[j].tcp_connect_addr() {
                        if let Ok(addr) = SocksAddr::try_from(format!("{}:{}", connect_addr, port))
                        {
                            new_sess.destination = addr;
                        }
                    }
                }
                stream = a.handle_tcp(&new_sess, Some(stream)).await?;
            }

            return Ok(Box::new(SimpleProxyStream(stream)));
        }

        for a in self.actors.iter() {
            if let Some((connect_addr, port, bind_addr)) = a.tcp_connect_addr() {
                let mut stream = self
                    .dial_tcp_stream(self.dns_client.clone(), &bind_addr, &connect_addr, &port)
                    .await?;

                for (i, a) in self.actors.iter().enumerate() {
                    let mut new_sess = sess.clone();
                    for j in (i + 1)..self.actors.len() {
                        if let Some((connect_addr, port, _)) = self.actors[j].tcp_connect_addr() {
                            if let Ok(addr) =
                                SocksAddr::try_from(format!("{}:{}", connect_addr, port))
                            {
                                new_sess.destination = addr;
                                break;
                            }
                        }
                    }
                    stream = a.handle_tcp(&new_sess, Some(stream)).await?;
                }

                return Ok(Box::new(SimpleProxyStream(stream)));
            }
        }
        Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid chain"))
    }
}
