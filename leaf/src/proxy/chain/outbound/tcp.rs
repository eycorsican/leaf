use std::convert::TryFrom;
use std::{io, sync::Arc};

use async_trait::async_trait;

use crate::{
    app::dns_client::DnsClient,
    proxy::{
        stream::SimpleProxyStream, OutboundConnect, OutboundHandler, ProxyStream,
        TcpOutboundHandler,
    },
    session::{Session, SocksAddr},
};

pub struct Handler {
    pub actors: Vec<Arc<dyn OutboundHandler>>,
    pub dns_client: Arc<DnsClient>,
}

impl Handler {
    fn next_tcp_connect_addr(&self, start: usize) -> Option<OutboundConnect> {
        for i in start..self.actors.len() {
            if let Some(addr) = self.actors[i].tcp_connect_addr() {
                return Some(addr);
            }
        }
        None
    }
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
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
        let mut stream = match stream {
            Some(stream) => stream,
            None => match self.tcp_connect_addr() {
                Some(OutboundConnect::Proxy(connect_addr, port, bind_addr)) => {
                    self.dial_tcp_stream(self.dns_client.clone(), &bind_addr, &connect_addr, &port)
                        .await?
                }
                Some(OutboundConnect::Direct(bind_addr)) => {
                    self.dial_tcp_stream(
                        self.dns_client.clone(),
                        &bind_addr,
                        &sess.destination.host(),
                        &sess.destination.port(),
                    )
                    .await?
                }
                None => {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid chain"));
                }
            },
        };

        for (i, a) in self.actors.iter().enumerate() {
            let mut new_sess = sess.clone();
            if let Some(OutboundConnect::Proxy(connect_addr, port, _)) =
                self.next_tcp_connect_addr(i + 1)
            {
                if let Ok(addr) = SocksAddr::try_from(format!("{}:{}", connect_addr, port)) {
                    new_sess.destination = addr;
                }
            }
            stream = a.handle_tcp(&new_sess, Some(stream)).await?;
        }

        return Ok(Box::new(SimpleProxyStream(stream)));
    }
}
