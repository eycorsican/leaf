use std::convert::TryFrom;
use std::{io, sync::Arc};

use async_trait::async_trait;

use crate::{
    app::SyncDnsClient,
    proxy::{
        stream::SimpleProxyStream, OutboundConnect, OutboundHandler, ProxyStream, TcpConnector,
        TcpOutboundHandler,
    },
    session::{Session, SocksAddr},
};

pub struct Handler {
    pub actors: Vec<Arc<dyn OutboundHandler>>,
    pub dns_client: SyncDnsClient,
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

    fn next_session(&self, mut sess: Session, start: usize) -> Session {
        if let Some(OutboundConnect::Proxy(address, port, _)) = self.next_tcp_connect_addr(start) {
            if let Ok(addr) = SocksAddr::try_from((address, port)) {
                sess.destination = addr;
            }
        }
        sess
    }
}

impl TcpConnector for Handler {}

#[async_trait]
impl TcpOutboundHandler for Handler {
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
        mut stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        if stream.is_none() {
            match self.tcp_connect_addr() {
                Some(OutboundConnect::Proxy(connect_addr, port, bind_addr)) => {
                    stream.replace(
                        self.dial_tcp_stream(
                            self.dns_client.clone(),
                            &bind_addr,
                            &connect_addr,
                            &port,
                        )
                        .await?,
                    );
                }
                Some(OutboundConnect::Direct(bind_addr)) => {
                    stream.replace(
                        self.dial_tcp_stream(
                            self.dns_client.clone(),
                            &bind_addr,
                            &sess.destination.host(),
                            &sess.destination.port(),
                        )
                        .await?,
                    );
                }
                Some(OutboundConnect::NoConnect) => (),
                _ => {
                    return Err(io::Error::new(io::ErrorKind::Other, "invalid input"));
                }
            }
        }

        for (i, a) in self.actors.iter().enumerate() {
            let new_sess = self.next_session(sess.clone(), i + 1);
            let s = stream.take();
            stream.replace(a.handle_tcp(&new_sess, s).await?);
        }

        if let Some(stream) = stream {
            Ok(Box::new(SimpleProxyStream(stream)))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid input"))
        }
    }
}
