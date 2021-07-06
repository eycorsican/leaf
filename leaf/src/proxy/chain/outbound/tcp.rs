use std::convert::TryFrom;
use std::io;

use async_trait::async_trait;

use crate::{
    proxy::*,
    session::{Session, SocksAddr},
};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
}

impl Handler {
    fn next_connect_addr(&self, start: usize) -> Option<OutboundConnect> {
        for i in start..self.actors.len() {
            if let Some(addr) = TcpOutboundHandler::connect_addr(self.actors[i].as_ref()) {
                return Some(addr);
            }
        }
        None
    }

    fn next_session(&self, mut sess: Session, start: usize) -> Session {
        if let Some(OutboundConnect::Proxy(address, port)) = self.next_connect_addr(start) {
            if let Ok(addr) = SocksAddr::try_from((address, port)) {
                sess.destination = addr;
            }
        }
        sess
    }
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    type Stream = AnyStream;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        for a in self.actors.iter() {
            if let Some(addr) = TcpOutboundHandler::connect_addr(a.as_ref()) {
                return Some(addr);
            }
        }
        None
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        mut stream: Option<Self::Stream>,
    ) -> io::Result<Self::Stream> {
        match self.connect_addr() {
            Some(OutboundConnect::NoConnect) => (),
            _ => {
                if stream.is_none() {
                    return Err(io::Error::new(io::ErrorKind::Other, "invalid input"));
                }
            }
        }
        for (i, a) in self.actors.iter().enumerate() {
            let new_sess = self.next_session(sess.clone(), i + 1);
            let s = stream.take();
            stream.replace(TcpOutboundHandler::handle(a.as_ref(), &new_sess, s).await?);
        }
        if let Some(stream) = stream {
            Ok(Box::new(stream))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid input"))
        }
    }
}
