use std::io;

use async_trait::async_trait;

use crate::{
    proxy::{InboundTransport, ProxyStream, SimpleProxyStream, TcpInboundHandler},
    session::{Session, SocksAddr, SocksAddrWireType},
};

use super::shadow::ShadowedStream;

pub struct Handler {
    pub cipher: String,
    pub password: String,
}

#[async_trait]
impl TcpInboundHandler for Handler {
    async fn handle_tcp<'a>(
        &'a self,
        mut sess: Session,
        stream: Box<dyn ProxyStream>,
    ) -> io::Result<InboundTransport> {
        let mut stream = ShadowedStream::new(stream, &self.cipher, &self.password)?;
        let destination = SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await?;
        sess.destination = destination;

        Ok(InboundTransport::Stream(
            Box::new(SimpleProxyStream(stream)),
            sess,
        ))
    }
}
