use async_trait::async_trait;

use crate::{
    proxy::*,
    session::{Session, SocksAddr, SocksAddrWireType},
};

use super::shadow::ShadowedStream;

pub struct Handler {
    pub cipher: String,
    pub password: String,
}

#[async_trait]
impl TcpInboundHandler for Handler {
    type TStream = AnyStream;
    type TDatagram = AnyInboundDatagram;

    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        stream: Self::TStream,
    ) -> std::io::Result<InboundTransport<Self::TStream, Self::TDatagram>> {
        let mut stream = ShadowedStream::new(stream, &self.cipher, &self.password)?;
        let destination = SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await?;
        sess.destination = destination;

        Ok(InboundTransport::Stream(Box::new(stream), sess))
    }
}
