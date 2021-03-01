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
    ) -> std::io::Result<InboundTransport> {
        let mut stream =
            ShadowedStream::new(stream, &self.cipher, &self.password).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("create shadowsocks stream failed: {}", e),
                )
            })?;
        let destination = match SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await
        {
            Ok(v) => v,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("read address failed: {}", e),
                ));
            }
        };
        sess.destination = destination;

        Ok(InboundTransport::Stream(
            Box::new(SimpleProxyStream(stream)),
            sess,
        ))
    }
}
