use std::io;

use async_trait::async_trait;
use log::*;

use crate::{
    proxy::{InboundTransport, SimpleProxyStream, TcpInboundHandler},
    session::{SocksAddr, SocksAddrWireType},
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
        transport: InboundTransport,
    ) -> std::io::Result<InboundTransport> {
        if let InboundTransport::Stream(stream, mut sess) = transport {
            let mut stream =
                ShadowedStream::new(stream, &self.cipher, &self.password).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("create shadowsocks stream failed: {}", e),
                    )
                })?;
            let destination =
                match SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("read address failed: {}", e);
                        return Err(io::Error::new(io::ErrorKind::Other, "unspecified"));
                    }
                };
            sess.destination = destination;

            Ok(InboundTransport::Stream(
                Box::new(SimpleProxyStream(stream)),
                sess,
            ))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid transport"))
        }
    }
}
