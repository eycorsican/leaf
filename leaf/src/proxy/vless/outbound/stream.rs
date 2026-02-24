use std::io;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use super::super::stream::{build_vless_tcp_header, VlessStream};
use crate::{proxy::*, session::*};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub uuid: String,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, self.address.clone(), self.port)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream session: {:?}", sess);
        let u = Uuid::parse_str(&self.uuid)
            .map_err(|e| io::Error::other(format!("parse uuid failed: {}", e)))?;
        let uuid_bytes = *u.as_bytes();

        let addr_type = match sess.destination.ip() {
            Some(ip) => {
                if ip.is_ipv4() {
                    1
                } else {
                    3
                }
            }
            None => 2,
        };
        let host = sess.destination.host();
        let port = sess.destination.port();

        let header = build_vless_tcp_header(&uuid_bytes, &host, port, addr_type);

        let mut stream = stream.ok_or_else(|| io::Error::other("invalid input"))?;
        stream.write_all(&header).await?;

        Ok(Box::new(VlessStream::new(
            stream,
            uuid_bytes,
            Some(sess.vision_read_raw.clone()),
        )))
    }
}
