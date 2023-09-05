use std::io;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use crate::{proxy::*, session::*};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub password: String,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, self.address.clone(), self.port)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        mut lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let mut stream =
            stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))?;
        let mut buf = BytesMut::new();
        let password = Sha224::digest(self.password.as_bytes());
        let password = hex::encode(&password[..]);
        buf.put_slice(password.as_bytes());
        buf.put_slice(b"\r\n");
        buf.put_u8(0x01); // tcp
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortLast);
        buf.put_slice(b"\r\n");

        let mut read_buf = Vec::with_capacity(2 * 1024);
        if let Some(lhs) = lhs.as_mut() {
            match tokio::time::timeout(Duration::from_millis(10), lhs.read_buf(&mut read_buf)).await
            {
                Ok(res) => {
                    let n = res?;
                    buf.put_slice(&read_buf[..n]);
                    stream.write_all(&buf).await?;
                }
                Err(_) => {
                    stream.write_all(&buf).await?;
                }
            }
        } else {
            stream.write_all(&buf).await?;
        }

        Ok(Box::new(stream))
    }
}
