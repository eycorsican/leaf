use std::io;

use anyhow::Result;
use async_trait::async_trait;
use bytes::BufMut;
use bytes::BytesMut;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use super::shadow::ShadowedStream;
use crate::{proxy::*, session::*};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    pub prefix: Option<Box<[u8]>>,
}

impl Handler {
    pub fn new(
        address: String,
        port: u16,
        cipher: String,
        password: String,
        prefix: Option<String>,
    ) -> Result<Self> {
        let prefix = prefix
            .as_ref()
            .map(|x| percent_encoding::percent_decode(x.as_bytes()).decode_utf8())
            .transpose()?
            .map(|x| x.to_string().into_bytes().into_boxed_slice());
        Ok(Self {
            address,
            port,
            cipher,
            password,
            prefix,
        })
    }
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
        let stream = stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))?;
        let mut stream = ShadowedStream::new(
            stream,
            &self.cipher,
            &self.password,
            self.prefix.as_ref().cloned(),
        )?;
        let mut buf = BytesMut::new();
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortLast);

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
