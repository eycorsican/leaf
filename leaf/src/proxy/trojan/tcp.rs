use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use socket2::{Domain, Socket, Type};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::{
    common::dns_client::DnsClient,
    // common::tls::wrap_tls,
    proxy::{stream::SimpleStream, ProxyStream, ProxyTcpHandler},
    session::Session,
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub password: String,
    // pub domain: String,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

#[async_trait]
impl ProxyTcpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        Some((self.address.clone(), self.port, self.bind_addr.clone()))
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        if let Some(mut stream) = stream {
            let mut buf = BytesMut::new();
            let password = Sha224::digest(self.password.as_bytes());
            let password = hex::encode(&password[..]);
            buf.put_slice(password.as_bytes());
            buf.put_slice(b"\r\n");
            buf.put_u8(0x01); // tcp
            sess.destination.write_into(&mut buf)?;
            buf.put_slice(b"\r\n");
            stream.write_all(&buf[..]).await?;
            return Ok(stream);
        }

        let ips = match self
            .dns_client
            .lookup_with_bind(String::from(&self.address), &self.bind_addr)
            .await
        {
            Ok(ips) => ips,
            Err(err) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("lookup {} failed: {}", &self.address, err),
                ));
            }
        };

        let mut last_err = None;

        for ip in ips {
            let socket = Socket::new(Domain::ipv4(), Type::stream(), None)?;
            socket.bind(&self.bind_addr.into())?;
            let addr = SocketAddr::new(ip, self.port);
            match TcpStream::connect_std(socket.into_tcp_stream(), &addr).await {
                Ok(mut stream) => {
                    // let mut stream = wrap_tls(stream, &self.domain).await?;

                    let mut buf = BytesMut::new();
                    let password = Sha224::digest(self.password.as_bytes());
                    let password = hex::encode(&password[..]);
                    buf.put_slice(password.as_bytes());
                    buf.put_slice(b"\r\n");
                    buf.put_u8(0x01); // tcp
                    sess.destination.write_into(&mut buf)?;
                    buf.put_slice(b"\r\n");
                    stream.write_all(&buf[..]).await?;
                    return Ok(Box::new(SimpleStream(stream)));
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any address",
            )
        }))
    }
}
