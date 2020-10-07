use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use socket2::{Domain, Socket, Type};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::{
    common::dns_client::DnsClient,
    proxy::{stream::SimpleStream, ProxyStream, ProxyTcpHandler},
    session::{Session, SocksAddr},
};

use super::SocksAddr as VLessSocksAddr;
use super::*;

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub uuid: String,
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
        let uuid = if let Ok(v) = Uuid::parse_str(&self.uuid) {
            v
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid uuid"));
        };
        let target = match &sess.destination {
            SocksAddr::Ip(addr) => VLessSocksAddr::from(addr),
            SocksAddr::Domain(domain, port) => match VLessSocksAddr::try_from((domain, *port)) {
                Ok(addr) => addr,
                Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "invalid destination")),
            },
        };

        if let Some(mut stream) = stream {
            let mut buf = BytesMut::new();
            buf.put_u8(0x0); // version
            buf.put_slice(uuid.as_bytes()); // uuid
            buf.put_u8(0x0); // addons
            buf.put_u8(0x01); // tcp command
            target.write_into(&mut buf)?;
            stream.write_all(&buf[..]).await?;

            let stream = VLessAuthStream::new(stream);

            return Ok(Box::new(SimpleStream(stream)));
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
                    let mut buf = BytesMut::new();
                    buf.put_u8(0x0); // version
                    buf.put_slice(uuid.as_bytes()); // uuid
                    buf.put_u8(0x0); // addons
                    buf.put_u8(0x01); // tcp command
                    target.write_into(&mut buf)?;
                    stream.write_all(&buf[..]).await?;

                    let stream = VLessAuthStream::new(stream);

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
