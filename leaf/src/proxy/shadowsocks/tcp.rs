use std::{
    convert::TryFrom,
    io::{self, Error, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use log::*;
use socket2::{Domain, Socket, Type};
use tokio::net::TcpStream;

use super::AeadCipher;
use super::ShadowedStream;
use super::SocksAddr as SSSocksAddr;
use crate::{
    common::dns_client::DnsClient,
    proxy::{stream::SimpleStream, ProxyStream, ProxyTcpHandler},
    session::{Session, SocksAddr},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
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
        if let Some(stream) = stream {
            let cipher = if let Some(c) = AeadCipher::new(&self.cipher, &self.password) {
                c
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "unable to create aead cipher",
                ));
            };
            let cipher = Box::new(cipher);
            let mut stream = ShadowedStream::new(stream, cipher);
            let target = match &sess.destination {
                SocksAddr::Ip(addr) => SSSocksAddr::from(addr),
                SocksAddr::Domain(domain, port) => match SSSocksAddr::try_from((domain, *port)) {
                    Ok(addr) => addr,
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("invalid destination: {}", e),
                        ));
                    }
                },
            };
            target.write_to(&mut stream).await?;
            return Ok(Box::new(SimpleStream(stream)));
        }

        let ips = match self
            .dns_client
            .lookup_with_bind(String::from(&self.address), &self.bind_addr)
            .await
        {
            Ok(ips) => ips,
            Err(err) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("lookup failed: {}", err),
                ));
            }
        };

        let mut last_err = None;

        for ip in ips {
            let socket = Socket::new(Domain::ipv4(), Type::stream(), None)?;
            socket.bind(&self.bind_addr.into())?;
            let addr = SocketAddr::new(ip, self.port);
            match TcpStream::connect_std(socket.into_tcp_stream(), &addr).await {
                Ok(stream) => {
                    let cipher = if let Some(c) = AeadCipher::new(&self.cipher, &self.password) {
                        c
                    } else {
                        warn!("unable to create aead cipher");
                        continue;
                    };
                    let cipher = Box::new(cipher);
                    let mut stream = ShadowedStream::new(stream, cipher);
                    let target = match &sess.destination {
                        SocksAddr::Ip(addr) => SSSocksAddr::from(addr),
                        SocksAddr::Domain(domain, port) => {
                            match SSSocksAddr::try_from((domain, *port)) {
                                Ok(addr) => addr,
                                Err(e) => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::Other,
                                        format!("invalid destination: {}", e),
                                    ));
                                }
                            }
                        }
                    };
                    target.write_to(&mut stream).await?;
                    return Ok(Box::new(SimpleStream(stream)));
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            Error::new(ErrorKind::InvalidInput, "could not resolve to any address")
        }))
    }
}
