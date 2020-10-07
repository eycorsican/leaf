use std::convert::TryFrom;
use std::net::SocketAddr;
use std::{io, sync::Arc};

use async_trait::async_trait;
use socket2::{Domain, Socket, Type};
use tokio::net::TcpStream;

use crate::{
    common::dns_client::DnsClient,
    proxy::{stream::SimpleStream, ProxyHandler, ProxyStream, ProxyTcpHandler},
    session::{Session, SocksAddr},
};

pub struct Handler {
    pub actors: Vec<Arc<dyn ProxyHandler>>,
    pub dns_client: Arc<DnsClient>,
}

#[async_trait]
impl ProxyTcpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        for a in self.actors.iter() {
            if let Some(addr) = a.tcp_connect_addr() {
                return Some(addr);
            }
        }
        None
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        if let Some(mut stream) = stream {
            for (i, a) in self.actors.iter().enumerate() {
                let mut new_sess = sess.clone();
                for j in (i + 1)..self.actors.len() {
                    if let Some((connect_addr, port, _)) = self.actors[j].tcp_connect_addr() {
                        if let Ok(addr) = SocksAddr::try_from(format!("{}:{}", connect_addr, port))
                        {
                            new_sess.destination = addr;
                        }
                    }
                }
                stream = a.handle(&new_sess, Some(stream)).await?;
            }

            return Ok(Box::new(SimpleStream(stream)));
        }

        for a in self.actors.iter() {
            if let Some((connect_addr, port, bind_addr)) = a.tcp_connect_addr() {
                let ips = match self
                    .dns_client
                    .lookup_with_bind(connect_addr.clone(), &bind_addr)
                    .await
                {
                    Ok(ips) => ips,
                    Err(err) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("lookup {} failed: {}", &connect_addr, err),
                        ));
                    }
                };

                let mut last_err = None;

                for ip in ips {
                    let socket = Socket::new(Domain::ipv4(), Type::stream(), None)?;
                    socket.bind(&bind_addr.to_owned().into())?;
                    let addr = SocketAddr::new(ip, port);
                    match TcpStream::connect_std(socket.into_tcp_stream(), &addr).await {
                        Ok(stream) => {
                            let mut stream: Box<dyn ProxyStream> = Box::new(SimpleStream(stream));

                            for (i, a) in self.actors.iter().enumerate() {
                                let mut new_sess = sess.clone();
                                for j in (i + 1)..self.actors.len() {
                                    if let Some((connect_addr, port, _)) =
                                        self.actors[j].tcp_connect_addr()
                                    {
                                        if let Ok(addr) = SocksAddr::try_from(format!(
                                            "{}:{}",
                                            connect_addr, port
                                        )) {
                                            new_sess.destination = addr;
                                            break;
                                        }
                                    }
                                }
                                stream = a.handle(&new_sess, Some(stream)).await?;
                            }

                            return Ok(Box::new(SimpleStream(stream)));
                        }
                        Err(e) => {
                            last_err = Some(e);
                        }
                    }
                }
                return Err(last_err.unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "could not resolve to any address",
                    )
                }));
            }
        }
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid chain"));
    }
}
