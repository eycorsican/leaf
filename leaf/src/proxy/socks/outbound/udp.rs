use std::{
    io::{Error, ErrorKind, Result},
    net::SocketAddr,
    sync::Arc,
};

use async_socks5::{AddrKind, Auth, SocksDatagram, SocksDatagramRecvHalf, SocksDatagramSendHalf};
use async_trait::async_trait;
use futures::future::TryFutureExt;
use socket2::{Domain, Socket, Type};
use tokio::net::{TcpStream, UdpSocket};

use crate::{
    common::dns_client::DnsClient,
    proxy::{
        ProxyDatagram, ProxyDatagramRecvHalf, ProxyDatagramSendHalf, ProxyStream, ProxyUdpHandler,
        UdpTransportType,
    },
    session::Session,
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

#[async_trait]
impl ProxyUdpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn udp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        Some((self.address.clone(), self.port, self.bind_addr.clone()))
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Packet
    }

    async fn connect<'a>(
        &'a self,
        _sess: &'a Session,
        _datagram: Option<Box<dyn ProxyDatagram>>,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> Result<Box<dyn ProxyDatagram>> {
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
                    let socket = UdpSocket::bind("0.0.0.0:0").await?;
                    let dg =
                        SocksDatagram::associate(stream, socket, None::<Auth>, None::<AddrKind>)
                            .map_err(|x| Error::new(ErrorKind::Other, x))
                            .await?;
                    let (rh, sh) = dg.split();
                    return Ok(Box::new(Datagram {
                        recv_half: rh,
                        send_half: sh,
                    }));
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

pub struct Datagram {
    pub recv_half: SocksDatagramRecvHalf<TcpStream>,
    pub send_half: SocksDatagramSendHalf<TcpStream>,
}

impl ProxyDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn ProxyDatagramRecvHalf>,
        Box<dyn ProxyDatagramSendHalf>,
    ) {
        (
            Box::new(DatagramRecvHalf(self.recv_half)),
            Box::new(DatagramSendHalf(self.send_half)),
        )
    }
}

pub struct DatagramRecvHalf(SocksDatagramRecvHalf<TcpStream>);

#[async_trait]
impl ProxyDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (n, addr) = self
            .0
            .recv_from(buf)
            .map_err(|x| Error::new(ErrorKind::Other, x))
            .await?;
        match addr {
            AddrKind::Ip(addr) => Ok((n, addr)),
            _ => Err(Error::new(
                ErrorKind::Other,
                "udp receiving domain address is not supported",
            )),
        }
    }
}

pub struct DatagramSendHalf(SocksDatagramSendHalf<TcpStream>);

#[async_trait]
impl ProxyDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> Result<usize> {
        self.0
            .send_to(buf, target.to_owned())
            .map_err(|x| Error::new(ErrorKind::Other, x))
            .await
    }
}
