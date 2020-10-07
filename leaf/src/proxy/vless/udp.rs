use std::cmp::min;
use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use futures::future::TryFutureExt;
use log::*;
use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::{
    common::dns_client::DnsClient,
    proxy::{
        ProxyDatagram, ProxyDatagramRecvHalf, ProxyDatagramSendHalf, ProxyStream, ProxyUdpHandler,
        UdpTransportType,
    },
    session::{Session, SocksAddr},
};

use super::SocksAddr as VLessSocksAddr;

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub uuid: String,
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
        UdpTransportType::Stream
    }

    async fn connect<'a>(
        &'a self,
        sess: &'a Session,
        _datagram: Option<Box<dyn ProxyDatagram>>,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyDatagram>> {
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
            buf.put_u8(0x02); // ucp command
            target.write_into(&mut buf)?;
            stream.write_all(&buf[..]).await?;

            let target = match sess.destination {
                SocksAddr::Ip(addr) => VLessSocksAddr::from(addr),
                SocksAddr::Domain(ref domain, port) => {
                    match VLessSocksAddr::try_from((domain, port)) {
                        Ok(addr) => addr,
                        Err(e) => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("invalid destination: {}", e),
                            ))
                        }
                    }
                }
            };
            return Ok(Box::new(Datagram { stream, target }));
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
                    buf.put_u8(0x02); // ucp command
                    target.write_into(&mut buf)?;
                    stream.write_all(&buf[..]).await?;

                    let target = match sess.destination {
                        SocksAddr::Ip(addr) => VLessSocksAddr::from(addr),
                        SocksAddr::Domain(ref domain, port) => {
                            match VLessSocksAddr::try_from((domain, port)) {
                                Ok(addr) => addr,
                                Err(e) => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::Other,
                                        format!("invalid destination: {}", e),
                                    ))
                                }
                            }
                        }
                    };
                    return Ok(Box::new(Datagram { stream, target }));
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

pub struct Datagram<S> {
    stream: S,
    target: VLessSocksAddr,
}

impl<S> ProxyDatagram for Datagram<S>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin + Send,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn ProxyDatagramRecvHalf>,
        Box<dyn ProxyDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        (
            Box::new(DatagramRecvHalf(r, self.target, false)),
            Box::new(DatagramSendHalf(w)),
        )
    }
}

pub struct DatagramRecvHalf<T>(ReadHalf<T>, VLessSocksAddr, bool);

#[async_trait]
impl<T> ProxyDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut buf2 = BytesMut::new();

        if !self.2 {
            // read version
            buf2.resize(1, 0);
            let _ = self.0.read_exact(&mut buf2).await?;
            if buf2[0] != 0x0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("invalid vless version: {}", buf2[0]),
                ));
            }

            // read addons
            buf2.resize(1, 0);
            let _ = self.0.read_exact(&mut buf2).await?;
            if buf2[0] != 0x0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("invalid vless version: {}", buf2[0]),
                ));
            }
            self.2 = true;
        }

        buf2.resize(2, 0);
        let _ = self.0.read_exact(&mut buf2).await?;
        let payload_len = BigEndian::read_u16(&buf2);
        buf2.resize(payload_len as usize, 0);
        let _ = self.0.read_exact(&mut buf2).await?;
        let to_write = min(buf2.len(), buf.len());
        if to_write < buf2.len() {
            warn!(
                "trucated udp payload, buf size too small: {} < {}",
                buf.len(),
                buf2.len()
            );
        }
        buf[..to_write].copy_from_slice(&buf2[..to_write]);
        let addr = match self.1 {
            VLessSocksAddr::Ip(addr) => addr,
            _ => {
                error!("unexpected domain address");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "unexpected domain address in vmess udp",
                ));
            }
        };
        Ok((to_write, addr))
    }
}

pub struct DatagramSendHalf<T>(WriteHalf<T>);

#[async_trait]
impl<T> ProxyDatagramSendHalf for DatagramSendHalf<T>
where
    T: AsyncRead + AsyncWrite + Send,
{
    async fn send_to(&mut self, buf: &[u8], _target: &SocketAddr) -> io::Result<usize> {
        let mut data = BytesMut::new();
        data.put_u16(buf.len() as u16);
        data.put_slice(buf);
        self.0.write_all(&data).map_ok(|_| buf.len()).await
    }
}
