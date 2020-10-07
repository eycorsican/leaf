use std::cmp::min;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use futures::future::TryFutureExt;
use log::*;
use sha2::{Digest, Sha224};
use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use crate::{
    common::dns_client::DnsClient,
    // common::tls::wrap_tls,
    proxy::{
        ProxyDatagram, ProxyDatagramRecvHalf, ProxyDatagramSendHalf, ProxyStream, ProxyUdpHandler,
        UdpTransportType,
    },
    session::{Session, SocksAddr},
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
        if let Some(mut stream) = stream {
            let mut buf = BytesMut::new();
            let password = Sha224::digest(self.password.as_bytes());
            let password = hex::encode(&password[..]);
            buf.put_slice(password.as_bytes());
            buf.put_slice(b"\r\n");
            buf.put_u8(0x03); // udp
            sess.destination.write_into(&mut buf)?;
            buf.put_slice(b"\r\n");
            stream.write_all(&buf).await?;

            let target = match sess.destination {
                SocksAddr::Ip(a) => a,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "udp destination with domain name is not supported",
                    ))
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
                    // let mut stream = wrap_tls(stream, &self.domain).await?;

                    let mut buf = BytesMut::new();
                    let password = Sha224::digest(self.password.as_bytes());
                    let password = hex::encode(&password[..]);
                    buf.put_slice(password.as_bytes());
                    buf.put_slice(b"\r\n");
                    buf.put_u8(0x03); // udp
                    sess.destination.write_into(&mut buf)?;
                    buf.put_slice(b"\r\n");
                    stream.write_all(&buf).await?;

                    let target = match sess.destination {
                        SocksAddr::Ip(a) => a,
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "udp destination with domain name is not supported",
                            ))
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
    target: SocketAddr,
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
            Box::new(DatagramRecvHalf(r, self.target)),
            Box::new(DatagramSendHalf(w)),
        )
    }
}

pub struct DatagramRecvHalf<T>(ReadHalf<T>, SocketAddr);

#[async_trait]
impl<T> ProxyDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let addr = SocksAddr::read_from(&mut self.0).await?;
        let mut buf2 = BytesMut::new();
        buf2.resize(2, 0);
        let _ = self.0.read_exact(&mut buf2).await?;
        let payload_len = BigEndian::read_u16(&buf2);
        let _ = self.0.read_exact(&mut buf2).await?;
        if &buf2[..2] != b"\r\n" {
            return Err(io::Error::new(io::ErrorKind::Other, "expected CLRF"));
        }
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
        match addr {
            SocksAddr::Ip(a) => Ok((to_write, a)),
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                "unexpected domain address",
            )),
        }
    }
}

pub struct DatagramSendHalf<T>(WriteHalf<T>);

#[async_trait]
impl<T> ProxyDatagramSendHalf for DatagramSendHalf<T>
where
    T: AsyncRead + AsyncWrite + Send,
{
    async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        let mut data = BytesMut::new();
        let target = SocksAddr::from(target.to_owned());
        target.write_into(&mut data)?;
        data.put_u16(buf.len() as u16);
        data.put_slice(b"\r\n");
        data.put_slice(buf);
        self.0.write_all(&data).map_ok(|_| buf.len()).await
    }
}
