use std::cmp::min;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use futures::future::TryFutureExt;
use log::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use uuid::Uuid;

use crate::{
    common::dns_client::DnsClient,
    proxy::{
        ProxyDatagram, ProxyDatagramRecvHalf, ProxyDatagramSendHalf, ProxyStream, ProxyUdpHandler,
        UdpTransportType,
    },
    session::{Session, SocksAddr, SocksAddrWireType},
};

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
        let uuid = Uuid::parse_str(&self.uuid).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("parse uuid failed: {}", e))
        })?;
        let mut buf = BytesMut::new();
        buf.put_u8(0x0); // version
        buf.put_slice(uuid.as_bytes()); // uuid
        buf.put_u8(0x0); // addons
        buf.put_u8(0x02); // ucp command
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortFirst)?;

        let mut stream = if let Some(stream) = stream {
            stream
        } else {
            self.dial_tcp_stream(
                self.dns_client.clone(),
                &self.bind_addr,
                &self.address,
                &self.port,
            )
            .await?
        };

        stream.write_all(&buf[..]).await?;
        Ok(Box::new(Datagram {
            stream,
            target: sess.destination.clone(),
        }))
    }
}

pub struct Datagram<S> {
    stream: S,
    target: SocksAddr,
}

impl<S> ProxyDatagram for Datagram<S>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
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

pub struct DatagramRecvHalf<T>(ReadHalf<T>, SocksAddr, bool);

#[async_trait]
impl<T> ProxyDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
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
            SocksAddr::Ip(addr) => addr,
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
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn send_to(&mut self, buf: &[u8], _target: &SocketAddr) -> io::Result<usize> {
        let mut data = BytesMut::new();
        data.put_u16(buf.len() as u16);
        data.put_slice(buf);
        self.0.write_all(&data).map_ok(|_| buf.len()).await
    }
}
