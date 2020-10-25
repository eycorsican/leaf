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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

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
    pub password: String,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

#[async_trait]
impl ProxyUdpHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn udp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        Some((self.address.clone(), self.port, self.bind_addr))
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
        let mut buf = BytesMut::new();
        let password = Sha224::digest(self.password.as_bytes());
        let password = hex::encode(&password[..]);
        buf.put_slice(password.as_bytes());
        buf.put_slice(b"\r\n");
        buf.put_u8(0x03); // udp
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortLast)?;
        buf.put_slice(b"\r\n");
        stream.write_all(&buf).await?;

        Ok(Box::new(Datagram { stream }))
    }
}

pub struct Datagram<S> {
    stream: S,
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
        (Box::new(DatagramRecvHalf(r)), Box::new(DatagramSendHalf(w)))
    }
}

pub struct DatagramRecvHalf<T>(ReadHalf<T>);

#[async_trait]
impl<T> ProxyDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let addr = SocksAddr::read_from(&mut self.0, SocksAddrWireType::PortLast).await?;
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
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        let mut data = BytesMut::new();
        let target = SocksAddr::from(target.to_owned());
        target.write_buf(&mut data, SocksAddrWireType::PortLast)?;
        data.put_u16(buf.len() as u16);
        data.put_slice(b"\r\n");
        data.put_slice(buf);
        self.0.write_all(&data).map_ok(|_| buf.len()).await
    }
}
