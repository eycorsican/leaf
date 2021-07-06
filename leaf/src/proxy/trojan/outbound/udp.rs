use std::cmp::min;
use std::io;

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use futures::future::TryFutureExt;
use log::*;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::{
    proxy::*,
    session::{Session, SocksAddr, SocksAddrWireType},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub password: String,
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    type UStream = AnyStream;
    type Datagram = AnyOutboundDatagram;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Proxy(self.address.clone(), self.port))
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Stream
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<Self::UStream, Self::Datagram>>,
    ) -> io::Result<Self::Datagram> {
        let stream = if let Some(OutboundTransport::Stream(stream)) = transport {
            stream
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid input"));
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

        let destination = match &sess.destination {
            SocksAddr::Domain(domain, port) => {
                Some(SocksAddr::Domain(domain.to_owned(), port.to_owned()))
            }
            _ => None,
        };

        Ok(Box::new(Datagram {
            stream,
            destination,
            head: Some(buf),
        }))
    }
}

pub struct Datagram<S> {
    stream: S,
    destination: Option<SocksAddr>,
    head: Option<BytesMut>,
}

impl<S> OutboundDatagram for Datagram<S>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        (
            Box::new(DatagramRecvHalf(r, self.destination)),
            Box::new(DatagramSendHalf(w, self.head)),
        )
    }
}

pub struct DatagramRecvHalf<T>(ReadHalf<T>, Option<SocksAddr>);

#[async_trait]
impl<T> OutboundDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
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

        // If the initial destination is of domain type, we return that
        // domain address instead of the real source address. That also
        // means we assume all received packets are comming from a same
        // address.
        if self.1.is_some() {
            Ok((to_write, self.1.as_ref().unwrap().clone()))
        } else {
            Ok((to_write, addr))
        }
    }
}

pub struct DatagramSendHalf<T>(WriteHalf<T>, Option<BytesMut>);

#[async_trait]
impl<T> OutboundDatagramSendHalf for DatagramSendHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        // FIXME we should calculate the return size more carefully.
        // max(0, n_written - all_headers_size)
        let payload_size = buf.len();

        let mut data = BytesMut::new();
        target.write_buf(&mut data, SocksAddrWireType::PortLast)?;
        data.put_u16(buf.len() as u16);
        data.put_slice(b"\r\n");
        data.put_slice(buf);

        // Writes the header along with the first payload.
        if self.1.is_some() {
            if let Some(mut head) = self.1.take() {
                head.extend_from_slice(&data);
                return self.0.write_all(&head).map_ok(|_| payload_size).await;
            }
        }

        self.0.write_all(&data).map_ok(|_| payload_size).await
    }
}
