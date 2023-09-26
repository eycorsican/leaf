use std::io;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use futures::future::TryFutureExt;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tracing::trace;

use crate::{proxy::*, session::*};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub password: String,
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, self.address.clone(), self.port)
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Reliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
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
            .write_buf(&mut buf, SocksAddrWireType::PortLast);
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
        let mut buf2 = [0; 4];
        self.0.read_exact(&mut buf2).await?;
        let payload_len = u16::from_be_bytes(buf2[..2].try_into().unwrap()) as usize;
        // TODO Check CLRF?
        if buf.len() < payload_len {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "Small buffer"));
        }
        self.0.read_exact(&mut buf[..payload_len]).await?;
        // If the initial destination is of domain type, we return that
        // domain address instead of the real source address. That also
        // means we assume all received packets are comming from a same
        // address.
        if self.1.is_some() {
            trace!(
                "trojan outbound received UDP {} bytes from {}",
                payload_len,
                self.1.as_ref().unwrap()
            );
            Ok((payload_len, self.1.as_ref().unwrap().clone()))
        } else {
            trace!(
                "trojan outbound received UDP {} bytes from {}",
                payload_len,
                &addr
            );
            Ok((payload_len, addr))
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
        trace!("trojan outbound send UDP {} bytes to {}", buf.len(), target);
        let mut data = BytesMut::new();
        target.write_buf(&mut data, SocksAddrWireType::PortLast);
        data.put_u16(buf.len() as u16);
        data.put_slice(b"\r\n");
        data.put_slice(buf);

        // Writes the header along with the first payload.
        if self.1.is_some() {
            if let Some(mut head) = self.1.take() {
                head.extend_from_slice(&data);
                return self.0.write_all(&head).map_ok(|_| buf.len()).await;
            }
        }

        self.0.write_all(&data).map_ok(|_| buf.len()).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}
