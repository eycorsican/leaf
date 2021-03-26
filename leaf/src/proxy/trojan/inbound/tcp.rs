use std::cmp::min;
use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use futures::TryFutureExt;
use log::*;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    proxy::TcpInboundHandler,
    proxy::{
        InboundDatagram, InboundDatagramRecvHalf, InboundDatagramSendHalf, InboundTransport,
        ProxyStream,
    },
    session::{DatagramSource, Session, SocksAddr, SocksAddrWireType},
};

struct StreamToDatagram {
    stream: Box<dyn ProxyStream>,
    source: DatagramSource,
}

impl InboundDatagram for StreamToDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (r, s) = tokio::io::split(self.stream);
        (
            Box::new(StreamToDatagramRecvHalf(r, self.source)),
            Box::new(StreamToDatagramSendHalf(s)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::new(io::ErrorKind::Other, "stream transport"))
    }
}

struct StreamToDatagramRecvHalf<T>(T, DatagramSource);

#[async_trait]
impl<T> InboundDatagramRecvHalf for StreamToDatagramRecvHalf<T>
where
    T: AsyncRead + Send + Sync + Unpin,
{
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<(usize, DatagramSource, Option<SocksAddr>)> {
        let dst_addr = SocksAddr::read_from(&mut self.0, SocksAddrWireType::PortLast).await?;
        let mut buf2 = BytesMut::new();
        buf2.resize(2, 0);
        let _ = self.0.read_exact(&mut buf2).await?;
        let payload_len = BigEndian::read_u16(&buf2);
        let _ = self.0.read_exact(&mut buf2).await?;
        if &buf2[..2] != b"\r\n" {
            return Err(io::Error::new(io::ErrorKind::Other, "expected CRLF"));
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
        Ok((to_write, self.1, Some(dst_addr)))
    }
}

struct StreamToDatagramSendHalf<T>(T);

#[async_trait]
impl<T> InboundDatagramSendHalf for StreamToDatagramSendHalf<T>
where
    T: AsyncWrite + Send + Sync + Unpin,
{
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: Option<&SocksAddr>,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let mut data = BytesMut::new();

        if let Some(src_addr) = src_addr {
            src_addr.write_buf(&mut data, SocksAddrWireType::PortLast)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "sending message without source",
            ));
        }

        data.put_u16(buf.len() as u16);
        data.put_slice(b"\r\n");
        data.put_slice(buf);
        self.0.write_all(&data).map_ok(|_| buf.len()).await
    }
}

// FIXME anti-detection, redirect traffic
pub struct Handler {
    key: Vec<u8>,
}

impl Handler {
    pub fn new(password: &str) -> Self {
        let key = Sha224::digest(password.as_bytes());
        let key = hex::encode(&key[..]);
        let key = key.as_bytes();
        Handler { key: key.to_vec() }
    }
}

#[async_trait]
impl TcpInboundHandler for Handler {
    async fn handle_tcp<'a>(
        &'a self,
        mut sess: Session,
        mut stream: Box<dyn ProxyStream>,
    ) -> std::io::Result<InboundTransport> {
        let mut buf = BytesMut::new();
        // read key
        buf.resize(56, 0);
        stream.read_exact(&mut buf).await?;
        if self.key[..] != buf[..] {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid key"));
        }
        // read crlf
        buf.resize(2, 0);
        stream.read_exact(&mut buf).await?;
        // read cmd
        buf.resize(1, 0);
        stream.read_exact(&mut buf).await?;
        match buf[0] {
            // tcp
            0x01 => {
                // read addr
                let dst_addr =
                    SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await?;
                sess.destination = dst_addr;
                // read crlf
                buf.resize(2, 0);
                stream.read_exact(&mut buf).await?;
                return Ok(InboundTransport::Stream(stream, sess));
            }
            // udp
            0x03 => {
                // read addr
                let dst_addr =
                    SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await?;
                sess.destination = dst_addr;
                // read crlf
                buf.resize(2, 0);
                stream.read_exact(&mut buf).await?;

                return Ok(InboundTransport::Datagram(Box::new(StreamToDatagram {
                    stream,
                    source: DatagramSource::new(sess.source, sess.stream_id),
                })));
            }
            _ => {
                return Err(io::Error::new(io::ErrorKind::Other, "invalid command"));
            }
        }
    }
}
