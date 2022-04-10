use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;

use anyhow::anyhow;
use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use futures::TryFutureExt;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    proxy::*,
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
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let dst_addr = SocksAddr::read_from(&mut self.0, SocksAddrWireType::PortLast)
            .map_err(|e| ProxyError::DatagramFatal(e.into()))
            .await?;
        let mut buf2 = BytesMut::new();
        buf2.resize(2, 0);
        let _ = self
            .0
            .read_exact(&mut buf2)
            .map_err(|e| ProxyError::DatagramFatal(e.into()))
            .await?;
        let payload_len = BigEndian::read_u16(&buf2) as usize;
        let _ = self
            .0
            .read_exact(&mut buf2)
            .map_err(|e| ProxyError::DatagramFatal(e.into()))
            .await?;
        if &buf2[..2] != b"\r\n" {
            return Err(ProxyError::DatagramFatal(anyhow!("Expeced CRLF")));
        }
        if buf.len() < payload_len {
            return Err(ProxyError::DatagramFatal(anyhow!("Small buffer")));
        }
        buf2.resize(payload_len, 0);
        let _ = self
            .0
            .read_exact(&mut buf2)
            .map_err(|e| ProxyError::DatagramFatal(e.into()))
            .await?;
        buf[..payload_len].copy_from_slice(&buf2[..payload_len]);
        Ok((payload_len, self.1, dst_addr))
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
        src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let mut data = BytesMut::new();
        src_addr.write_buf(&mut data, SocksAddrWireType::PortLast);
        data.put_u16(buf.len() as u16);
        data.put_slice(b"\r\n");
        data.put_slice(buf);
        self.0.write_all(&data).map_ok(|_| buf.len()).await
    }
}

// FIXME anti-detection, redirect traffic
pub struct Handler {
    keys: HashMap<Vec<u8>, ()>,
}

impl Handler {
    pub fn new(passwords: Vec<String>) -> Self {
        let mut keys = HashMap::new();
        for pass in passwords {
            let key = Sha224::digest(pass.as_bytes());
            let key = hex::encode(&key[..]);
            keys.insert(key.as_bytes().to_vec(), ());
        }
        Handler { keys }
    }
}

#[async_trait]
impl TcpInboundHandler for Handler {
    type TStream = AnyStream;
    type TDatagram = AnyInboundDatagram;

    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        mut stream: Self::TStream,
    ) -> std::io::Result<InboundTransport<Self::TStream, Self::TDatagram>> {
        let mut buf = BytesMut::new();
        // read key
        buf.resize(56, 0);
        stream.read_exact(&mut buf).await?;
        if !self.keys.contains_key(&buf[..]) {
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
