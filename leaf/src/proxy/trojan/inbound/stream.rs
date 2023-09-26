use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use futures::TryFutureExt;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

use crate::{
    proxy::*,
    session::{DatagramSource, Network, Session, SocksAddr, SocksAddrWireType},
};

struct Datagram {
    stream: AnyStream,
    source: DatagramSource,
}

impl Datagram {
    pub fn new(stream: AnyStream, source: DatagramSource) -> Self {
        Self { stream, source }
    }
}

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (r, s) = tokio::io::split(self.stream);
        (
            Box::new(DatagramRecvHalf(r, self.source)),
            Box::new(DatagramSendHalf(s)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::new(io::ErrorKind::Other, "stream transport"))
    }
}

struct DatagramRecvHalf<T>(T, DatagramSource);

#[async_trait]
impl<T> InboundDatagramRecvHalf for DatagramRecvHalf<T>
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
        let mut buf2 = [0; 4];
        self.0
            .read_exact(&mut buf2)
            .map_err(|e| ProxyError::DatagramFatal(e.into()))
            .await?;
        let payload_len = u16::from_be_bytes(buf2[..2].try_into().unwrap()) as usize;
        if buf.len() < payload_len {
            return Err(ProxyError::DatagramFatal(anyhow!("Small buffer")));
        }
        // TODO Check CRLF?
        self.0
            .read_exact(&mut buf[..payload_len])
            .map_err(|e| ProxyError::DatagramFatal(e.into()))
            .await?;
        trace!(
            "trojan inbound received UDP {} bytes for {}",
            payload_len,
            &dst_addr
        );
        Ok((payload_len, self.1, dst_addr))
    }
}

struct DatagramSendHalf<T>(T);

#[async_trait]
impl<T> InboundDatagramSendHalf for DatagramSendHalf<T>
where
    T: AsyncWrite + Send + Sync + Unpin,
{
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        trace!(
            "trojan inbound send UDP {} bytes for {}",
            buf.len(),
            &src_addr
        );
        let mut data = BytesMut::new();
        src_addr.write_buf(&mut data, SocksAddrWireType::PortLast);
        data.put_u16(buf.len() as u16);
        data.put_slice(b"\r\n");
        data.put_slice(buf);
        self.0.write_all(&data).map_ok(|_| buf.len()).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}

pub struct Handler {
    keys: HashSet<Vec<u8>>,
}

impl Handler {
    pub fn new(passwords: Vec<String>) -> Self {
        let mut keys = HashSet::new();
        for pass in passwords {
            let key = Sha224::digest(pass.as_bytes());
            let key = hex::encode(&key[..]);
            keys.insert(key.as_bytes().to_vec());
        }
        Handler { keys }
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        let mut buf = [0; 56];
        // read key
        stream.read_exact(&mut buf[..56]).await?;
        if !self.keys.contains(&buf[..]) {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid key"));
        }
        // read crlf and cmd
        stream.read_exact(&mut buf[..3]).await?;
        // TODO Check CRLF?
        let cmd = buf[2];
        // read addr
        let dst_addr = SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await?;
        sess.destination = dst_addr;
        // read crlf
        stream.read_exact(&mut buf[..2]).await?;
        match cmd {
            // tcp
            0x01 => Ok(InboundTransport::Stream(stream, sess)),
            // udp
            0x03 => {
                sess.network = Network::Udp;
                Ok(InboundTransport::Datagram(
                    Box::new(Datagram::new(
                        stream,
                        DatagramSource::new(sess.source, sess.stream_id),
                    )),
                    Some(sess),
                ))
            }
            _ => Err(io::Error::new(io::ErrorKind::Other, "invalid command")),
        }
    }
}
