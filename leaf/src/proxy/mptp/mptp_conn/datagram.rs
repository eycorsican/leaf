use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::proxy::*;
use crate::session::{DatagramSource, SocksAddr};

use super::protocol::{Address, UdpHeader};

pub struct MptpDatagram<S> {
    stream: S,
}

impl<S> MptpDatagram<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }
}

impl<S> InboundDatagram for MptpDatagram<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (r, w) = split(self.stream);
        (
            Box::new(InboundDatagramRecvHalfImpl(r)),
            Box::new(InboundDatagramSendHalfImpl(w)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::new(io::ErrorKind::Other, "not supported"))
    }
}

impl<S> OutboundDatagram for MptpDatagram<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, w) = split(self.stream);
        (
            Box::new(OutboundDatagramRecvHalfImpl(r)),
            Box::new(OutboundDatagramSendHalfImpl(w)),
        )
    }
}

pub struct InboundDatagramRecvHalfImpl<R>(ReadHalf<R>);

#[async_trait]
impl<R: AsyncRead + Send + Sync + Unpin> InboundDatagramRecvHalf
    for InboundDatagramRecvHalfImpl<R>
{
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        // Read length (2 bytes)
        let mut len_buf = [0u8; 2];
        if let Err(e) = self.0.read_exact(&mut len_buf).await {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                return Err(ProxyError::DatagramFatal(anyhow::anyhow!("stream closed")));
            }
            return Err(ProxyError::DatagramFatal(e.into()));
        }
        let len = u16::from_be_bytes(len_buf) as usize;

        let mut data = vec![0u8; len];
        self.0
            .read_exact(&mut data)
            .await
            .map_err(|e| ProxyError::DatagramFatal(e.into()))?;

        let mut data_buf = BytesMut::from(&data[..]);
        let header = UdpHeader::decode(&mut data_buf)
            .map_err(|e| ProxyError::DatagramWarn(anyhow::anyhow!(e)))?
            .ok_or_else(|| ProxyError::DatagramWarn(anyhow::anyhow!("incomplete header")))?;

        let payload_len = data_buf.len();
        if buf.len() < payload_len {
            return Err(ProxyError::DatagramWarn(anyhow::anyhow!(
                "buffer too small"
            )));
        }
        buf[..payload_len].copy_from_slice(&data_buf);

        let dst_addr = match header.addr {
            Address::Ipv4(ip) => SocksAddr::from((ip, header.port)),
            Address::Ipv6(ip) => SocksAddr::from((ip, header.port)),
            Address::Domain(domain) => SocksAddr::try_from((domain, header.port))
                .map_err(|e| ProxyError::DatagramWarn(anyhow::anyhow!(e)))?,
        };

        // For inbound, we don't really know the source addr from the stream itself.
        // We just use a placeholder.
        let src_addr = DatagramSource::new("0.0.0.0:0".parse().unwrap(), None);

        Ok((payload_len, src_addr, dst_addr))
    }
}

pub struct InboundDatagramSendHalfImpl<W>(WriteHalf<W>);

#[async_trait]
impl<W: AsyncWrite + Send + Sync + Unpin> InboundDatagramSendHalf
    for InboundDatagramSendHalfImpl<W>
{
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let address = match src_addr {
            SocksAddr::Ip(std::net::SocketAddr::V4(v4)) => Address::Ipv4(*v4.ip()),
            SocksAddr::Ip(std::net::SocketAddr::V6(v6)) => Address::Ipv6(*v6.ip()),
            SocksAddr::Domain(domain, _) => Address::Domain(domain.clone()),
        };

        let header = UdpHeader {
            frag: 0,
            addr: address,
            port: src_addr.port(),
        };

        let mut encoded = BytesMut::new();
        header.encode(&mut encoded);
        encoded.put_slice(buf);

        let len = encoded.len() as u16;
        self.0.write_u16(len).await?;
        self.0.write_all(&encoded).await?;

        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}

pub struct OutboundDatagramRecvHalfImpl<R>(ReadHalf<R>);

#[async_trait]
impl<R: AsyncRead + Send + Sync + Unpin> OutboundDatagramRecvHalf
    for OutboundDatagramRecvHalfImpl<R>
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        // Read length (2 bytes)
        let mut len_buf = [0u8; 2];
        self.0.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;

        let mut data = vec![0u8; len];
        self.0.read_exact(&mut data).await?;

        let mut data_buf = BytesMut::from(&data[..]);
        let header = UdpHeader::decode(&mut data_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete header"))?;

        let payload_len = data_buf.len();
        if buf.len() < payload_len {
            tracing::warn!(
                "UDP payload too large for buffer: {} > {}",
                payload_len,
                buf.len()
            );
            buf.copy_from_slice(&data_buf[..buf.len()]);
            let addr = match header.addr {
                Address::Ipv4(ip) => SocksAddr::from((ip, header.port)),
                Address::Ipv6(ip) => SocksAddr::from((ip, header.port)),
                Address::Domain(domain) => SocksAddr::try_from((domain, header.port))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            };
            return Ok((buf.len(), addr));
        }
        buf[..payload_len].copy_from_slice(&data_buf);

        let addr = match header.addr {
            Address::Ipv4(ip) => SocksAddr::from((ip, header.port)),
            Address::Ipv6(ip) => SocksAddr::from((ip, header.port)),
            Address::Domain(domain) => SocksAddr::try_from((domain, header.port))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        };

        Ok((payload_len, addr))
    }
}

pub struct OutboundDatagramSendHalfImpl<W>(WriteHalf<W>);

#[async_trait]
impl<W: AsyncWrite + Send + Sync + Unpin> OutboundDatagramSendHalf
    for OutboundDatagramSendHalfImpl<W>
{
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let address = match target {
            SocksAddr::Ip(std::net::SocketAddr::V4(v4)) => Address::Ipv4(*v4.ip()),
            SocksAddr::Ip(std::net::SocketAddr::V6(v6)) => Address::Ipv6(*v6.ip()),
            SocksAddr::Domain(domain, _) => Address::Domain(domain.clone()),
        };

        let header = UdpHeader {
            frag: 0,
            addr: address,
            port: target.port(),
        };

        let mut encoded = BytesMut::new();
        header.encode(&mut encoded);
        encoded.put_slice(buf);

        let len = encoded.len() as u16;
        self.0.write_u16(len).await?;
        self.0.write_all(&encoded).await?;

        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}
