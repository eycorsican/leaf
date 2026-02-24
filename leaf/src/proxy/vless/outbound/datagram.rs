use std::collections::VecDeque;
use std::io;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use uuid::Uuid;

use super::super::datagram::{build_vless_udp_header, VlessUdpParser};
use crate::{proxy::*, session::*};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub uuid: String,
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
        tracing::trace!("handling outbound datagram session: {:?}", sess);
        let u = Uuid::parse_str(&self.uuid)
            .map_err(|e| io::Error::other(format!("parse uuid failed: {}", e)))?;
        let uuid_bytes = *u.as_bytes();

        let addr_type = match sess.destination.ip() {
            Some(ip) => {
                if ip.is_ipv4() {
                    1
                } else {
                    3
                }
            }
            None => 2,
        };
        let host = sess.destination.host();
        let port = sess.destination.port();

        let header = build_vless_udp_header(&uuid_bytes, &host, port, addr_type);

        let stream = if let Some(OutboundTransport::Stream(stream)) = transport {
            stream
        } else {
            return Err(io::Error::other("invalid input"));
        };

        Ok(Box::new(Datagram {
            stream,
            destination: sess.destination.clone(),
            header: Some(header),
        }))
    }
}

pub struct Datagram<S> {
    stream: S,
    destination: SocksAddr,
    header: Option<Vec<u8>>,
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
            Box::new(DatagramRecvHalf {
                reader: r,
                parser: VlessUdpParser::new(),
                buffer: VecDeque::new(),
                destination: self.destination,
            }),
            Box::new(DatagramSendHalf {
                writer: w,
                header: self.header,
            }),
        )
    }
}

pub struct DatagramRecvHalf<T> {
    reader: ReadHalf<T>,
    parser: VlessUdpParser,
    buffer: VecDeque<Vec<u8>>,
    destination: SocksAddr,
}

#[async_trait]
impl<T> OutboundDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        loop {
            if let Some(payload) = self.buffer.pop_front() {
                let to_write = std::cmp::min(payload.len(), buf.len());
                buf[..to_write].copy_from_slice(&payload[..to_write]);
                return Ok((to_write, self.destination.clone()));
            }

            let mut io_buf = [0u8; 8192];
            let n = self.reader.read(&mut io_buf).await?;
            if n == 0 {
                warn!("VLESS UDP Recv EOF from server");
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }
            let packets = self.parser.parse(&io_buf[..n]);
            for p in packets {
                self.buffer.push_back(p);
            }
        }
    }
}

pub struct DatagramSendHalf<T> {
    writer: WriteHalf<T>,
    header: Option<Vec<u8>>,
}

use tracing::{debug, warn};

#[async_trait]
impl<T> OutboundDatagramSendHalf for DatagramSendHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn send_to(&mut self, buf: &[u8], _target: &SocksAddr) -> io::Result<usize> {
        let payload_len = buf.len() as u16;
        let header_len = self.header.as_ref().map(|h| h.len()).unwrap_or(0);
        let mut write_buf = Vec::with_capacity(2 + buf.len() + header_len);

        if let Some(header) = self.header.take() {
            debug!("VLESS UDP Sending Header: {:02x?}", header);
            write_buf.extend_from_slice(&header);
        }

        write_buf.extend_from_slice(&payload_len.to_be_bytes());
        write_buf.extend_from_slice(buf);

        self.writer.write_all(&write_buf).await?;
        self.writer.flush().await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.writer.shutdown().await
    }
}
