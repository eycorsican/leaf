use std::{
    cmp::min,
    convert::TryFrom,
    io::{self, Error, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use log::*;
use tokio::net::UdpSocket;

use super::{ShadowedDatagram, ShadowedDatagramRecvHalf, ShadowedDatagramSendHalf};
use crate::{
    common::dns_client::DnsClient,
    proxy::{
        ProxyDatagram, ProxyDatagramRecvHalf, ProxyDatagramSendHalf, ProxyStream, ProxyUdpHandler,
        SimpleDatagram, UdpTransportType,
    },
    session::{Session, SocksAddr, SocksAddrWireType},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
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
        UdpTransportType::Packet
    }

    async fn connect<'a>(
        &'a self,
        _sess: &'a Session,
        datagram: Option<Box<dyn ProxyDatagram>>,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyDatagram>> {
        let ips = match self
            .dns_client
            .lookup_with_bind(String::from(&self.address), &self.bind_addr)
            .await
        {
            Ok(ips) => ips,
            Err(err) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("lookup failed: {}", err),
                ));
            }
        };

        if ips.len() == 0 {
            return Err(Error::new(ErrorKind::Other, "no resolved address"));
        }

        let ip = ips[0]; // pick a random one? iterate all?
        let addr = SocketAddr::new(ip, self.port);

        let socket = if let Some(socket) = datagram {
            socket
        } else {
            let socket = UdpSocket::bind(self.bind_addr).await?;
            let socket = Box::new(SimpleDatagram(socket));
            socket
        };

        let dgram = ShadowedDatagram::with_initial_buffer_size(
            socket,
            &self.cipher,
            &self.password,
            2 * 1024,
        )
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("new shadowed stream failed: {}", e),
            )
        })?;
        let (r, s) = dgram.split();
        return Ok(Box::new(Datagram { r, s, server: addr }));
    }
}

pub struct Datagram {
    pub r: ShadowedDatagramRecvHalf,
    pub s: ShadowedDatagramSendHalf,
    pub server: SocketAddr,
}

impl ProxyDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn ProxyDatagramRecvHalf>,
        Box<dyn ProxyDatagramSendHalf>,
    ) {
        (
            Box::new(DatagramRecvHalf(self.r)),
            Box::new(DatagramSendHalf {
                send_half: self.s,
                server: self.server,
            }),
        )
    }
}

pub struct DatagramRecvHalf(ShadowedDatagramRecvHalf);

#[async_trait]
impl ProxyDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // TODO optimize
        let mut buf2 = [0u8; 2 * 1024];
        let (n, _) = self.0.recv_from(&mut buf2).await?;
        let tgt_addr = match SocksAddr::try_from((&buf2[..n], SocksAddrWireType::PortLast)) {
            Ok(v) => v,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("invalid remote address: {}", e),
                ));
            }
        };
        match tgt_addr {
            SocksAddr::Ip(addr) => {
                let payload_len = n - tgt_addr.size();
                let to_write = min(payload_len, buf.len());
                if to_write < payload_len {
                    warn!("truncated udp packet, please report this issue");
                }
                buf[..to_write].copy_from_slice(&buf2[tgt_addr.size()..tgt_addr.size() + to_write]);
                Ok((to_write, addr))
            }
            _ => Err(Error::new(
                ErrorKind::Other,
                "udp receiving domain address is not supported",
            )),
        }
    }
}

pub struct DatagramSendHalf {
    send_half: ShadowedDatagramSendHalf,
    server: SocketAddr,
}

#[async_trait]
impl ProxyDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        let mut buf2 = BytesMut::new();
        let target = SocksAddr::from(target);
        target.write_buf(&mut buf2, SocksAddrWireType::PortLast)?;
        buf2.put_slice(&buf);

        match self.send_half.send_to(&buf2, &self.server).await {
            Ok(_) => Ok(buf.len()),
            Err(err) => Err(err),
        }
    }
}
