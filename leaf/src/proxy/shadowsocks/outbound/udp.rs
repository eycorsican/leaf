use std::{
    cmp::min,
    convert::TryFrom,
    io::{self, Error, ErrorKind},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use log::*;

use crate::{
    app::dns_client::DnsClient,
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf,
        OutboundTransport, SimpleOutboundDatagram, UdpConnector, UdpOutboundHandler,
        UdpTransportType,
    },
    session::{Session, SocksAddr, SocksAddrWireType},
};

use super::shadow::{self, ShadowedDatagram};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

impl UdpConnector for Handler {}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn udp_connect_addr(&self) -> Option<OutboundConnect> {
        if !self.address.is_empty() && self.port != 0 {
            Some(OutboundConnect::Proxy(
                self.address.clone(),
                self.port,
                self.bind_addr,
            ))
        } else {
            None
        }
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Packet
    }

    async fn handle_udp<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport>,
    ) -> io::Result<Box<dyn OutboundDatagram>> {
        let server_addr = if let Ok(ip) = self.address.parse::<IpAddr>() {
            SocksAddr::Ip(SocketAddr::new(ip, self.port))
        } else {
            SocksAddr::Domain(self.address.clone(), self.port)
        };

        let socket = if let Some(OutboundTransport::Datagram(socket)) = transport {
            socket
        } else {
            let socket = self.create_udp_socket(&self.bind_addr).await?;
            Box::new(SimpleOutboundDatagram::new(
                socket,
                None,
                self.dns_client.clone(),
                self.bind_addr,
            ))
        };

        let dgram = ShadowedDatagram::new(&self.cipher, &self.password).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("new shadowed datagram failed: {}", e),
            )
        })?;

        let destination = match &sess.destination {
            SocksAddr::Domain(domain, port) => {
                Some(SocksAddr::Domain(domain.to_owned(), port.to_owned()))
            }
            _ => None,
        };

        Ok(Box::new(Datagram {
            dgram,
            socket,
            destination,
            server_addr,
        }))
    }
}

pub struct Datagram {
    pub dgram: ShadowedDatagram,
    pub socket: Box<dyn OutboundDatagram>,
    pub destination: Option<SocksAddr>,
    pub server_addr: SocksAddr,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let dgram = Arc::new(self.dgram);
        let (r, s) = self.socket.split();
        (
            Box::new(DatagramRecvHalf(dgram.clone(), r, self.destination)),
            Box::new(DatagramSendHalf {
                dgram,
                send_half: s,
                server_addr: self.server_addr,
            }),
        )
    }
}

pub struct DatagramRecvHalf(
    Arc<ShadowedDatagram>,
    Box<dyn OutboundDatagramRecvHalf>,
    Option<SocksAddr>,
);

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let mut buf2 = BytesMut::new();
        buf2.resize(2 * 1024, 0);
        let (n, _) = self.1.recv_from(&mut buf2).await?;
        buf2.resize(n, 0);
        let plaintext = self.0.decrypt(buf2).map_err(|_| shadow::crypto_err())?;
        let src_addr = match SocksAddr::try_from((&plaintext[..], SocksAddrWireType::PortLast)) {
            Ok(v) => v,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("invalid remote address: {}", e),
                ));
            }
        };
        let payload_len = plaintext.len() - src_addr.size();
        let to_write = min(payload_len, buf.len());
        if to_write < payload_len {
            warn!("truncated udp packet, please report this issue");
        }
        buf[..to_write].copy_from_slice(&plaintext[src_addr.size()..src_addr.size() + to_write]);
        if self.2.is_some() {
            // must be a domain destination
            Ok((to_write, self.2.as_ref().unwrap().clone()))
        } else {
            Ok((to_write, src_addr))
        }
    }
}

pub struct DatagramSendHalf {
    dgram: Arc<ShadowedDatagram>,
    send_half: Box<dyn OutboundDatagramSendHalf>,
    server_addr: SocksAddr,
}

#[async_trait]
impl OutboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let mut buf2 = BytesMut::new();
        target.write_buf(&mut buf2, SocksAddrWireType::PortLast)?;
        buf2.put_slice(&buf);

        let ciphertext = self.dgram.encrypt(buf2).map_err(|_| shadow::crypto_err())?;
        match self.send_half.send_to(&ciphertext, &self.server_addr).await {
            Ok(_) => Ok(buf.len()),
            Err(err) => Err(err),
        }
    }
}
