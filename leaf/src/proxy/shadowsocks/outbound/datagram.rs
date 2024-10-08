use std::{convert::TryFrom, io, sync::Arc};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};

use crate::{proxy::*, session::*};

use super::shadow::{self, ShadowedDatagram};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Udp, self.address.clone(), self.port)
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let server_addr = SocksAddr::try_from((&self.address, self.port))?;

        let socket = if let Some(OutboundTransport::Datagram(socket)) = transport {
            socket
        } else {
            // Don't accept stream transport because we can't determine datagram
            // boundary.
            return Err(io::Error::new(io::ErrorKind::Other, "invalid ss input"));
        };

        let dgram = ShadowedDatagram::new(&self.cipher, &self.password)?;

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
        let mut recv_buf = BytesMut::new();
        recv_buf.resize(buf.len(), 0);
        let (n, _) = self.1.recv_from(&mut recv_buf).await?;
        recv_buf.resize(n, 0);
        let plaintext = self.0.decrypt(recv_buf).map_err(|_| shadow::crypto_err())?;
        let src_addr = SocksAddr::try_from((&plaintext[..], SocksAddrWireType::PortLast))?;
        let payload_len = plaintext.len() - src_addr.size();
        assert!(payload_len <= buf.len());
        buf[..payload_len]
            .copy_from_slice(&plaintext[src_addr.size()..src_addr.size() + payload_len]);
        Ok((payload_len, self.2.clone().unwrap_or(src_addr)))
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
        let mut send_buf = BytesMut::new();
        target.write_buf(&mut send_buf, SocksAddrWireType::PortLast);
        send_buf.put_slice(buf);
        let ciphertext = self
            .dgram
            .encrypt(send_buf)
            .map_err(|_| shadow::crypto_err())?;
        self.send_half
            .send_to(&ciphertext, &self.server_addr)
            .map_ok(|_| buf.len())
            .await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.send_half.close().await
    }
}
