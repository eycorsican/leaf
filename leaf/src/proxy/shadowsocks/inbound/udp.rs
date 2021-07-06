use std::cmp::min;
use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use log::*;

use crate::{
    proxy::*,
    session::{SocksAddr, SocksAddrWireType},
};

use super::shadow::{self, ShadowedDatagram};

pub struct Handler {
    pub cipher: String,
    pub password: String,
}

#[async_trait]
impl UdpInboundHandler for Handler {
    type UStream = AnyStream;
    type UDatagram = AnyInboundDatagram;

    async fn handle<'a>(
        &'a self,
        socket: Self::UDatagram,
    ) -> io::Result<InboundTransport<Self::UStream, Self::UDatagram>> {
        let dgram = ShadowedDatagram::new(&self.cipher, &self.password)?;
        Ok(InboundTransport::Datagram(Box::new(Datagram {
            dgram,
            socket,
        })))
    }
}

pub struct Datagram {
    dgram: ShadowedDatagram,
    socket: Box<dyn InboundDatagram>,
}

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let dgram = Arc::new(self.dgram);
        let (rh, sh) = self.socket.split();
        (
            Box::new(DatagramRecvHalf(dgram.clone(), rh)),
            Box::new(DatagramSendHalf(dgram, sh)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        unimplemented!();
    }
}

pub struct DatagramRecvHalf(Arc<ShadowedDatagram>, Box<dyn InboundDatagramRecvHalf>);

#[async_trait]
impl InboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<(usize, DatagramSource, Option<SocksAddr>)> {
        let mut recv_buf = BytesMut::new();
        recv_buf.resize(2 * 1024, 0);
        let (n, src_addr, _) = self.1.recv_from(&mut recv_buf).await?;
        recv_buf.resize(n, 0);
        let plaintext = match self.0.decrypt(recv_buf) {
            Ok(v) => v,
            Err(e) => {
                warn!("decrypt ss message failed: {}", e);
                return Ok((0, src_addr, None));
            }
        };
        let dst_addr = match SocksAddr::try_from((&plaintext[..], SocksAddrWireType::PortLast)) {
            Ok(v) => v,
            Err(e) => {
                warn!("read addr from ss message failed: {}", e);
                return Ok((0, src_addr, None));
            }
        };
        let header_size = dst_addr.size();
        let payload_size = plaintext.len() - header_size;
        let to_recv = min(buf.len(), payload_size);
        if to_recv < payload_size {
            warn!("truncated pkt");
        }
        (&mut buf[..to_recv]).copy_from_slice(&plaintext[header_size..header_size + to_recv]);
        Ok((payload_size, src_addr, Some(dst_addr)))
    }
}

pub struct DatagramSendHalf(Arc<ShadowedDatagram>, Box<dyn InboundDatagramSendHalf>);

#[async_trait]
impl InboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: Option<&SocksAddr>,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let mut send_buf = BytesMut::new();

        if let Some(src_addr) = src_addr {
            src_addr.write_buf(&mut send_buf, SocksAddrWireType::PortLast)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "sending message without source",
            ));
        }

        send_buf.put_slice(buf);
        let ciphertext = self.0.encrypt(send_buf).map_err(|_| shadow::crypto_err())?;
        self.1.send_to(&ciphertext[..], None, dst_addr).await
    }
}
