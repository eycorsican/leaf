use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};

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
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        let dgram = ShadowedDatagram::new(&self.cipher, &self.password)?;
        Ok(InboundTransport::Datagram(
            Box::new(Datagram { dgram, socket }),
            None,
        ))
    }
}

pub struct Datagram {
    dgram: ShadowedDatagram,
    socket: AnyInboundDatagram,
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
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let mut recv_buf = BytesMut::new();
        recv_buf.resize(buf.len(), 0);
        let (n, src_addr, _) = self.1.recv_from(&mut recv_buf).await?;
        recv_buf.resize(n, 0);
        let plaintext = self
            .0
            .decrypt(recv_buf)
            .map_err(|e| ProxyError::DatagramWarn(anyhow!("Decrypt payload failed: {}", e)))?;
        let dst_addr = SocksAddr::try_from((&plaintext[..], SocksAddrWireType::PortLast))
            .map_err(|e| ProxyError::DatagramWarn(anyhow!("Parse target address failed: {}", e)))?;
        let header_size = dst_addr.size();
        let payload_size = plaintext.len() - header_size;
        assert!(buf.len() >= payload_size);
        buf[..payload_size].copy_from_slice(&plaintext[header_size..header_size + payload_size]);
        Ok((payload_size, src_addr, dst_addr))
    }
}

pub struct DatagramSendHalf(Arc<ShadowedDatagram>, Box<dyn InboundDatagramSendHalf>);

#[async_trait]
impl InboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let mut send_buf = BytesMut::new();
        src_addr.write_buf(&mut send_buf, SocksAddrWireType::PortLast);
        send_buf.put_slice(buf);
        let ciphertext = self.0.encrypt(send_buf).map_err(|_| shadow::crypto_err())?;
        self.1.send_to(&ciphertext[..], src_addr, dst_addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.1.close().await
    }
}
