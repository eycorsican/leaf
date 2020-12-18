use std::{io, net::SocketAddr};

use async_trait::async_trait;
use tokio::net::{
    udp::{RecvHalf, SendHalf},
    UdpSocket,
};

use crate::session::SocksAddr;

use super::{
    InboundDatagram, InboundDatagramRecvHalf, InboundDatagramSendHalf, OutboundDatagram,
    OutboundDatagramRecvHalf, OutboundDatagramSendHalf,
};

/// An outbound datagram simply wraps a UDP socket.
pub struct SimpleOutboundDatagram(pub UdpSocket);

impl OutboundDatagram for SimpleOutboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, s) = self.0.split();
        (
            Box::new(SimpleOutboundDatagramRecvHalf(r)),
            Box::new(SimpleOutboundDatagramSendHalf(s)),
        )
    }
}

pub struct SimpleOutboundDatagramRecvHalf(RecvHalf);

#[async_trait]
impl OutboundDatagramRecvHalf for SimpleOutboundDatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }
}

pub struct SimpleOutboundDatagramSendHalf(SendHalf);

#[async_trait]
impl OutboundDatagramSendHalf for SimpleOutboundDatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, target).await
    }
}

/// An inbound datagram simply wraps a UDP socket.
pub struct SimpleInboundDatagram(pub UdpSocket);

impl InboundDatagram for SimpleInboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (r, s) = self.0.split();
        (
            Box::new(SimpleInboundDatagramRecvHalf(r)),
            Box::new(SimpleInboundDatagramSendHalf(s)),
        )
    }
}

pub struct SimpleInboundDatagramRecvHalf(RecvHalf);

#[async_trait]
impl InboundDatagramRecvHalf for SimpleInboundDatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<SocksAddr>)> {
        let (n, src_addr) = self.0.recv_from(buf).await?;
        Ok((n, src_addr, None))
    }
}

pub struct SimpleInboundDatagramSendHalf(SendHalf);

#[async_trait]
impl InboundDatagramSendHalf for SimpleInboundDatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        _src_addr: Option<&SocksAddr>,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        self.0.send_to(buf, dst_addr).await
    }
}
