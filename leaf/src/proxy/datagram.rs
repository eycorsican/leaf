use std::{io, net::SocketAddr};

use async_trait::async_trait;
use tokio::net::{
    udp::{RecvHalf, SendHalf},
    UdpSocket,
};

use super::{ProxyDatagram, ProxyDatagramRecvHalf, ProxyDatagramSendHalf};

pub struct SimpleDatagramRecvHalf(RecvHalf);

#[async_trait]
impl ProxyDatagramRecvHalf for SimpleDatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }
}

pub struct SimpleDatagramSendHalf(SendHalf);

#[async_trait]
impl ProxyDatagramSendHalf for SimpleDatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, target).await
    }
}

pub struct SimpleDatagram(pub UdpSocket);

impl ProxyDatagram for SimpleDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn ProxyDatagramRecvHalf>,
        Box<dyn ProxyDatagramSendHalf>,
    ) {
        let (r, s) = self.0.split();
        (
            Box::new(SimpleDatagramRecvHalf(r)),
            Box::new(SimpleDatagramSendHalf(s)),
        )
    }
}
