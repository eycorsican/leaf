use std::{io, net::IpAddr};

use async_trait::async_trait;
use futures::TryFutureExt;

use crate::{
    proxy::*,
    session::{Session, SocksAddr},
};

/// Handler with a redirect target address.
pub struct Handler {
    pub address: String,
    pub port: u16,
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    type UStream = AnyStream;
    type Datagram = AnyOutboundDatagram;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Proxy(self.address.clone(), self.port))
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Datagram
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<Self::UStream, Self::Datagram>>,
    ) -> io::Result<Self::Datagram> {
        let dgram = if let Some(OutboundTransport::Datagram(dgram)) = transport {
            dgram
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid input"));
        };
        let target = SocksAddr::from((
            self.address.parse::<IpAddr>().map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("parse IpAddr failed: {}", e))
            })?,
            self.port,
        ));
        Ok(Box::new(Datagram {
            socket: dgram,
            destination: sess.destination.clone(),
            target,
        }))
    }
}

pub struct Datagram {
    pub socket: Box<dyn OutboundDatagram>,
    // The destination application datagrams send to.
    pub destination: SocksAddr,
    // The target we would like to redirect to.
    pub target: SocksAddr,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, s) = self.socket.split();
        (
            Box::new(DatagramRecvHalf(r, self.destination)),
            Box::new(DatagramSendHalf(s, self.target)),
        )
    }
}

pub struct DatagramRecvHalf(Box<dyn OutboundDatagramRecvHalf>, SocksAddr);

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        // Always rewrite the address, thus would allow only symmetric NAT sessions.
        let dest = self.1.clone();
        self.0.recv_from(buf).map_ok(|(n, _)| (n, dest)).await
    }
}

pub struct DatagramSendHalf(Box<dyn OutboundDatagramSendHalf>, SocksAddr);

#[async_trait]
impl OutboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], _target: &SocksAddr) -> io::Result<usize> {
        self.0.send_to(buf, &self.1).await
    }
}
