use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use futures::TryFutureExt;
use tokio::net::UdpSocket;

use crate::{
    app::SyncDnsClient,
    session::{DatagramSource, SocksAddr},
};

use super::{
    InboundDatagram, InboundDatagramRecvHalf, InboundDatagramSendHalf, OutboundDatagram,
    OutboundDatagramRecvHalf, OutboundDatagramSendHalf,
};

/// An outbound datagram simply wraps a UDP socket.
pub struct SimpleOutboundDatagram {
    inner: UdpSocket,
    destination: Option<SocksAddr>,
    dns_client: SyncDnsClient,
}

impl SimpleOutboundDatagram {
    pub fn new(
        inner: UdpSocket,
        destination: Option<SocksAddr>,
        dns_client: SyncDnsClient,
    ) -> Self {
        SimpleOutboundDatagram {
            inner,
            destination,
            dns_client,
        }
    }
}

impl OutboundDatagram for SimpleOutboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let r = Arc::new(self.inner);
        let s = r.clone();
        (
            Box::new(SimpleOutboundDatagramRecvHalf(r, self.destination)),
            Box::new(SimpleOutboundDatagramSendHalf(s, self.dns_client)),
        )
    }
}

pub struct SimpleOutboundDatagramRecvHalf(Arc<UdpSocket>, Option<SocksAddr>);

#[async_trait]
impl OutboundDatagramRecvHalf for SimpleOutboundDatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        match self.0.recv_from(buf).await {
            Ok((n, a)) => {
                if self.1.is_some() {
                    Ok((n, self.1.as_ref().unwrap().clone()))
                } else {
                    Ok((n, SocksAddr::Ip(a)))
                }
            }
            Err(e) => Err(e),
        }
    }
}

pub struct SimpleOutboundDatagramSendHalf(Arc<UdpSocket>, SyncDnsClient);

#[async_trait]
impl OutboundDatagramSendHalf for SimpleOutboundDatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let addr = match target {
            SocksAddr::Domain(domain, port) => {
                let ips = {
                    self.1
                        .read()
                        .await
                        .lookup(domain)
                        .map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("lookup {} failed: {}", domain, e),
                            )
                        })
                        .await?
                };
                if ips.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "could not resolve to any address",
                    ));
                }
                SocketAddr::new(ips[0], port.to_owned())
            }
            SocksAddr::Ip(a) => a.to_owned(),
        };
        self.0.send_to(buf, &addr).await
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
        let r = Arc::new(self.0);
        let s = r.clone();
        (
            Box::new(SimpleInboundDatagramRecvHalf(r)),
            Box::new(SimpleInboundDatagramSendHalf(s)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        self.0.into_std()
    }
}

pub struct SimpleInboundDatagramRecvHalf(Arc<UdpSocket>);

#[async_trait]
impl InboundDatagramRecvHalf for SimpleInboundDatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<(usize, DatagramSource, Option<SocksAddr>)> {
        let (n, src_addr) = self.0.recv_from(buf).await?;
        Ok((n, DatagramSource::new(src_addr, None), None))
    }
}

pub struct SimpleInboundDatagramSendHalf(Arc<UdpSocket>);

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
