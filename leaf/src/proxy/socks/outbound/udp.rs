use std::{
    io::{Error, ErrorKind, Result},
    net::SocketAddr,
    sync::Arc,
};

use async_socks5::{AddrKind, Auth, SocksDatagram, SocksDatagramRecvHalf, SocksDatagramSendHalf};
use async_trait::async_trait;
use futures::future::TryFutureExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;

use crate::{
    app::dns_client::DnsClient,
    proxy::{
        OutboundConnect, OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf,
        OutboundTransport, UdpOutboundHandler, UdpTransportType,
    },
    session::Session,
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn udp_connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::Proxy(
            self.address.clone(),
            self.port,
            self.bind_addr,
        ))
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Packet
    }

    async fn handle_udp<'a>(
        &'a self,
        _sess: &'a Session,
        _transport: Option<OutboundTransport>,
    ) -> Result<Box<dyn OutboundDatagram>> {
        // TODO support chaining, this requires implementing our own socks5 client
        let stream = self
            .dial_tcp_stream(
                self.dns_client.clone(),
                &self.bind_addr,
                &self.address,
                &self.port,
            )
            .await?;
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let socket = SocksDatagram::associate(stream, socket, None::<Auth>, None::<AddrKind>)
            .map_err(|x| Error::new(ErrorKind::Other, x))
            .await?;
        Ok(Box::new(Datagram { socket }))
    }
}

pub struct Datagram<S> {
    pub socket: SocksDatagram<S>,
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
        let (rh, sh) = self.socket.split();
        (
            Box::new(DatagramRecvHalf(rh)),
            Box::new(DatagramSendHalf(sh)),
        )
    }
}

pub struct DatagramRecvHalf<S>(SocksDatagramRecvHalf<S>);

// unsafe impl<S> Send for DatagramRecvHalf<S> {}

#[async_trait]
impl<S> OutboundDatagramRecvHalf for DatagramRecvHalf<S>
where
    S: 'static + AsyncRead + AsyncWrite + Send + Unpin + Sync,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (n, addr) = self
            .0
            .recv_from(buf)
            .map_err(|x| Error::new(ErrorKind::Other, x))
            .await?;
        match addr {
            AddrKind::Ip(addr) => Ok((n, addr)),
            _ => Err(Error::new(
                ErrorKind::Other,
                "udp receiving domain address is not supported",
            )),
        }
    }
}

pub struct DatagramSendHalf<S>(SocksDatagramSendHalf<S>);

// unsafe impl<S> Send for DatagramSendHalf<S> {}

#[async_trait]
impl<S> OutboundDatagramSendHalf for DatagramSendHalf<S>
where
    S: 'static + AsyncRead + AsyncWrite + Send + Unpin + Sync,
{
    async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> Result<usize> {
        self.0
            .send_to(buf, target.to_owned())
            .map_err(|x| Error::new(ErrorKind::Other, x))
            .await
    }
}
