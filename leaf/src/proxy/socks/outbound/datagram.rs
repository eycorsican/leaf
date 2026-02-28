use std::{
    io::{Error, Result},
    sync::Arc,
};

use async_socks5::{AddrKind, Auth, SocksDatagram};
use async_trait::async_trait;
use futures::future::TryFutureExt;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{app::SyncDnsClient, common::resolver::Resolver, proxy::*, session::*};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub dns_client: SyncDnsClient,
}

impl TcpConnector for Handler {}
impl UdpConnector for Handler {}

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
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        // TODO support chaining, this requires implementing our own socks5 client
        let stream = self
            .new_tcp_stream(self.dns_client.clone(), &self.address, &self.port)
            .await?;
        let mut indicator = sess.source;
        if let Ok(ip) = self.address.parse::<IpAddr>() {
            if ip.is_loopback() {
                indicator = SocketAddr::new(ip, 0);
            }
        }
        let socket = self.new_udp_socket(&indicator).await?;

        // Resolve the SOCKS server address to IP (handles both IP and domain names)
        let mut resolver = Resolver::new(self.dns_client.clone(), &self.address, &self.port)
            .await
            .map_err(|e| Error::other(format!("resolve SOCKS server address failed: {}", e)))?;
        let server_addr = resolver
            .next()
            .ok_or_else(|| Error::other("no resolved address for SOCKS server"))?;

        let auth = match (&self.username, &self.password) {
            (auth_username, _) if auth_username.is_empty() => None,
            (auth_username, auth_password) => Some(Auth {
                username: auth_username.to_owned(),
                password: auth_password.to_owned(),
            }),
        };

        let socket = SocksDatagram::associate(stream, socket, auth, server_addr.into())
            .map_err(Error::other)
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
        let rh = Arc::new(self.socket);
        let sh = rh.clone();
        (
            Box::new(DatagramRecvHalf(rh)),
            Box::new(DatagramSendHalf(sh)),
        )
    }
}

pub struct DatagramRecvHalf<S>(Arc<SocksDatagram<S>>);

#[async_trait]
impl<S> OutboundDatagramRecvHalf for DatagramRecvHalf<S>
where
    S: 'static + AsyncRead + AsyncWrite + Send + Unpin + Sync,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocksAddr)> {
        let (n, addr) = self.0.recv_from(buf).map_err(Error::other).await?;
        match addr {
            AddrKind::Ip(addr) => Ok((n, SocksAddr::Ip(addr))),
            AddrKind::Domain(domain, port) => Ok((n, SocksAddr::Domain(domain, port))),
        }
    }
}

pub struct DatagramSendHalf<S>(Arc<SocksDatagram<S>>);

#[async_trait]
impl<S> OutboundDatagramSendHalf for DatagramSendHalf<S>
where
    S: 'static + AsyncRead + AsyncWrite + Send + Unpin + Sync,
{
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> Result<usize> {
        match target {
            SocksAddr::Ip(a) => {
                self.0
                    .send_to(buf, a.to_owned())
                    .map_ok(|_| buf.len())
                    .map_err(Error::other)
                    .await
            }
            SocksAddr::Domain(domain, port) => {
                self.0
                    .send_to(buf, (domain.to_owned(), *port))
                    .map_ok(|_| buf.len())
                    .map_err(Error::other)
                    .await
            }
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        // FIXME implement our own socks5 outbound to propagate this.
        Ok(())
    }
}
