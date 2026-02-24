use std::io;

use crate::proxy::mptp::mptp_conn::protocol::{
    Address, HandshakeRequest, CMD_CONNECT, CMD_UDP, VER,
};
use crate::proxy::mptp::mptp_conn::{MptpDatagram, MptpStream};
use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{
    app::SyncDnsClient,
    proxy::{
        connect_stream_outbound, AnyOutboundDatagram, AnyOutboundHandler, AnyOutboundTransport,
        AnyStream, DatagramTransportType, OutboundConnect, OutboundDatagramHandler,
        OutboundStreamHandler,
    },
    session::{Session, SocksAddr},
};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    pub address: String,
    pub port: u16,
    pub dns_client: SyncDnsClient,
}

impl Handler {
    async fn establish_mptp_stream(
        &self,
        sess: &Session,
        cmd: u8,
    ) -> io::Result<MptpStream<AnyStream>> {
        let mut sub_streams = Vec::new();

        // Clone session and set destination to MPTP server
        let mut server_sess = sess.clone();
        server_sess.destination = SocksAddr::try_from((self.address.clone(), self.port))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let cid = Uuid::new_v4();
        let target_addr = match &sess.destination {
            SocksAddr::Ip(addr) => match addr {
                std::net::SocketAddr::V4(v4) => Address::Ipv4(*v4.ip()),
                std::net::SocketAddr::V6(v6) => Address::Ipv6(*v6.ip()),
            },
            SocksAddr::Domain(domain, _) => Address::Domain(domain.clone()),
        };
        let target_port = sess.destination.port();

        // 1. Establish sub-connections
        for (i, actor) in self.actors.iter().enumerate() {
            if let Ok(stream_handler) = actor.stream() {
                // Try to connect if the actor requires a connection
                let stream_opt: Option<AnyStream> =
                    connect_stream_outbound(&server_sess, self.dns_client.clone(), actor)
                        .await
                        .map_err(|e| {
                            io::Error::new(io::ErrorKind::Other, format!("connect failed: {}", e))
                        })?;

                match stream_handler.handle(&server_sess, None, stream_opt).await {
                    Ok(mut stream) => {
                        // 2. Perform Handshake on each sub-connection
                        let req = HandshakeRequest {
                            ver: VER,
                            cid,
                            cmd,
                            dst_addr: target_addr.clone(),
                            dst_port: target_port,
                        };

                        let mut buf = BytesMut::new();
                        req.encode(&mut buf);

                        if let Err(e) = stream.write_all(&buf).await {
                            tracing::warn!("Failed to send handshake for sub {}: {}", i, e);
                            continue;
                        }

                        sub_streams.push(stream);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to connect sub {}: {}", i, e);
                    }
                }
            }
        }

        if sub_streams.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "No available sub-connections",
            ));
        }

        // 3. Create MptpStream
        Ok(MptpStream::new(sub_streams, cid))
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream session: {:?}", sess);
        let mptp_stream = self.establish_mptp_stream(sess, CMD_CONNECT).await?;
        Ok(Box::new(mptp_stream))
    }
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Reliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram session: {:?}", sess);
        let mptp_stream = self.establish_mptp_stream(sess, CMD_UDP).await?;
        let mptp_datagram = MptpDatagram::new(mptp_stream);
        Ok(Box::new(mptp_datagram))
    }
}
