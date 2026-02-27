use std::io;

use crate::proxy::mptp::mptp_conn::protocol::{
    Address, HandshakeRequest, CMD_CONNECT, CMD_UDP, VER,
};
use crate::proxy::mptp::mptp_conn::{MptpDatagram, MptpStream};
use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
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
        let (tx, mut rx) = mpsc::unbounded_channel();
        let cid = Uuid::new_v4();

        // Clone session and set destination to MPTP server
        let mut server_sess = sess.clone();
        server_sess.destination = SocksAddr::try_from((self.address.clone(), self.port))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let target_addr = match &sess.destination {
            SocksAddr::Ip(addr) => match addr {
                std::net::SocketAddr::V4(v4) => Address::Ipv4(*v4.ip()),
                std::net::SocketAddr::V6(v6) => Address::Ipv6(*v6.ip()),
            },
            SocksAddr::Domain(domain, _) => Address::Domain(domain.clone()),
        };
        let target_port = sess.destination.port();

        // 1. Establish sub-connections in parallel
        for (i, actor) in self.actors.iter().enumerate() {
            let actor = actor.clone();
            let server_sess = server_sess.clone();
            let dns_client = self.dns_client.clone();
            let tx = tx.clone();
            let target_addr = target_addr.clone();
            let cid = cid;
            let cmd = cmd;
            let target_port = target_port;

            tokio::spawn(async move {
                if let Ok(stream_handler) = actor.stream() {
                    // Try to connect if the actor requires a connection
                    let stream_opt =
                        match connect_stream_outbound(&server_sess, dns_client, &actor).await {
                            Ok(opt) => opt,
                            Err(e) => {
                                tracing::warn!("Failed to connect sub {}: {}", i, e);
                                return;
                            }
                        };

                    match stream_handler.handle(&server_sess, None, stream_opt).await {
                        Ok(mut stream) => {
                            // 2. Perform Handshake on each sub-connection
                            let req = HandshakeRequest {
                                ver: VER,
                                cid,
                                cmd,
                                dst_addr: target_addr,
                                dst_port: target_port,
                            };

                            let mut buf = BytesMut::new();
                            req.encode(&mut buf);

                            // Add a small delay to ensure handshake is sent as a distinct packet if possible
                            // or to allow server to accept connection properly before data
                            // tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                            if let Err(e) = stream.write_all(&buf).await {
                                tracing::warn!("Failed to send handshake for sub {}: {}", i, e);
                                return;
                            }

                            let _ = tx.send((stream, Some(cid)));
                        }
                        Err(e) => {
                            tracing::warn!("Failed to handle sub {}: {}", i, e);
                        }
                    }
                }
            });
        }

        // Drop our local tx so that rx.recv() returns None when all tasks finish
        drop(tx);

        // Wait for the first successful connection
        if let Some((first_stream, _)) = rx.recv().await {
            // 3. Create MptpStream with the first stream and the receiver for subsequent ones
            Ok(MptpStream::new_with_receiver_and_initial(
                vec![first_stream],
                rx,
            ))
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "No available sub-connections",
            ))
        }
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
