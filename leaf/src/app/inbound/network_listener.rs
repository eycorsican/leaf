use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use futures::stream::StreamExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::channel as tokio_channel;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};
use tokio::time::timeout;
use tracing::{debug, info, trace, warn};

use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::{NatManager, UdpPacket};
use crate::proxy::*;
use crate::session::{Network, Session, SocksAddr};
use crate::Runner;

// Handle an inbound datagram, which is similar to a UDP socket, managed by NAT
// manager.
async fn handle_inbound_datagram(
    inbound_tag: String,
    socket: Box<dyn InboundDatagram>,
    sess: Option<Session>,
    nat_manager: Arc<NatManager>,
) {
    // Left-hand side socket, it's usually encapsulated with inbound protocol
    // layers.
    let (mut lr, mut ls) = socket.split();

    // Datagrams read from the left-hand side socket would go through the NAT
    // manager first, which maintains UDP sessions, the NAT manager creates the
    // right-hand side socket by dispatching UDP sessions, then datagrams are sent
    // to the socket by the NAT manager. When the NAT manager reads some packets
    // from the right-hand side socket, they would be sent back here through a
    // channel, then we can send them to left-hand side socket.
    let (l_tx, mut l_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) =
        tokio_channel(*crate::option::UDP_UPLINK_CHANNEL_SIZE);

    tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            let dst_addr = pkt.dst_addr.must_ip();
            trace!(
                "inbound send UDP packet: dst {}, {} bytes",
                &dst_addr,
                pkt.data.len()
            );
            if let Err(e) = ls.send_to(&pkt.data[..], &pkt.src_addr, &dst_addr).await {
                debug!("Send datagram failed: {}", e);
                break;
            }
        }
        if let Err(e) = ls.close().await {
            debug!("Failed to close inbound datagram: {}", e);
        }
    });

    let mut buf = vec![0u8; *crate::option::DATAGRAM_BUFFER_SIZE * 1024];
    loop {
        match lr.recv_from(&mut buf).await {
            Err(ProxyError::DatagramFatal(e)) => {
                debug!("Fatal error when receiving datagram: {}", e);
                break;
            }
            Err(ProxyError::DatagramWarn(e)) => {
                debug!("Warning when receiving datagram: {}", e);
                continue;
            }
            Ok((n, dgram_src, dst_addr)) => {
                trace!(
                    "inbound received UDP packet: src {}, {} bytes",
                    &dgram_src.address,
                    n
                );
                let pkt = UdpPacket::new(
                    (&buf[..n]).to_vec(),
                    SocksAddr::from(dgram_src.address),
                    dst_addr,
                );
                nat_manager
                    .send(sess.as_ref(), &dgram_src, &inbound_tag, &l_tx, pkt)
                    .await;
            }
        }
    }
}

// Handle an inbound transport.
async fn handle_inbound_transport(
    transport: AnyInboundTransport,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) {
    match transport {
        // A reliable transport.
        InboundTransport::Stream(stream, sess) => {
            dispatcher.dispatch_stream(sess, stream).await;
        }
        // An unreliable transport.
        InboundTransport::Datagram(socket, sess) => {
            handle_inbound_datagram(handler.tag().clone(), socket, sess, nat_manager).await;
        }
        // A multiplexed transport.
        InboundTransport::Incoming(mut incoming) => {
            while let Some(transport) = incoming.next().await {
                match transport {
                    BaseInboundTransport::Stream(stream, mut sess) => {
                        let dispatcher_cloned = dispatcher.clone();
                        sess.inbound_tag = handler.tag().clone();
                        tokio::spawn(async move {
                            dispatcher_cloned.dispatch_stream(sess, stream).await
                        });
                    }
                    BaseInboundTransport::Datagram(socket, sess) => {
                        tokio::spawn(handle_inbound_datagram(
                            handler.tag().clone(),
                            socket,
                            sess,
                            nat_manager.clone(),
                        ));
                    }
                    _ => (),
                }
            }
        }
        _ => (),
    }
}

// Handle an accepted inbound TCP stream.
async fn handle_inbound_tcp_stream(
    stream: TcpStream,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> io::Result<()> {
    let source = stream
        .peer_addr()
        .unwrap_or_else(|_| *crate::option::UNSPECIFIED_BIND_ADDR);
    let local_addr = stream
        .local_addr()
        .unwrap_or_else(|_| *crate::option::UNSPECIFIED_BIND_ADDR);
    let sess = Session {
        network: Network::Tcp,
        source,
        local_addr,
        inbound_tag: handler.tag().clone(),
        ..Default::default()
    };
    // Transforms the TCP stream into an inbound transport.
    let transport = timeout(
        Duration::from_secs(*crate::option::INBOUND_ACCEPT_TIMEOUT),
        handler.stream()?.handle(sess, Box::new(stream)),
    )
    .await??;
    handle_inbound_transport(transport, handler, dispatcher, nat_manager).await;
    Ok(())
}

// Handle inbounds which listen on TCP.
async fn handle_tcp_listen(
    listen_addr: SocketAddr,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> io::Result<()> {
    let listener = crate::proxy::TcpListener::bind(&listen_addr).await?;
    info!("listening tcp {}", &listen_addr);
    loop {
        let (stream, _) = listener.accept().await?;
        let handler_cloned = handler.clone();
        let dispatcher_cloned = dispatcher.clone();
        let nat_manager_cloned = nat_manager.clone();
        tokio::spawn(async move {
            // Handle each TCP stream.
            if let Err(e) = handle_inbound_tcp_stream(
                stream,
                handler_cloned,
                dispatcher_cloned,
                nat_manager_cloned,
            )
            .await
            {
                debug!("handle inbound stream failed: {}", e);
            }
        });
    }
}

// Handle inbounds which bind on UDP.
async fn handle_udp_listen(
    listen_addr: SocketAddr,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> io::Result<()> {
    let socket = UdpSocket::bind(&listen_addr).await?;
    info!("listening udp {}", &listen_addr);
    // Transforms the UDP socket into an inbound transport.
    let transport = handler
        .datagram()?
        .handle(Box::new(SimpleInboundDatagram(socket)))
        .await?;
    handle_inbound_transport(transport, handler, dispatcher, nat_manager).await;
    Ok(())
}

pub struct NetworkInboundListener {
    pub address: String,
    pub port: u16,
    pub handler: AnyInboundHandler,
    pub dispatcher: Arc<Dispatcher>,
    pub nat_manager: Arc<NatManager>,
}

impl NetworkInboundListener {
    pub fn listen(&self) -> Result<Vec<Runner>> {
        let mut runners: Vec<Runner> = Vec::new();
        let listen_addr = SocketAddr::new(self.address.parse()?, self.port);
        // Check whether this inbound listens on TCP.
        if self.handler.stream().is_ok() {
            let listen_addr_cloned = listen_addr.clone();
            let handler_cloned = self.handler.clone();
            let dispatcher_cloned = self.dispatcher.clone();
            let nat_manager_cloned = self.nat_manager.clone();
            runners.push(Box::pin(async move {
                if let Err(e) = handle_tcp_listen(
                    listen_addr_cloned,
                    handler_cloned,
                    dispatcher_cloned,
                    nat_manager_cloned,
                )
                .await
                {
                    warn!("handler tcp listen failed: {}", e);
                }
            }));
        }
        // Check whether this inbound binds on UDP.
        if self.handler.datagram().is_ok() {
            let listen_addr_cloned = listen_addr.clone();
            let handler_cloned = self.handler.clone();
            let dispatcher_cloned = self.dispatcher.clone();
            let nat_manager_cloned = self.nat_manager.clone();
            runners.push(Box::pin(async move {
                if let Err(e) = handle_udp_listen(
                    listen_addr_cloned,
                    handler_cloned,
                    dispatcher_cloned,
                    nat_manager_cloned,
                )
                .await
                {
                    warn!("handler udp listen failed: {}", e);
                }
            }));
        }
        Ok(runners)
    }
}
