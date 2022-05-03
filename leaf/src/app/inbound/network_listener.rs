use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;

use futures::stream::StreamExt;
use log::*;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::channel as tokio_channel;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};

use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::{NatManager, UdpPacket};
use crate::proxy::*;
use crate::session::{Network, Session, SocksAddr};
use crate::Runner;

async fn handle_inbound_datagram(
    inbound_tag: String,
    socket: Box<dyn InboundDatagram>,
    sess: Option<Session>,
    nat_manager: Arc<NatManager>,
) {
    // Left-hand side socket, it's usually encapsulated with inbound protocol layers.
    let (mut lr, mut ls) = socket.split();

    // Datagrams read from the left-hand side socket would go through the NAT manager first,
    // which maintains UDP sessions, the NAT manager creates the right-hand side socket
    // by dispatching UDP sessions, then datagrams are sent to the socket by the NAT manager.
    // When the NAT manager reads some packets from the right-hand side socket, they would
    // be sent back here through a channel, then we can send them to left-hand side socket.
    let (l_tx, mut l_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) = tokio_channel(100);

    tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            let dst_addr = pkt.dst_addr.must_ip();
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

async fn handle_inbound_stream(
    stream: TcpStream,
    h: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) {
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
        inbound_tag: h.tag().clone(),
        ..Default::default()
    };

    match TcpInboundHandler::handle(h.as_ref(), sess, Box::new(stream)).await {
        Ok(res) => match res {
            InboundTransport::Stream(stream, sess) => {
                dispatcher.dispatch_tcp(sess, stream).await;
            }
            InboundTransport::Datagram(socket, sess) => {
                handle_inbound_datagram(h.tag().clone(), socket, sess, nat_manager).await;
            }
            InboundTransport::Incoming(mut incoming) => {
                while let Some(transport) = incoming.next().await {
                    match transport {
                        BaseInboundTransport::Stream(stream, sess) => {
                            let dispatcher_cloned = dispatcher.clone();
                            tokio::spawn(async move {
                                dispatcher_cloned.dispatch_tcp(sess, stream).await;
                            });
                        }
                        BaseInboundTransport::Datagram(socket, sess) => {
                            let nat_manager2 = nat_manager.clone();
                            let tag = h.tag().clone();
                            tokio::spawn(async move {
                                handle_inbound_datagram(tag, socket, sess, nat_manager2).await;
                            });
                        }
                        BaseInboundTransport::Empty => (),
                    }
                }
            }
            InboundTransport::Empty => (),
        },
        Err(e) => {
            debug!("handle inbound tcp failed: {:?}", e);
        }
    }
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
        let handler = self.handler.clone();
        let dispatcher = self.dispatcher.clone();
        let nat_manager = self.nat_manager.clone();
        let address = self.address.clone();
        let port = self.port;

        if self.handler.has_tcp() {
            let listen_addr = SocketAddr::new(address.parse::<IpAddr>()?, port);
            let tcp_task = async move {
                let listener = TcpListener::bind(&listen_addr).await.unwrap();
                info!("inbound listening tcp {}", &listen_addr);
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            tokio::spawn(handle_inbound_stream(
                                stream,
                                handler.clone(),
                                dispatcher.clone(),
                                nat_manager.clone(),
                            ));
                        }
                        Err(e) => {
                            error!("accept connection failed: {}", e);
                            break;
                        }
                    }
                }
            };
            runners.push(Box::pin(tcp_task));
        }

        if self.handler.has_udp() {
            let nat_manager = self.nat_manager.clone();
            let dispatcher = self.dispatcher.clone();
            let handler = self.handler.clone();
            let address = self.address.clone();
            let port = self.port;
            let listen_addr = SocketAddr::new(address.parse()?, port);
            let udp_task = async move {
                let socket = UdpSocket::bind(&listen_addr).await.unwrap();
                info!("inbound listening udp {}", &listen_addr);

                // FIXME spawn
                match UdpInboundHandler::handle(
                    handler.as_ref(),
                    Box::new(SimpleInboundDatagram(socket)),
                )
                .await
                {
                    Ok(res) => match res {
                        InboundTransport::Stream(stream, sess) => {
                            dispatcher.dispatch_tcp(sess, stream).await;
                        }
                        InboundTransport::Datagram(socket, sess) => {
                            handle_inbound_datagram(
                                handler.tag().clone(),
                                socket,
                                sess,
                                nat_manager,
                            )
                            .await;
                        }
                        InboundTransport::Incoming(mut incoming) => {
                            while let Some(transport) = incoming.next().await {
                                match transport {
                                    BaseInboundTransport::Stream(stream, sess) => {
                                        let dispatcher_cloned = dispatcher.clone();
                                        tokio::spawn(async move {
                                            dispatcher_cloned.dispatch_tcp(sess, stream).await;
                                        });
                                    }
                                    BaseInboundTransport::Datagram(socket, sess) => {
                                        let nat_manager2 = nat_manager.clone();
                                        let tag = handler.tag().clone();
                                        tokio::spawn(async move {
                                            handle_inbound_datagram(
                                                tag,
                                                socket,
                                                sess,
                                                nat_manager2,
                                            )
                                            .await;
                                        });
                                    }
                                    BaseInboundTransport::Empty => (),
                                }
                            }
                        }
                        InboundTransport::Empty => (),
                    },
                    Err(e) => {
                        debug!("handle inbound socket failed: {}", e);
                    }
                }
            };
            runners.push(Box::pin(udp_task));
        }

        Ok(runners)
    }
}
