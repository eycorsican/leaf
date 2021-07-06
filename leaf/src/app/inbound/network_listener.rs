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
    nat_manager: Arc<NatManager>,
) {
    let (mut client_sock_recv, mut client_sock_send) = socket.split();

    let (client_ch_tx, mut client_ch_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) =
        tokio_channel(100);

    tokio::spawn(async move {
        while let Some(pkt) = client_ch_rx.recv().await {
            let dst_addr = match pkt.dst_addr {
                Some(a) => a,
                None => {
                    warn!("ignore udp pkt with unexpected empty dst addr");
                    continue;
                }
            };
            let dst_addr = match dst_addr {
                SocksAddr::Ip(a) => a,
                _ => {
                    error!("unexpected domain address");
                    continue;
                }
            };
            let src_addr = match pkt.src_addr {
                Some(a) => a,
                None => {
                    warn!("ignore udp pkt with unexpected empty src addr");
                    continue;
                }
            };
            if let Err(e) = client_sock_send
                .send_to(&pkt.data[..], Some(&src_addr), &dst_addr)
                .await
            {
                warn!("send udp pkt failed: {}", e);
                return;
            }
        }
        debug!("udp downlink ended");
    });

    let mut buf = [0u8; 2 * 1024];
    loop {
        match client_sock_recv.recv_from(&mut buf).await {
            Err(e) => {
                debug!("udp recv error: {}", e);
                break;
            }
            Ok((n, dgram_src, dst_addr)) => {
                if n == 0 {
                    // Means a proxy layer error, e.g. the ss handler failed to
                    // decrypt a message.
                    //
                    // TODO use error matching for this purpose?
                    //
                    // The problem here is we don't want to exit the receive loop
                    // because of a proxy protocol error if the underlying socket
                    // is UDP-based. But we do wnat to exit the loop and the task
                    // spawned above if the underlying socket is TCP-based. More
                    // careful investigation needed.
                    continue;
                }
                let dst_addr = if let Some(dst_addr) = dst_addr {
                    dst_addr
                } else {
                    warn!("inbound datagram receives message without destination");
                    continue;
                };
                if !nat_manager.contains_key(&dgram_src).await {
                    let sess = Session {
                        network: Network::Udp,
                        source: dgram_src.address,
                        destination: dst_addr.clone(),
                        inbound_tag: inbound_tag.clone(),
                        ..Default::default()
                    };

                    nat_manager
                        .add_session(&sess, dgram_src, client_ch_tx.clone())
                        .await;

                    debug!(
                        "added udp session {} -> {} ({})",
                        &dgram_src,
                        &dst_addr.to_string(),
                        nat_manager.size().await,
                    );
                }

                let pkt = UdpPacket {
                    data: (&buf[..n]).to_vec(),
                    src_addr: Some(SocksAddr::from(dgram_src.address)),
                    dst_addr: Some(dst_addr),
                };
                nat_manager.send(&dgram_src, pkt).await;
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
            InboundTransport::Stream(stream, mut sess) => {
                dispatcher.dispatch_tcp(&mut sess, stream).await;
            }
            InboundTransport::Datagram(socket) => {
                handle_inbound_datagram(h.tag().clone(), socket, nat_manager).await;
            }
            InboundTransport::Incoming(mut incoming) => {
                while let Some(transport) = incoming.next().await {
                    match transport {
                        BaseInboundTransport::Stream(stream, mut sess) => {
                            let dispatcher2 = dispatcher.clone();
                            tokio::spawn(async move {
                                dispatcher2.dispatch_tcp(&mut sess, stream).await;
                            });
                        }
                        BaseInboundTransport::Datagram(socket) => {
                            let nat_manager2 = nat_manager.clone();
                            let tag = h.tag().clone();
                            tokio::spawn(async move {
                                handle_inbound_datagram(tag, socket, nat_manager2).await;
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
                        InboundTransport::Stream(stream, mut sess) => {
                            dispatcher.dispatch_tcp(&mut sess, stream).await;
                        }
                        InboundTransport::Datagram(socket) => {
                            handle_inbound_datagram(handler.tag().clone(), socket, nat_manager)
                                .await;
                        }
                        InboundTransport::Incoming(mut incoming) => {
                            while let Some(transport) = incoming.next().await {
                                match transport {
                                    BaseInboundTransport::Stream(stream, mut sess) => {
                                        let dispatcher2 = dispatcher.clone();
                                        tokio::spawn(async move {
                                            dispatcher2.dispatch_tcp(&mut sess, stream).await;
                                        });
                                    }
                                    BaseInboundTransport::Datagram(socket) => {
                                        let nat_manager2 = nat_manager.clone();
                                        let tag = handler.tag().clone();
                                        tokio::spawn(async move {
                                            handle_inbound_datagram(tag, socket, nat_manager2)
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
