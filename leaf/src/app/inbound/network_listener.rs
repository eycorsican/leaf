use std::sync::Arc;

use log::*;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::stream::StreamExt;
use tokio::sync::mpsc::channel as tokio_channel;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};

use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::{NatManager, UdpPacket};
use crate::proxy::InboundHandler;
use crate::proxy::{InboundDatagram, InboundTransport, SimpleInboundDatagram, SimpleProxyStream};
use crate::session::{Session, SocksAddr};
use crate::Runner;

use super::InboundListener;

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
            Ok((n, src_addr, dst_addr)) => {
                let dst_addr = if let Some(dst_addr) = dst_addr {
                    dst_addr
                } else {
                    warn!("inbound datagram receives message without destination");
                    continue;
                };
                if !nat_manager.contains_key(&src_addr).await {
                    let sess = Session {
                        source: src_addr,
                        local_addr: "0.0.0.0:0".parse().unwrap(),
                        destination: dst_addr.clone(),
                        inbound_tag: inbound_tag.clone(),
                    };

                    nat_manager
                        .add_session(&sess, src_addr, client_ch_tx.clone())
                        .await;

                    debug!(
                        "added udp session {}:{} -> {} ({})",
                        &src_addr.ip(),
                        &src_addr.port(),
                        &dst_addr.to_string(),
                        nat_manager.size().await,
                    );
                }

                let pkt = UdpPacket {
                    data: (&buf[..n]).to_vec(),
                    src_addr: Some(SocksAddr::from(src_addr)),
                    dst_addr: Some(dst_addr),
                };
                nat_manager.send(&src_addr, pkt).await;
            }
        }
    }
}

async fn handle_inbound_stream(
    stream: TcpStream,
    handler: Arc<dyn InboundHandler>,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) {
    let source = stream
        .peer_addr()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    let local_addr = stream
        .local_addr()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    let sess = Session {
        source,
        local_addr,
        destination: SocksAddr::empty_ipv4(),
        inbound_tag: handler.tag().clone(),
    };

    match handler
        .handle_tcp(InboundTransport::Stream(
            Box::new(SimpleProxyStream(stream)),
            sess,
        ))
        .await
    {
        Ok(res) => match res {
            InboundTransport::Stream(stream, mut sess) => {
                let _ = dispatcher.dispatch_tcp(&mut sess, stream).await;
            }
            InboundTransport::Datagram(socket) => {
                handle_inbound_datagram(handler.tag().clone(), socket, nat_manager).await;
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
    pub handler: Arc<dyn InboundHandler>,
    pub dispatcher: Arc<Dispatcher>,
    pub nat_manager: Arc<NatManager>,
}

impl InboundListener for NetworkInboundListener {
    fn listen(&self) -> Vec<Runner> {
        let mut runners: Vec<Runner> = Vec::new();
        let handler = self.handler.clone();
        let dispatcher = self.dispatcher.clone();
        let nat_manager = self.nat_manager.clone();
        let address = self.address.clone();
        let port = self.port;

        if self.handler.has_tcp() {
            let tcp_task = async move {
                let mut listener = TcpListener::bind(format!("{}:{}", address, port).as_str())
                    .await
                    .unwrap();
                info!("inbound listening tcp {}:{}", address, port);
                while let Some(stream) = listener.next().await {
                    match stream {
                        Ok(stream) => {
                            tokio::spawn(handle_inbound_stream(
                                stream,
                                handler.clone(),
                                dispatcher.clone(),
                                nat_manager.clone(),
                            ));
                        }
                        Err(e) => {
                            warn!("accept connection failed: {}", e);
                        }
                    }
                }
            };
            runners.push(Box::pin(tcp_task));
        }

        if self.handler.has_udp() {
            let nat_manager = self.nat_manager.clone();
            let handler = self.handler.clone();
            let address = self.address.clone();
            let port = self.port;
            let udp_task = async move {
                let socket = UdpSocket::bind(format!("{}:{}", address, port))
                    .await
                    .unwrap();
                info!("inbound listening udp {}:{}", address, port);

                match handler
                    .handle_udp(Some(Box::new(SimpleInboundDatagram(socket))))
                    .await
                {
                    Ok(socket) => {
                        handle_inbound_datagram(handler.tag().clone(), socket, nat_manager).await;
                    }
                    Err(e) => {
                        error!("handle inbound socket failed: {}", e);
                    }
                }
            };
            runners.push(Box::pin(udp_task));
        }

        runners
    }
}
