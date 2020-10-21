use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Result;
use bytes::{BufMut, BytesMut};
use log::*;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::channel as tokio_channel;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};

use crate::{
    app::nat_manager::{NatManager, UdpPacket},
    session::{Session, SocksAddr, SocksAddrWireType},
    Runner,
};

pub fn new(listen: String, port: u16, nat_manager: Arc<NatManager>) -> Result<Runner> {
    let t = async move {
        let socket = UdpSocket::bind(format!("{}:{}", listen, port))
            .await
            .unwrap();
        info!("socks inbound listening udp {}:{}", listen.clone(), port);

        let (mut client_sock_recv, mut client_sock_send) = socket.split();

        let (client_ch_tx, mut client_ch_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) =
            tokio_channel(100);

        // downlink
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
                let mut buf = BytesMut::new();
                buf.put_u16(0);
                buf.put_u8(0);
                let src_addr = match pkt.src_addr {
                    Some(a) => a,
                    None => {
                        warn!("ignore udp pkt with unexpected empty src addr");
                        continue;
                    }
                };
                if let Err(e) = src_addr.write_buf(&mut buf, SocksAddrWireType::PortLast) {
                    warn!("write address failed: {}", e);
                    continue;
                }
                buf.put_slice(&pkt.data);
                if let Err(e) = client_sock_send.send_to(&buf[..], &dst_addr).await {
                    warn!("send udp pkt failed: {}", e);
                    return;
                }
            }
            error!("unexpected udp downlink ended");
        });

        let mut buf = [0u8; 2 * 1024];
        loop {
            match client_sock_recv.recv_from(&mut buf).await {
                Err(e) => {
                    error!("udp recv error: {}", e);
                    break;
                }
                Ok((n, src_addr)) => {
                    if n < 3 {
                        warn!("recv short udp pkt");
                        continue;
                    }

                    let dst_addr =
                        match SocksAddr::try_from((&buf[3..], SocksAddrWireType::PortLast)) {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("read address failed: {}", e);
                                continue;
                            }
                        };

                    if !nat_manager.contains_key(&src_addr).await {
                        let sess = Session {
                            source: Some(src_addr.clone()),
                            destination: dst_addr.clone(),
                        };

                        if let Err(_) = nat_manager
                            .add_session(&sess, src_addr, client_ch_tx.clone(), 30)
                            .await
                        {
                            continue; // dispatch failed
                        }

                        debug!(
                            "udp session {}:{} -> {} ({})",
                            &src_addr.ip(),
                            &src_addr.port(),
                            &dst_addr.to_string(),
                            nat_manager.size().await,
                        );
                    }

                    let pkt = UdpPacket {
                        data: (&buf[3 + dst_addr.size()..n]).to_vec(),
                        src_addr: Some(SocksAddr::from(src_addr)),
                        dst_addr: Some(dst_addr),
                    };
                    nat_manager.send(&src_addr, pkt).await;
                }
            }
        }
    };

    Ok(Box::pin(t))
}
