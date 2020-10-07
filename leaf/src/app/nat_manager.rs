use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Result;
use futures::future::abortable;
use log::*;
use tokio::sync::{
    mpsc::{self, Sender},
    Mutex as TokioMutex,
};

use crate::app::dispatcher::Dispatcher;
use crate::session::{Session, SocksAddr};

#[derive(Debug)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: Option<SocksAddr>,
    pub dst_addr: Option<SocksAddr>,
}

pub struct NatManager {
    sessions: Arc<TokioMutex<HashMap<SocketAddr, Sender<UdpPacket>>>>,
    dispatcher: Arc<Dispatcher>,
}

impl NatManager {
    pub fn new(dispatcher: Arc<Dispatcher>) -> Self {
        NatManager {
            sessions: Arc::new(TokioMutex::new(HashMap::new())),
            dispatcher,
        }
    }

    pub async fn contains_key(&self, key: &SocketAddr) -> bool {
        self.sessions.lock().await.contains_key(key)
    }

    pub async fn send(&self, key: &SocketAddr, pkt: UdpPacket) {
        let mut sessions = self.sessions.lock().await;
        if let Some(tx) = sessions.get_mut(key) {
            if let Err(err) = tx.try_send(pkt) {
                debug!("send uplink packet failed {:?}", err);
            }
        } else {
            error!("no nat association found");
        }
    }

    pub async fn size(&self) -> usize {
        self.sessions.lock().await.len()
    }

    pub async fn add_session(
        &self,
        sess: &Session,
        raddr: SocketAddr,
        client_ch_tx: Sender<UdpPacket>,
        timeout: u64,
    ) -> Result<()> {
        // new socket to communicate with the target.
        let socket = match self.dispatcher.dispatch_udp(sess).await {
            Ok(s) => s,
            Err(e) => {
                return Err(anyhow!("dispatch udp failed: {}", e));
            }
        };
        let (mut target_sock_recv, mut target_sock_send) = socket.split();

        let (target_ch_tx, mut target_ch_rx) = mpsc::channel(100);

        self.sessions.lock().await.insert(raddr, target_ch_tx);

        let mut client_ch_tx = client_ch_tx.clone();

        // downlink
        let sessions = self.sessions.clone();
        let downlink_task = async move {
            let mut buf = [0u8; 2 * 1024];
            loop {
                match target_sock_recv.recv_from(&mut buf).await {
                    Err(err) => {
                        debug!("udp downlink error: {}", err);
                        sessions.lock().await.remove(&raddr);
                        break;
                    }
                    Ok((0, _)) => {
                        debug!("receive zero-len udp packet");
                        sessions.lock().await.remove(&raddr);
                        break;
                    }
                    Ok((n, addr)) => {
                        let pkt = UdpPacket {
                            data: (&buf[..n]).to_vec(),
                            src_addr: Some(SocksAddr::from(addr)),
                            dst_addr: Some(SocksAddr::from(raddr)),
                        };
                        if let Err(err) = client_ch_tx.try_send(pkt) {
                            debug!(
                                "send downlink packet failed {} -> {}: {:?}",
                                &addr, &raddr, err
                            );
                        }
                        // TODO update timeout
                    }
                }
            }
        };
        let (downlink_task, downlink_task_handle) = abortable(downlink_task);
        tokio::spawn(downlink_task);

        // uplink
        let uplink_task = async move {
            while let Some(pkt) = target_ch_rx.recv().await {
                if pkt.dst_addr.is_none() {
                    warn!("unexpected none dst addr in uplink pkts");
                    continue;
                }
                let addr = match pkt.dst_addr {
                    Some(a) => match a {
                        SocksAddr::Ip(v) => v,
                        _ => {
                            warn!("unexpected domain addr");
                            continue;
                        }
                    },
                    None => {
                        warn!("unexpected none addr");
                        continue;
                    }
                };
                match target_sock_send.send_to(&pkt.data, &addr).await {
                    Ok(0) => {
                        debug!("uplink send zero bytes");
                    }
                    Ok(_) => {
                        continue;
                    }
                    Err(err) => {
                        debug!("uplink send error {:?}", err);
                    }
                }
            }
        };
        let (uplink_task, uplink_task_handle) = abortable(uplink_task);
        tokio::spawn(uplink_task);

        let sessions = self.sessions.clone();
        tokio::spawn(async move {
            tokio::time::delay_for(Duration::from_secs(timeout)).await;
            sessions.lock().await.remove(&raddr);
            downlink_task_handle.abort();
            uplink_task_handle.abort();
            debug!("udp session {} end", &raddr);
        });

        Ok(())
    }
}
