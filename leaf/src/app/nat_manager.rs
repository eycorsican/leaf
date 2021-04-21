use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::{abortable, BoxFuture};
use log::*;
use tokio::sync::{
    mpsc::{self, Sender},
    oneshot, Mutex as TokioMutex,
};

use crate::app::dispatcher::Dispatcher;
use crate::option;
use crate::session::{DatagramSource, Session, SocksAddr};

#[derive(Debug)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: Option<SocksAddr>,
    pub dst_addr: Option<SocksAddr>,
}

type SessionMap =
    Arc<TokioMutex<HashMap<DatagramSource, (Sender<UdpPacket>, oneshot::Sender<bool>, Instant)>>>;

pub struct NatManager {
    sessions: SessionMap,
    dispatcher: Arc<Dispatcher>,
    timeout_check_task: TokioMutex<Option<BoxFuture<'static, ()>>>,
}

impl NatManager {
    pub fn new(dispatcher: Arc<Dispatcher>) -> Self {
        let sessions: SessionMap = Arc::new(TokioMutex::new(HashMap::new()));
        let sessions2 = sessions.clone();

        // The task is lazy, will not run until any sessions added.
        let timeout_check_task: BoxFuture<'static, ()> = Box::pin(async move {
            loop {
                let mut sessions = sessions2.lock().await;
                let n_total = sessions.len();
                let now = Instant::now();
                let mut to_be_remove = Vec::new();
                for (key, val) in sessions.iter() {
                    if now.duration_since(val.2).as_secs() >= *option::UDP_SESSION_TIMEOUT {
                        to_be_remove.push(key.to_owned());
                    }
                }
                for key in to_be_remove.iter() {
                    if let Some(sess) = sessions.remove(key) {
                        // Sends a signal to abort downlink task, uplink task will
                        // end automatically when we drop the channel's tx side upon
                        // session removal.
                        if let Err(e) = sess.1.send(true) {
                            debug!("failed to send abort signal on session {}: {}", key, e);
                        }
                        debug!("udp session {} ended", key);
                    }
                }
                drop(to_be_remove); // drop explicitly
                let n_remaining = sessions.len();
                let n_removed = n_total - n_remaining;
                drop(sessions); // release the lock
                if n_removed > 0 {
                    trace!(
                        "removed {} nat sessions, remaining {} sessions",
                        n_removed,
                        n_remaining
                    );
                }
                tokio::time::sleep(Duration::from_secs(
                    *option::UDP_SESSION_TIMEOUT_CHECK_INTERVAL,
                ))
                .await;
            }
        });

        NatManager {
            sessions,
            dispatcher,
            timeout_check_task: TokioMutex::new(Some(timeout_check_task)),
        }
    }

    pub async fn contains_key(&self, key: &DatagramSource) -> bool {
        self.sessions.lock().await.contains_key(key)
    }

    pub async fn send(&self, key: &DatagramSource, pkt: UdpPacket) {
        let mut sessions = self.sessions.lock().await;
        if let Some(sess) = sessions.get_mut(key) {
            if let Err(err) = sess.0.try_send(pkt) {
                debug!("send uplink packet failed {}", err);
            }
            sess.2 = Instant::now(); // activity update
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
        raddr: DatagramSource,
        client_ch_tx: Sender<UdpPacket>,
    ) {
        // Runs the lazy task for session cleanup job, this task will run only once.
        if let Some(task) = self.timeout_check_task.lock().await.take() {
            tokio::spawn(task);
        }

        let (target_ch_tx, mut target_ch_rx) = mpsc::channel(64);
        let (downlink_abort_tx, downlink_abort_rx) = oneshot::channel();

        self.sessions
            .lock()
            .await
            .insert(raddr, (target_ch_tx, downlink_abort_tx, Instant::now()));

        let dispatcher = self.dispatcher.clone();
        let sessions = self.sessions.clone();
        let sess = sess.clone();

        // Spawns a new task for dispatching to avoid blocking the current task,
        // because we have stream type transports for UDP traffic, establishing a
        // TCP stream would block the task.
        tokio::spawn(async move {
            // new socket to communicate with the target.
            let socket = match dispatcher.dispatch_udp(&sess).await {
                Ok(s) => s,
                Err(_) => {
                    sessions.lock().await.remove(&raddr);
                    return;
                }
            };

            let (mut target_sock_recv, mut target_sock_send) = socket.split();

            let client_ch_tx = client_ch_tx.clone();

            // downlink
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
                                src_addr: Some(addr.clone()),
                                dst_addr: Some(SocksAddr::from(raddr.address)),
                            };
                            if let Err(err) = client_ch_tx.send(pkt).await {
                                debug!(
                                    "send downlink packet failed {} -> {}: {}",
                                    &addr, &raddr, err
                                );
                                sessions.lock().await.remove(&raddr);
                                break;
                            }

                            // activity update
                            {
                                let mut sessions = sessions.lock().await;
                                if let Some(sess) = sessions.get_mut(&raddr) {
                                    if addr.port() == 53 {
                                        // If the destination port is 53, we assume it's a
                                        // DNS query and set a negative timeout so it will
                                        // be removed on next check.
                                        sess.2.checked_sub(Duration::from_secs(
                                            *option::UDP_SESSION_TIMEOUT,
                                        ));
                                    } else {
                                        sess.2 = Instant::now();
                                    }
                                }
                            }
                        }
                    }
                }
            };

            let (downlink_task, downlink_task_handle) = abortable(downlink_task);
            tokio::spawn(downlink_task);

            // Runs a task to receive the abort signal.
            tokio::spawn(async move {
                if let Err(e) = downlink_abort_rx.await {
                    debug!(
                        "failed to receive abort signal on session {}: {}",
                        &raddr, e
                    );
                };
                downlink_task_handle.abort();
            });

            // uplink
            tokio::spawn(async move {
                while let Some(pkt) = target_ch_rx.recv().await {
                    if pkt.dst_addr.is_none() {
                        warn!("unexpected none dst addr in uplink pkts");
                        continue;
                    }
                    let addr = match pkt.dst_addr {
                        Some(a) => a,
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
            });
        });
    }
}
