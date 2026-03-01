use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::{io, pin::Pin};

use async_trait::async_trait;
use futures::{
    ready,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, RwLock};
use tracing::debug;

use crate::{option, proxy::*, session::*};

pub type SyncStatManager = Arc<RwLock<StatManager>>;

pub struct Stream {
    pub inner: AnyStream,
    pub bytes_recvd: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub recv_completed: Arc<AtomicBool>,
    pub send_completed: Arc<AtomicBool>,
    pub last_peer_active: Arc<AtomicU32>,
    pub id: u64,
    pub tx: mpsc::UnboundedSender<u64>,
}

impl Drop for Stream {
    fn drop(&mut self) {
        // In case of abnormal shutdown.
        self.recv_completed.store(true, Ordering::Relaxed);
        self.send_completed.store(true, Ordering::Relaxed);
        let _ = self.tx.send(self.id);
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let len = buf.filled().len();
        let remaining = buf.remaining();
        ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        let new_len = buf.filled().len();
        if new_len > len {
            self.bytes_recvd
                .fetch_add((new_len - len) as u64, Ordering::Relaxed);
            self.last_peer_active
                .store(get_unix_timestamp(), Ordering::Relaxed);
        } else if remaining > 0 {
            self.recv_completed.store(true, Ordering::Relaxed);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
        self.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.inner).poll_shutdown(cx))?;
        self.send_completed.store(true, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

pub struct Datagram {
    pub inner: Option<AnyOutboundDatagram>,
    pub bytes_recvd: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub recv_completed: Arc<AtomicBool>,
    pub send_completed: Arc<AtomicBool>,
    pub last_peer_active: Arc<AtomicU32>,
    pub id: u64,
    pub tx: mpsc::UnboundedSender<u64>,
}

impl Drop for Datagram {
    fn drop(&mut self) {
        let _ = self.tx.send(self.id);
    }
}

impl OutboundDatagram for Datagram {
    fn split(
        mut self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, s) = self.inner.take().expect("inner should be present").split();
        (
            Box::new(DatagramRecvHalf(
                r,
                self.bytes_recvd.clone(),
                self.recv_completed.clone(),
                self.last_peer_active.clone(),
            )),
            Box::new(DatagramSendHalf(
                s,
                self.bytes_sent.clone(),
                self.send_completed.clone(),
            )),
        )
    }
}

pub struct DatagramRecvHalf(
    Box<dyn OutboundDatagramRecvHalf>,
    Arc<AtomicU64>,
    Arc<AtomicBool>,
    Arc<AtomicU32>,
);

impl Drop for DatagramRecvHalf {
    fn drop(&mut self) {
        self.2.store(true, Ordering::Relaxed);
    }
}

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        self.0.recv_from(buf).await.map(|(n, a)| {
            self.1.fetch_add(n as u64, Ordering::Relaxed);
            self.3.store(get_unix_timestamp(), Ordering::Relaxed);
            (n, a)
        })
    }
}

pub struct DatagramSendHalf(
    Box<dyn OutboundDatagramSendHalf>,
    Arc<AtomicU64>,
    Arc<AtomicBool>,
);

impl Drop for DatagramSendHalf {
    fn drop(&mut self) {
        self.2.store(true, Ordering::Relaxed);
    }
}

#[async_trait]
impl OutboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        self.0.send_to(buf, target).await.inspect(|&n| {
            self.1.fetch_add(n as u64, Ordering::Relaxed);
        })
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.close().await
    }
}

pub struct Counter {
    pub id: u64,
    pub sess: Session,
    pub start_time: u32,
    pub bytes_recvd: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub recv_completed: Arc<AtomicBool>,
    pub send_completed: Arc<AtomicBool>,
    pub last_peer_active: Arc<AtomicU32>,
    pub logged: Arc<AtomicBool>,
}

impl Counter {
    pub fn bytes_recvd(&self) -> u64 {
        self.bytes_recvd.load(Ordering::Relaxed)
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn recv_completed(&self) -> bool {
        self.recv_completed.load(Ordering::Relaxed)
    }

    pub fn send_completed(&self) -> bool {
        self.send_completed.load(Ordering::Relaxed)
    }

    pub fn last_peer_active(&self) -> u32 {
        self.last_peer_active.load(Ordering::Relaxed)
    }

    pub fn start_time(&self) -> u32 {
        self.start_time
    }

    pub fn log_session_end(&self) {
        if !self.logged.swap(true, Ordering::Relaxed) {
            let _g = self.sess.span.enter();
            debug!(
                "session end out={} dst={} tx={} rx={}",
                self.sess.outbound_tag,
                self.sess.destination,
                self.bytes_sent(),
                self.bytes_recvd(),
            );
        }
    }
}

impl Drop for Counter {
    fn drop(&mut self) {
        self.log_session_end();
    }
}

fn get_unix_timestamp() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|x| x.as_secs() as u32)
        .unwrap_or(0)
}

pub struct StatManager {
    pub counters: HashMap<u64, Counter>,
    pub recent_counters: VecDeque<Counter>,
    pub max_recent_connections: usize,
    pub next_id: u64,
    pub tx: mpsc::UnboundedSender<u64>,
    pub rx: Option<mpsc::UnboundedReceiver<u64>>,
}

impl Default for StatManager {
    fn default() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            counters: HashMap::new(),
            recent_counters: VecDeque::new(),
            max_recent_connections: *option::MAX_RECENT_CONNECTIONS,
            next_id: 1,
            tx,
            rx: Some(rx),
        }
    }
}

impl StatManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn move_to_recent(&mut self) {
        let mut to_move = Vec::new();
        for (id, c) in self.counters.iter() {
            if c.recv_completed() && c.send_completed() {
                to_move.push(*id);
            }
        }
        for id in to_move {
            if let Some(counter) = self.counters.remove(&id) {
                counter.log_session_end();
                if self.max_recent_connections > 0 {
                    self.recent_counters.push_back(counter);
                }
            }
        }
        if self.max_recent_connections > 0 {
            self.prune_recent();
        }
    }

    fn prune_recent(&mut self) {
        // Only prune when exceeding 2x the limit to reduce sorting frequency
        if self.recent_counters.len() > self.max_recent_connections * 2 {
            let mut recent_vec: Vec<Counter> = self.recent_counters.drain(..).collect();
            recent_vec.sort_by_key(|c| c.start_time());
            let to_remove = recent_vec.len() - self.max_recent_connections;
            self.recent_counters = recent_vec.into_iter().skip(to_remove).collect();
        }
    }

    pub fn cleanup_task(sm: SyncStatManager) -> crate::Runner {
        Box::pin(async move {
            let mut rx = {
                let mut sm_w = sm.write().await;
                sm_w.rx.take().expect("rx should be present")
            };
            loop {
                let mut ids = Vec::new();
                // Batch up to 100 IDs or wait for a bit
                match tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
                    Ok(Some(id)) => {
                        ids.push(id);
                        // Try to collect more IDs without waiting
                        while let Ok(id) = rx.try_recv() {
                            ids.push(id);
                            if ids.len() >= 500 {
                                break;
                            }
                        }
                    }
                    Ok(None) => break, // Channel closed
                    Err(_) => {
                        // Timeout reached, check if we need to do periodic cleanup anyway
                        let mut sm_w = sm.write().await;
                        sm_w.move_to_recent();
                        continue;
                    }
                }

                if !ids.is_empty() {
                    let mut sm_w = sm.write().await;
                    for id in ids {
                        if let Some(counter) = sm_w.counters.remove(&id) {
                            counter.log_session_end();
                            if sm_w.max_recent_connections > 0 {
                                sm_w.recent_counters.push_back(counter);
                            }
                        }
                    }
                    if sm_w.max_recent_connections > 0 {
                        sm_w.prune_recent();
                    }
                }
            }
        })
    }

    pub fn stat_stream(&mut self, stream: AnyStream, sess: Session) -> AnyStream {
        let bytes_recvd = Arc::new(AtomicU64::new(0));
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let recv_completed = Arc::new(AtomicBool::new(false));
        let send_completed = Arc::new(AtomicBool::new(false));
        let logged = Arc::new(AtomicBool::new(false));
        let ts = get_unix_timestamp();
        let last_peer_active = Arc::new(AtomicU32::new(ts));
        let id = self.next_id;
        self.next_id += 1;
        self.counters.insert(
            id,
            Counter {
                id,
                sess,
                start_time: ts,
                bytes_recvd: bytes_recvd.clone(),
                bytes_sent: bytes_sent.clone(),
                recv_completed: recv_completed.clone(),
                send_completed: send_completed.clone(),
                last_peer_active: last_peer_active.clone(),
                logged,
            },
        );
        Box::new(Stream {
            inner: stream,
            bytes_recvd,
            bytes_sent,
            recv_completed,
            send_completed,
            last_peer_active,
            id,
            tx: self.tx.clone(),
        })
    }

    pub fn stat_inbound_stream(&mut self, stream: AnyStream, sess: Session) -> AnyStream {
        let bytes_recvd = Arc::new(AtomicU64::new(0));
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let recv_completed = Arc::new(AtomicBool::new(false));
        let send_completed = Arc::new(AtomicBool::new(false));
        let logged = Arc::new(AtomicBool::new(false));
        let ts = get_unix_timestamp();
        let last_peer_active = Arc::new(AtomicU32::new(ts));
        let id = self.next_id;
        self.next_id += 1;
        self.counters.insert(
            id,
            Counter {
                id,
                sess,
                start_time: ts,
                bytes_recvd: bytes_recvd.clone(),
                bytes_sent: bytes_sent.clone(),
                recv_completed: recv_completed.clone(),
                send_completed: send_completed.clone(),
                last_peer_active: last_peer_active.clone(),
                logged,
            },
        );
        Box::new(Stream {
            inner: stream,
            bytes_recvd: bytes_sent,
            bytes_sent: bytes_recvd,
            recv_completed: send_completed,
            send_completed: recv_completed,
            last_peer_active,
            id,
            tx: self.tx.clone(),
        })
    }

    pub fn stat_outbound_datagram(
        &mut self,
        dgram: AnyOutboundDatagram,
        sess: Session,
    ) -> AnyOutboundDatagram {
        let bytes_recvd = Arc::new(AtomicU64::new(0));
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let recv_completed = Arc::new(AtomicBool::new(false));
        let send_completed = Arc::new(AtomicBool::new(false));
        let logged = Arc::new(AtomicBool::new(false));
        let ts = get_unix_timestamp();
        let last_peer_active = Arc::new(AtomicU32::new(ts));
        let id = self.next_id;
        self.next_id += 1;
        self.counters.insert(
            id,
            Counter {
                id,
                sess,
                start_time: ts,
                bytes_recvd: bytes_recvd.clone(),
                bytes_sent: bytes_sent.clone(),
                recv_completed: recv_completed.clone(),
                send_completed: send_completed.clone(),
                last_peer_active: last_peer_active.clone(),
                logged,
            },
        );
        Box::new(Datagram {
            inner: Some(dgram),
            bytes_recvd,
            bytes_sent,
            recv_completed,
            send_completed,
            last_peer_active,
            id,
            tx: self.tx.clone(),
        })
    }

    pub fn get_last_peer_active(&self, outbound_tag: &str) -> Option<u32> {
        self.counters
            .values()
            .filter(|counter| counter.sess.outbound_tag == outbound_tag)
            .map(|counter| counter.last_peer_active())
            .max()
    }

    pub fn since_last_peer_active(&self, outbound_tag: &str) -> Option<u32> {
        self.get_last_peer_active(outbound_tag)
            .map(|ts| get_unix_timestamp().saturating_sub(ts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::ReadBuf;

    struct MockStream {
        data: Vec<u8>,
        read_pos: usize,
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context,
            buf: &mut ReadBuf,
        ) -> Poll<io::Result<()>> {
            let rem = self.data.len() - self.read_pos;
            if rem == 0 {
                return Poll::Ready(Ok(()));
            }
            let to_read = std::cmp::min(rem, buf.remaining());
            buf.put_slice(&self.data[self.read_pos..self.read_pos + to_read]);
            self.read_pos += to_read;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_stat_stream_non_empty_buf() {
        let mock = MockStream {
            data: vec![1, 2, 3, 4, 5],
            read_pos: 0,
        };
        let stream = Box::new(mock);

        let bytes_recvd = Arc::new(AtomicU64::new(0));
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let recv_completed = Arc::new(AtomicBool::new(false));
        let send_completed = Arc::new(AtomicBool::new(false));
        let last_peer_active = Arc::new(AtomicU32::new(0));

        let mut stat_stream = Stream {
            inner: stream,
            bytes_recvd: bytes_recvd.clone(),
            bytes_sent: bytes_sent.clone(),
            recv_completed: recv_completed.clone(),
            send_completed: send_completed.clone(),
            last_peer_active: last_peer_active.clone(),
            sm: None,
        };

        let mut data = vec![0u8; 20];
        // Simulate existing data in buffer
        let mut buf = ReadBuf::new(&mut data);
        buf.put_slice(&[0xAA; 5]);

        use futures::future::poll_fn;
        poll_fn(|cx| Pin::new(&mut stat_stream).poll_read(cx, &mut buf))
            .await
            .unwrap();

        assert_eq!(buf.filled().len(), 10);

        let received = bytes_recvd.load(Ordering::Relaxed);
        // This assertion should fail with current implementation (will be 10 instead of 5)
        assert_eq!(received, 5, "Expected 5 bytes received, got {}", received);
    }
}
