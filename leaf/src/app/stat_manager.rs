use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::{io, pin::Pin};

use async_trait::async_trait;
use futures::{
    ready,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::info;

use crate::{proxy::*, session::*};

pub struct Stream {
    pub inner: AnyStream,
    pub bytes_recvd: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub recv_completed: Arc<AtomicBool>,
    pub send_completed: Arc<AtomicBool>,
    pub last_peer_active: Arc<AtomicU32>,
}

impl Drop for Stream {
    fn drop(&mut self) {
        // In case of abnormal shutdown.
        self.recv_completed.store(true, Ordering::Relaxed);
        self.send_completed.store(true, Ordering::Relaxed);
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
    pub inner: AnyOutboundDatagram,
    pub bytes_recvd: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub recv_completed: Arc<AtomicBool>,
    pub send_completed: Arc<AtomicBool>,
    pub last_peer_active: Arc<AtomicU32>,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, s) = self.inner.split();
        (
            Box::new(DatagramRecvHalf(
                r,
                self.bytes_recvd,
                self.recv_completed,
                self.last_peer_active,
            )),
            Box::new(DatagramSendHalf(s, self.bytes_sent, self.send_completed)),
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
    pub sess: Session,
    pub start_time: u32,
    pub bytes_recvd: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub recv_completed: Arc<AtomicBool>,
    pub send_completed: Arc<AtomicBool>,
    pub last_peer_active: Arc<AtomicU32>,
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
}

fn get_unix_timestamp() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|x| x.as_secs() as u32)
        .unwrap_or(0)
}

#[inline]
fn log_session_end(c: &Counter) {
    info!(
        "[{}] [{}] [{}] [{}] [{}] [{}] [{}] [END]",
        c.sess
            .forwarded_source
            .unwrap_or_else(|| c.sess.source.ip()),
        c.sess.network,
        c.sess.inbound_tag,
        c.sess.outbound_tag,
        c.sess.destination,
        c.bytes_sent(),
        c.bytes_recvd(),
    );
}

#[derive(Default)]
pub struct StatManager {
    pub counters: Vec<Counter>,
}

impl StatManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cleanup_task(sm: super::SyncStatManager) -> crate::Runner {
        Box::pin(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                let mut sm = sm.write().await;
                let mut i = 0;
                while i < sm.counters.len() {
                    if sm.counters[i].recv_completed() && sm.counters[i].send_completed() {
                        let c = sm.counters.swap_remove(i);
                        log_session_end(&c);
                    } else {
                        i += 1;
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
        let ts = get_unix_timestamp();
        let last_peer_active = Arc::new(AtomicU32::new(ts));
        self.counters.push(Counter {
            sess,
            start_time: ts,
            bytes_recvd: bytes_recvd.clone(),
            bytes_sent: bytes_sent.clone(),
            recv_completed: recv_completed.clone(),
            send_completed: send_completed.clone(),
            last_peer_active: last_peer_active.clone(),
        });
        Box::new(Stream {
            inner: stream,
            bytes_recvd,
            bytes_sent,
            recv_completed,
            send_completed,
            last_peer_active,
        })
    }

    pub fn stat_inbound_stream(&mut self, stream: AnyStream, sess: Session) -> AnyStream {
        let bytes_recvd = Arc::new(AtomicU64::new(0));
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let recv_completed = Arc::new(AtomicBool::new(false));
        let send_completed = Arc::new(AtomicBool::new(false));
        let ts = get_unix_timestamp();
        let last_peer_active = Arc::new(AtomicU32::new(ts));
        self.counters.push(Counter {
            sess,
            start_time: ts,
            bytes_recvd: bytes_recvd.clone(),
            bytes_sent: bytes_sent.clone(),
            recv_completed: recv_completed.clone(),
            send_completed: send_completed.clone(),
            last_peer_active: last_peer_active.clone(),
        });
        Box::new(Stream {
            inner: stream,
            bytes_recvd: bytes_sent,
            bytes_sent: bytes_recvd,
            recv_completed: send_completed,
            send_completed: recv_completed,
            last_peer_active,
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
        let ts = get_unix_timestamp();
        let last_peer_active = Arc::new(AtomicU32::new(ts));
        self.counters.push(Counter {
            sess,
            start_time: ts,
            bytes_recvd: bytes_recvd.clone(),
            bytes_sent: bytes_sent.clone(),
            recv_completed: recv_completed.clone(),
            send_completed: send_completed.clone(),
            last_peer_active: last_peer_active.clone(),
        });
        Box::new(Datagram {
            inner: dgram,
            bytes_recvd,
            bytes_sent,
            recv_completed,
            send_completed,
            last_peer_active,
        })
    }

    pub fn get_last_peer_active(&self, outbound_tag: &str) -> Option<u32> {
        self.counters
            .iter()
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
