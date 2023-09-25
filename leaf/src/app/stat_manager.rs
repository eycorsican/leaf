use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
        ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        if buf.filled().is_empty() {
            self.recv_completed.store(true, Ordering::Relaxed);
        } else {
            self.bytes_recvd
                .fetch_add(buf.filled().len() as u64, Ordering::Relaxed);
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
            Box::new(DatagramRecvHalf(r, self.bytes_recvd, self.recv_completed)),
            Box::new(DatagramSendHalf(s, self.bytes_sent, self.send_completed)),
        )
    }
}

pub struct DatagramRecvHalf(
    Box<dyn OutboundDatagramRecvHalf>,
    Arc<AtomicU64>,
    Arc<AtomicBool>,
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
        self.0.send_to(buf, target).await.map(|n| {
            self.1.fetch_add(n as u64, Ordering::Relaxed);
            n
        })
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.close().await
    }
}

pub struct Counter {
    pub sess: Session,
    pub bytes_recvd: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub recv_completed: Arc<AtomicBool>,
    pub send_completed: Arc<AtomicBool>,
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

pub struct StatManager {
    pub counters: Vec<Counter>,
}

impl StatManager {
    pub fn new() -> Self {
        Self {
            counters: Vec::new(),
        }
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
        self.counters.push(Counter {
            sess,
            bytes_recvd: bytes_recvd.clone(),
            bytes_sent: bytes_sent.clone(),
            recv_completed: recv_completed.clone(),
            send_completed: send_completed.clone(),
        });
        Box::new(Stream {
            inner: stream,
            bytes_recvd,
            bytes_sent,
            recv_completed,
            send_completed,
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
        self.counters.push(Counter {
            sess,
            bytes_recvd: bytes_recvd.clone(),
            bytes_sent: bytes_sent.clone(),
            recv_completed: recv_completed.clone(),
            send_completed: send_completed.clone(),
        });
        Box::new(Datagram {
            inner: dgram,
            bytes_recvd,
            bytes_sent,
            recv_completed,
            send_completed,
        })
    }
}
