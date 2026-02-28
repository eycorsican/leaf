use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

use crate::proxy::mptp::mptp_conn::{
    protocol::{Address, HandshakeRequest, CMD_UDP},
    MptpDatagram, MptpStream,
};
use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{self, UnboundedSender};
use uuid::Uuid;

use crate::{
    proxy::{AnyInboundTransport, AnyStream, InboundStreamHandler, InboundTransport},
    session::{DatagramSource, Session, SocksAddr, StreamId},
};

struct PrefixedStream<S> {
    stream: S,
    prefix: BytesMut,
}

impl<S> PrefixedStream<S> {
    fn new(stream: S, prefix: BytesMut) -> Self {
        Self { stream, prefix }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let len = std::cmp::min(buf.remaining(), self.prefix.len());
            buf.put_slice(&self.prefix[..len]);
            self.prefix.advance(len);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

struct TrackedMptpStream<S> {
    inner: MptpStream<S>,
    cid: Uuid,
    sessions: Arc<RwLock<HashMap<Uuid, UnboundedSender<(S, Option<Uuid>)>>>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TrackedMptpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TrackedMptpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> Drop for TrackedMptpStream<S> {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.sessions.write() {
            sessions.remove(&self.cid);
            tracing::debug!("MPTP session {} removed", self.cid);
        }
    }
}

pub struct Handler {
    sessions:
        Arc<RwLock<HashMap<Uuid, UnboundedSender<(PrefixedStream<AnyStream>, Option<Uuid>)>>>>,
}

impl Handler {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let mut buf = BytesMut::with_capacity(1024);

        // Read handshake
        // We need to loop until we have enough data or EOF
        loop {
            let n = stream.read_buf(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF during handshake",
                ));
            }

            // Try to decode
            let mut buf_copy = buf.clone();
            match HandshakeRequest::decode(&mut buf_copy) {
                Ok(Some(req)) => {
                    // Success
                    // buf_copy has advanced, so we know how much was consumed.
                    // Actually HandshakeRequest::decode advances the buffer.
                    // So we can determine the consumed amount by comparing lengths.
                    let consumed = buf.len() - buf_copy.len();
                    buf.advance(consumed);

                    let remaining = buf; // This is the prefix for the stream

                    let prefixed_stream = PrefixedStream::new(stream, remaining);

                    // Check CID
                    let is_new = {
                        let sessions = self
                            .sessions
                            .read()
                            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Lock poisoned"))?;
                        !sessions.contains_key(&req.cid)
                    };

                    if is_new {
                        tracing::info!("New MPTP session: {}", req.cid);
                        let (tx, rx) = mpsc::unbounded_channel();

                        // Register session
                        {
                            let mut sessions = self.sessions.write().map_err(|_| {
                                io::Error::new(io::ErrorKind::Other, "Lock poisoned")
                            })?;
                            sessions.insert(req.cid, tx.clone());
                        }

                        // Send the first stream (this one) to the MptpStream via channel?
                        // No, MptpStream::new_with_receiver takes the receiver.
                        // And we can pass the initial stream(s) via channel or maybe constructor supports it?
                        // MptpStream::new_with_receiver(rx) creates an empty one that pulls from rx.
                        // So we should send this stream to tx.

                        let _ = tx.send((prefixed_stream, Some(req.cid)));

                        let mptp_stream = MptpStream::new_with_receiver(rx);
                        let tracked_stream = TrackedMptpStream {
                            inner: mptp_stream,
                            cid: req.cid,
                            sessions: self.sessions.clone(),
                        };

                        // Update session destination
                        match req.dst_addr {
                            Address::Ipv4(ip) => {
                                sess.destination = SocksAddr::from((ip, req.dst_port));
                            }
                            Address::Ipv6(ip) => {
                                sess.destination = SocksAddr::from((ip, req.dst_port));
                            }
                            Address::Domain(domain) => {
                                sess.destination = SocksAddr::try_from((domain, req.dst_port))
                                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                            }
                        }

                        if req.cmd == CMD_UDP {
                            let stream_id = StreamId::Uuid(req.cid);
                            let dgram_src = DatagramSource::new(sess.source, Some(stream_id));
                            let mptp_datagram =
                                MptpDatagram::new_with_source(tracked_stream, dgram_src);
                            return Ok(InboundTransport::Datagram(
                                Box::new(mptp_datagram),
                                Some(sess),
                            ));
                        }

                        return Ok(InboundTransport::Stream(Box::new(tracked_stream), sess));
                    } else {
                        tracing::debug!("Joining existing MPTP session: {}", req.cid);
                        let tx = {
                            let sessions = self.sessions.read().map_err(|_| {
                                io::Error::new(io::ErrorKind::Other, "Lock poisoned")
                            })?;
                            sessions.get(&req.cid).cloned()
                        };

                        if let Some(tx) = tx {
                            if let Err(_) = tx.send((prefixed_stream, Some(req.cid))) {
                                // Channel closed, session probably dead
                                tracing::warn!("MPTP session {} channel closed", req.cid);
                                return Err(io::Error::new(
                                    io::ErrorKind::ConnectionAborted,
                                    "Session closed",
                                ));
                            }
                            return Ok(InboundTransport::Empty);
                        } else {
                            // Should not happen due to lock, but possible if removed concurrently
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionRefused,
                                "Session not found",
                            ));
                        }
                    }
                }
                Ok(None) => {
                    // Need more data
                    continue;
                }
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                }
            }
        }
    }
}
