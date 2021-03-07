use std::cmp::min;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{io, pin::Pin};

use bytes::{BufMut, Bytes, BytesMut};
use futures::future::{abortable, AbortHandle};
use futures::sink::Sink;
use futures::stream::SplitSink;
use futures::stream::SplitStream;
use futures::stream::Stream;
use futures::SinkExt;
use futures::StreamExt;
use futures::{
    ready,
    task::{Context, Poll},
    Future,
};
use log::trace;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::time::delay_for;

use crate::proxy::ProxyStream;

#[cfg(feature = "inbound-amux")]
pub mod inbound;
#[cfg(feature = "outbound-amux")]
pub mod outbound;

pub static NAME: &str = "amux";

pub const FRAME_STREAM: u8 = 0x01;
pub const FRAME_STREAM_FIN: u8 = 0x02;

pub fn random_u16() -> u16 {
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    let mut buf = [0u8; std::mem::size_of::<u16>()];
    let mut rng = StdRng::from_entropy();
    rng.fill_bytes(&mut buf);
    u16::from_be_bytes(buf)
}

type StreamId = u16;

pub enum MuxFrame {
    /// A frame to send stream data. The frame opens new stream implicitly, when
    /// the server side receives a Stream frame with an unseen stream ID, it should
    /// create a new stream for it.
    Stream(StreamId, Vec<u8>), // |type(1,0x01)|id(2)|len(2)|data|
    /// A frame to close the send half of a stream.
    StreamFin(StreamId), // |type(1,0x02)|id(2)|
}

impl MuxFrame {
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        match self {
            MuxFrame::Stream(id, data) => {
                buf.put_u8(FRAME_STREAM);
                buf.put_u16(*id as u16);
                buf.put_u16(data.len() as u16); // FIXME check len
                buf.put_slice(data);
            }
            MuxFrame::StreamFin(id) => {
                buf.put_u8(FRAME_STREAM_FIN);
                buf.put_u16(*id as u16);
            }
        }
        buf.freeze()
    }
}

impl std::fmt::Display for MuxFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MuxFrame::Stream(stream_id, data) => {
                write!(f, "Stream({}, {} bytes)", stream_id, data.len())
            }
            MuxFrame::StreamFin(stream_id) => {
                write!(f, "StreamFin({})", stream_id)
            }
        }
    }
}

pub type Streams = Arc<Mutex<HashMap<StreamId, Sender<Vec<u8>>>>>;

pub struct MuxStream {
    session_id: SessionId,
    stream_id: StreamId,
    stream_read_rx: Receiver<Vec<u8>>,
    frame_write_tx: Sender<MuxFrame>,
    buf: BytesMut,
}

impl MuxStream {
    pub fn new(
        session_id: SessionId,
        stream_id: StreamId,
        frame_write_tx: Sender<MuxFrame>,
    ) -> (Self, Sender<Vec<u8>>) {
        trace!("new mux stream {} (session {})", stream_id, session_id);
        let (stream_read_tx, stream_read_rx) = mpsc::channel::<Vec<u8>>(1);
        (
            MuxStream {
                session_id,
                stream_id,
                stream_read_rx,
                frame_write_tx,
                buf: BytesMut::new(),
            },
            stream_read_tx,
        )
    }

    pub fn id(&self) -> StreamId {
        self.stream_id
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        trace!(
            "drop mux stream {} (session {})",
            self.stream_id,
            self.session_id
        );
    }
}

fn broken_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "broken pipe")
}

impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.buf.is_empty() {
            let to_read = min(buf.len(), self.buf.len());
            let for_read = self.buf.split_to(to_read);
            buf[..to_read].copy_from_slice(&for_read[..to_read]);
            return Poll::Ready(Ok(to_read));
        }
        Poll::Ready(
            ready!(self.stream_read_rx.poll_recv(cx)).map_or(Err(broken_pipe()), |data| {
                if data.len() == 0 {
                    Ok(0) // EOF
                } else {
                    let to_read = min(buf.len(), data.len());
                    buf[..to_read].copy_from_slice(&data[..to_read]);
                    if data.len() > to_read {
                        self.buf.extend_from_slice(&data[to_read..]);
                    }
                    Ok(to_read)
                }
            }),
        )
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let frame = MuxFrame::Stream(self.stream_id, buf.to_vec());
        Poll::Ready(ready!(Box::pin(self.frame_write_tx.send(frame))
            .as_mut()
            .poll(cx)
            .map_ok(|_| buf.len())
            .map_err(|_| broken_pipe())))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let frame = MuxFrame::StreamFin(self.stream_id);
        Poll::Ready(ready!(Box::pin(self.frame_write_tx.send(frame))
            .as_mut()
            .poll(cx)
            .map_ok(|_| ())
            .map_err(|_| broken_pipe())))
    }
}

pub struct MuxConnection<S> {
    inner: S,
    items: VecDeque<Bytes>,
}

impl<S> MuxConnection<S> {
    pub fn new(inner: S) -> Self {
        MuxConnection {
            inner,
            items: VecDeque::with_capacity(1),
        }
    }
}

impl<S: AsyncRead + Unpin> Stream for MuxConnection<S> {
    type Item = io::Result<MuxFrame>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let me = &mut *self;
        let mut ftype = [0u8; 1];
        ready!(Pin::new(&mut me.inner.read_exact(&mut ftype)).poll(cx))?;
        match ftype[0] {
            FRAME_STREAM => {
                let mut stream_id = [0u8; 2];
                ready!(Pin::new(&mut me.inner.read_exact(&mut stream_id)).poll(cx))?;
                let stream_id = u16::from_be_bytes(stream_id);
                let mut len = [0u8; 2];
                ready!(Pin::new(&mut me.inner.read_exact(&mut len)).poll(cx))?;
                let len = u16::from_be_bytes(len) as usize;
                let mut data = vec![0u8; len];
                ready!(Pin::new(&mut me.inner.read_exact(&mut data)).poll(cx))?;
                Poll::Ready(Some(Ok(MuxFrame::Stream(stream_id, data))))
            }
            FRAME_STREAM_FIN => {
                let mut stream_id = [0u8; 2];
                ready!(Pin::new(&mut me.inner.read_exact(&mut stream_id)).poll(cx))?;
                let stream_id = u16::from_be_bytes(stream_id);
                Poll::Ready(Some(Ok(MuxFrame::StreamFin(stream_id))))
            }
            _ => Poll::Ready(None),
        }
    }
}

impl<S: AsyncWrite + Unpin> Sink<MuxFrame> for MuxConnection<S> {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let me = &mut *self;
        if let Some(item) = me.items.pop_front() {
            ready!(Pin::new(&mut me.inner.write_all(&item)).poll(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: MuxFrame) -> Result<(), Self::Error> {
        self.items.push_back(item.to_bytes());
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let me = &mut *self;
        while let Some(item) = me.items.pop_front() {
            ready!(Pin::new(&mut me.inner.write_all(&item)).poll(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let me = &mut *self;
        while let Some(item) = me.items.pop_front() {
            ready!(Pin::new(&mut me.inner.write_all(&item)).poll(cx))?;
        }
        Poll::Ready(Ok(()))
    }
}

// SessionId is a local identifier for connectors and acceptors, it has nothing
// to do with the remote peer.
type SessionId = u16;

struct Accept {
    session_id: SessionId,
    stream_accept_tx: Sender<MuxStream>,
    frame_write_tx: Sender<MuxFrame>,
}

pub struct MuxSession;

impl MuxSession {
    fn run_frame_receive_loop(
        streams: Streams,
        mut frame_stream: SplitStream<MuxConnection<Box<dyn ProxyStream>>>,
        recv_end: Option<Arc<Mutex<bool>>>,
        mut accept: Option<Accept>,
    ) -> AbortHandle {
        let task = async move {
            while let Some(frame) = frame_stream.next().await {
                match frame {
                    Ok(frame) => {
                        match frame {
                            MuxFrame::Stream(stream_id, data) => {
                                // In accept mode.
                                if let Some(Accept {
                                    session_id,
                                    stream_accept_tx,
                                    frame_write_tx,
                                }) = accept.as_mut()
                                {
                                    // Accepts new stream for an unseen stream ID.
                                    if !streams.lock().await.contains_key(&stream_id) {
                                        let (mux_stream, stream_read_tx) = MuxStream::new(
                                            *session_id,
                                            stream_id,
                                            frame_write_tx.clone(),
                                        );
                                        streams.lock().await.insert(stream_id, stream_read_tx);
                                        if let Err(_) = stream_accept_tx.send(mux_stream).await {
                                            // The `Incoming` transport has been dropped.
                                            break;
                                        }
                                    }
                                }
                                // Sends data to the stream.
                                if let Some(mut stream_read_tx) =
                                    streams.lock().await.get(&stream_id).cloned()
                                {
                                    // FIXME error
                                    let _ = stream_read_tx.send(data).await;
                                }
                            }
                            MuxFrame::StreamFin(stream_id) => {
                                // Send an empty buffer to indicate EOF.
                                if let Some(mut stream_read_tx) =
                                    streams.lock().await.get(&stream_id).cloned()
                                {
                                    // FIXME error
                                    let _ = stream_read_tx.send(Vec::new()).await;
                                }
                                let streams2 = streams.clone();
                                tokio::spawn(async move {
                                    delay_for(Duration::from_secs(4)).await;
                                    streams2.lock().await.remove(&stream_id);
                                });
                            }
                        }
                    }
                    // Borken pipe.
                    Err(_) => {
                        streams.lock().await.clear();
                        break;
                    }
                }
            }
            // Stop receving.
            if let Some(recv_end) = recv_end {
                *recv_end.lock().await = true;
            }
            streams.lock().await.clear();
        };
        let (task, handle) = abortable(task);
        tokio::spawn(task);
        handle
    }

    fn run_frame_send_loop(
        streams: Streams,
        mut frame_sink: SplitSink<MuxConnection<Box<dyn ProxyStream>>, MuxFrame>,
        mut frame_write_rx: Receiver<MuxFrame>,
        send_end: Option<Arc<Mutex<bool>>>,
    ) -> AbortHandle {
        let task = async move {
            while let Some(frame) = frame_write_rx.recv().await {
                // Peek EOF.
                match frame {
                    MuxFrame::StreamFin(ref stream_id) => {
                        let streams2 = streams.clone();
                        let stream_id2 = *stream_id;
                        tokio::spawn(async move {
                            delay_for(Duration::from_secs(4)).await;
                            streams2.lock().await.remove(&stream_id2);
                        });
                    }
                    _ => (),
                }
                // Send
                if let Err(_) = frame_sink.send(frame).await {
                    break;
                }
            }
            if let Some(send_end) = send_end {
                *send_end.lock().await = true;
            }
            streams.lock().await.clear();
        };
        let (task, handle) = abortable(task);
        tokio::spawn(task);
        handle
    }

    pub fn connector(
        conn: Box<dyn ProxyStream>,
        max_accepts: usize,
        concurrency: usize,
    ) -> MuxConnector {
        let (frame_sink, frame_stream) = MuxConnection::new(conn).split();
        let (frame_write_tx, frame_write_rx) = mpsc::channel::<MuxFrame>(1);
        let (recv_end, send_end) = (Arc::new(Mutex::new(false)), Arc::new(Mutex::new(false)));
        let streams: Streams = Arc::new(Mutex::new(HashMap::new()));
        let recv_handle = Self::run_frame_receive_loop(
            streams.clone(),
            frame_stream,
            Some(recv_end.clone()),
            None,
        );
        let send_handle = Self::run_frame_send_loop(
            streams.clone(),
            frame_sink,
            frame_write_rx,
            Some(send_end.clone()),
        );
        let session_id = random_u16();
        MuxConnector::new(
            max_accepts,
            concurrency,
            session_id,
            streams,
            frame_write_tx,
            recv_end,
            send_end,
            recv_handle,
            send_handle,
        )
    }

    pub fn acceptor(conn: Box<dyn ProxyStream>) -> MuxAcceptor {
        let (frame_sink, frame_stream) = MuxConnection::new(conn).split();
        let (frame_write_tx, frame_write_rx) = mpsc::channel::<MuxFrame>(1);
        let streams: Streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_accept_tx, stream_accept_rx) = mpsc::channel(1);
        let session_id = random_u16();
        let recv_handle = Self::run_frame_receive_loop(
            streams.clone(),
            frame_stream,
            None,
            Some(Accept {
                session_id,
                stream_accept_tx,
                frame_write_tx,
            }),
        );
        let send_handle =
            Self::run_frame_send_loop(streams.clone(), frame_sink, frame_write_rx, None);
        MuxAcceptor::new(session_id, stream_accept_rx, recv_handle, send_handle)
    }
}

pub struct MuxConnector {
    // Maximum number of acceptable streams.
    max_accepts: usize,
    // Stream concurrency.
    concurrency: usize,
    // ID for debugging purposes.
    session_id: SessionId,
    // Counter for number of streams created.
    total_accepted: usize,
    // Active streams.
    streams: Streams,
    // Sender for sending frames from streams to the send loop.
    frame_write_tx: Sender<MuxFrame>,
    // Flag the end of the receive loop.
    recv_end: Arc<Mutex<bool>>,
    // Flag the end of the send loop.
    send_end: Arc<Mutex<bool>>,
    // Handle to abort the receive loop.
    recv_handle: AbortHandle,
    // Handle to abort the send loop.
    send_handle: AbortHandle,
    // Indicates the connector has no active streams and is no longer accept
    // new stream request.
    done: AtomicBool,
}

impl MuxConnector {
    pub fn new(
        max_accepts: usize,
        concurrency: usize,
        session_id: SessionId,
        streams: Streams,
        frame_write_tx: Sender<MuxFrame>,
        recv_end: Arc<Mutex<bool>>,
        send_end: Arc<Mutex<bool>>,
        recv_handle: AbortHandle,
        send_handle: AbortHandle,
    ) -> Self {
        trace!(
            "new mux connector {} (max_accepts: {}, concurrency: {})",
            session_id,
            max_accepts,
            concurrency
        );
        MuxConnector {
            max_accepts,
            concurrency,
            session_id,
            total_accepted: 0,
            streams,
            frame_write_tx,
            recv_end,
            send_end,
            recv_handle,
            send_handle,
            done: AtomicBool::new(false),
        }
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    pub async fn new_stream(&mut self) -> Option<MuxStream> {
        if self.is_done() {
            return None;
        }
        if *self.recv_end.lock().await {
            self.done.store(true, Ordering::Relaxed);
            return None;
        }
        if *self.send_end.lock().await {
            self.done.store(true, Ordering::Relaxed);
            return None;
        }
        if self.total_accepted >= self.max_accepts {
            if self.streams.lock().await.is_empty() {
                self.done.store(true, Ordering::Relaxed);
            }
            return None;
        }
        if self.streams.lock().await.len() >= self.concurrency {
            return None;
        }
        let frame_write_tx = self.frame_write_tx.clone();
        let stream_id = random_u16();
        let (mux_stream, stream_read_tx) =
            MuxStream::new(self.session_id, stream_id, frame_write_tx);
        self.streams.lock().await.insert(stream_id, stream_read_tx);
        self.total_accepted += 1;
        Some(mux_stream)
    }
}

impl Drop for MuxConnector {
    fn drop(&mut self) {
        self.recv_handle.abort();
        self.send_handle.abort();
        trace!("drop mux connector {}", self.session_id);
    }
}

pub struct MuxAcceptor {
    // ID for debugging purposes.
    session_id: SessionId,
    // Receiver to receive accepted streams from this acceptor.
    stream_accept_rx: Receiver<MuxStream>,
    // Handle to abort the receive loop.
    recv_handle: AbortHandle,
    // Handle to abort the send loop.
    send_handle: AbortHandle,
}

impl MuxAcceptor {
    pub fn new(
        session_id: SessionId,
        stream_accept_rx: Receiver<MuxStream>,
        recv_handle: AbortHandle,
        send_handle: AbortHandle,
    ) -> Self {
        trace!("new mux acceptor {}", session_id);
        MuxAcceptor {
            session_id,
            stream_accept_rx,
            recv_handle,
            send_handle,
        }
    }
}

impl Drop for MuxAcceptor {
    fn drop(&mut self) {
        self.recv_handle.abort();
        self.send_handle.abort();
        trace!("drop mux acceptor {}", self.session_id);
    }
}

impl Stream for MuxAcceptor {
    type Item = MuxStream;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream_accept_rx.poll_recv(cx)
    }
}
