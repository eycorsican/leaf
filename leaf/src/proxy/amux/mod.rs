use std::cmp::min;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{io, pin::Pin};

use bytes::{Buf, BufMut, Bytes, BytesMut};
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
    Future, TryFutureExt,
};
use log::trace;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::time::sleep;

#[cfg(feature = "inbound-amux")]
pub mod inbound;
#[cfg(feature = "outbound-amux")]
pub mod outbound;

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

enum TaskState {
    Idle,
    Pending(Pin<Box<dyn Future<Output = io::Result<()>> + 'static + Sync + Send>>),
}

pub struct MuxStream {
    session_id: SessionId,
    stream_id: StreamId,
    stream_read_rx: Receiver<Vec<u8>>,
    frame_write_tx: Sender<MuxFrame>,
    buf: BytesMut,
    write_state: TaskState,
    shutdown_state: TaskState,
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
                write_state: TaskState::Idle,
                shutdown_state: TaskState::Idle,
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
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        if !self.buf.is_empty() {
            let to_read = min(buf.remaining(), self.buf.len());
            let for_read = self.buf.split_to(to_read);
            buf.put_slice(&for_read[..to_read]);
            return Poll::Ready(Ok(()));
        }
        Poll::Ready(
            ready!(self.stream_read_rx.poll_recv(cx)).map_or(Err(broken_pipe()), |data| {
                if data.is_empty() {
                    Ok(()) // EOF
                } else {
                    let to_read = min(buf.remaining(), data.len());
                    buf.put_slice(&data[..to_read]);
                    if data.len() > to_read {
                        self.buf.extend_from_slice(&data[to_read..]);
                    }
                    Ok(())
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
        loop {
            match self.write_state {
                TaskState::Idle => {
                    let frame = MuxFrame::Stream(self.stream_id, buf.to_vec());
                    let tx = self.frame_write_tx.clone();
                    let task =
                        Box::pin(async move { tx.send(frame).map_err(|_| broken_pipe()).await });
                    self.write_state = TaskState::Pending(task);
                }
                TaskState::Pending(ref mut task) => {
                    let res = ready!(task.as_mut().poll(cx).map_ok(|_| buf.len()));
                    self.write_state = TaskState::Idle;
                    return Poll::Ready(res);
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        loop {
            match self.shutdown_state {
                TaskState::Idle => {
                    let frame = MuxFrame::StreamFin(self.stream_id);
                    let tx = self.frame_write_tx.clone();
                    let task =
                        Box::pin(async move { tx.send(frame).map_err(|_| broken_pipe()).await });
                    self.shutdown_state = TaskState::Pending(task);
                }
                TaskState::Pending(ref mut task) => {
                    let res = ready!(task.as_mut().poll(cx).map_ok(|_| ()));
                    self.shutdown_state = TaskState::Idle;
                    return Poll::Ready(res);
                }
            }
        }
    }
}

pub struct MuxConnection<S> {
    inner: S,
    read_buf: BytesMut,
    write_buf: BytesMut,
    backpressure_boundary: usize,
}

fn unknown_frame() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "unknown frame type")
}

impl<S> MuxConnection<S> {
    pub fn new(inner: S) -> Self {
        MuxConnection {
            inner,
            read_buf: BytesMut::with_capacity(2 * 1024),
            write_buf: BytesMut::new(),
            backpressure_boundary: 2 * 1024,
        }
    }

    pub fn decode_frame(&mut self) -> io::Result<Option<MuxFrame>> {
        let mut buf = &self.read_buf[..];
        if buf.is_empty() {
            return Ok(None);
        }
        match buf[0] {
            FRAME_STREAM => {
                buf = &buf[1..];

                if buf.len() < 2 {
                    self.read_buf.reserve(3);
                    return Ok(None);
                }
                let stream_id = u16::from_be_bytes((&buf[..2]).try_into().unwrap());
                buf = &buf[2..];

                if buf.len() < 2 {
                    self.read_buf.reserve(5);
                    return Ok(None);
                }
                let len = u16::from_be_bytes((&buf[..2]).try_into().unwrap()) as usize;
                buf = &buf[2..];

                if buf.len() < len {
                    self.read_buf.reserve(5 + len);
                    return Ok(None);
                }
                let data = &buf[..len];

                // TODO freeze bytes
                let frame = MuxFrame::Stream(stream_id, data.to_vec());
                let _ = self.read_buf.split_to(5 + len);

                self.read_buf.reserve(3); // minimal frame size

                Ok(Some(frame))
            }
            FRAME_STREAM_FIN => {
                buf = &buf[1..];

                if buf.len() < 2 {
                    self.read_buf.reserve(3);
                    return Ok(None);
                }
                let stream_id = u16::from_be_bytes((&buf[..2]).try_into().unwrap());

                let frame = MuxFrame::StreamFin(stream_id);
                let _ = self.read_buf.split_to(1 + 2);

                self.read_buf.reserve(3); // minimal frame size

                Ok(Some(frame))
            }
            _ => Err(unknown_frame()),
        }
    }

    pub fn encode_frame(&mut self, frame: MuxFrame) -> io::Result<()> {
        self.write_buf.extend_from_slice(&frame.to_bytes());
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> Stream for MuxConnection<S> {
    type Item = io::Result<MuxFrame>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        use tokio_util::io::poll_read_buf;
        let me = &mut *self;
        loop {
            // Upon `None` return, the `read_buf` must have properly reserved
            // space for further data.
            if let Some(frame) = me.decode_frame()? {
                return Poll::Ready(Some(Ok(frame)));
            }
            me.read_buf.reserve(1); // avoid spurious EOF
            let bytect = match poll_read_buf(Pin::new(&mut me.inner), cx, &mut me.read_buf)? {
                Poll::Ready(ct) => ct,
                Poll::Pending => return Poll::Pending,
            };
            if bytect == 0 {
                return Poll::Ready(Some(Err(broken_pipe())));
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> Sink<MuxFrame> for MuxConnection<S> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.write_buf.len() >= self.backpressure_boundary {
            self.poll_flush(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: MuxFrame) -> Result<(), Self::Error> {
        self.encode_frame(item)?;
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let me = &mut *self;

        // ready!(Pin::new(&mut me.inner.write_all(&me.write_buf)).poll(cx))?;

        while !me.write_buf.is_empty() {
            let n = ready!(Pin::new(&mut me.inner).poll_write(cx, &me.write_buf))?;
            if n == 0 {
                return Poll::Ready(Err(broken_pipe()));
            }
            me.write_buf.advance(n);
        }

        ready!(Pin::new(&mut me.inner).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let me = &mut *self;
        ready!(Pin::new(&mut me.inner).poll_flush(cx))?;
        ready!(Pin::new(&mut me.inner).poll_shutdown(cx))?;
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
    fn run_frame_receive_loop<S>(
        streams: Streams,
        mut frame_stream: SplitStream<MuxConnection<S>>,
        recv_end: Option<Arc<Mutex<bool>>>,
        mut accept: Option<Accept>,
    ) -> AbortHandle
    where
        S: 'static + AsyncRead + AsyncWrite + Unpin + Send,
    {
        let task = Box::pin(async move {
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
                                        if stream_accept_tx.send(mux_stream).await.is_err() {
                                            // The `Incoming` transport has been dropped.
                                            break;
                                        }
                                    }
                                }
                                // Sends data to the stream.
                                if let Some(stream_read_tx) =
                                    streams.lock().await.get(&stream_id).cloned()
                                {
                                    // FIXME error
                                    let _ = stream_read_tx.send(data).await;
                                }
                            }
                            MuxFrame::StreamFin(stream_id) => {
                                // Send an empty buffer to indicate EOF.
                                if let Some(stream_read_tx) =
                                    streams.lock().await.get(&stream_id).cloned()
                                {
                                    // FIXME error
                                    let _ = stream_read_tx.send(Vec::new()).await;
                                }
                                let streams2 = streams.clone();
                                tokio::spawn(async move {
                                    sleep(Duration::from_secs(4)).await;
                                    streams2.lock().await.remove(&stream_id);
                                });
                            }
                        }
                    }
                    // Borken pipe.
                    Err(_) => {
                        break;
                    }
                }
            }
            // Stop receving.
            if let Some(recv_end) = recv_end {
                *recv_end.lock().await = true;
            }
            streams.lock().await.clear();
        });
        let (task, handle) = abortable(task);
        tokio::spawn(task);
        handle
    }

    fn run_frame_send_loop<S>(
        streams: Streams,
        mut frame_sink: SplitSink<MuxConnection<S>, MuxFrame>,
        mut frame_write_rx: Receiver<MuxFrame>,
        send_end: Option<Arc<Mutex<bool>>>,
    ) -> AbortHandle
    where
        S: 'static + AsyncRead + AsyncWrite + Unpin + Send,
    {
        let task = Box::pin(async move {
            while let Some(frame) = frame_write_rx.recv().await {
                // Peek EOF.
                if let MuxFrame::StreamFin(ref stream_id) = frame {
                    let streams2 = streams.clone();
                    let stream_id2 = *stream_id;
                    tokio::spawn(async move {
                        sleep(Duration::from_secs(4)).await;
                        streams2.lock().await.remove(&stream_id2);
                    });
                }
                // Send
                if frame_sink.send(frame).await.is_err() {
                    break;
                }
            }
            if let Some(send_end) = send_end {
                *send_end.lock().await = true;
            }
            streams.lock().await.clear();
        });
        let (task, handle) = abortable(task);
        tokio::spawn(task);
        handle
    }

    pub fn connector<S>(conn: S, max_accepts: usize, concurrency: usize) -> MuxConnector
    where
        S: 'static + AsyncRead + AsyncWrite + Unpin + Send,
    {
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

    pub fn acceptor<S>(conn: S) -> MuxAcceptor
    where
        S: 'static + AsyncRead + AsyncWrite + Unpin + Send,
    {
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
        let send_handle = Self::run_frame_send_loop(streams, frame_sink, frame_write_rx, None);
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
    #[allow(clippy::too_many_arguments)]
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
