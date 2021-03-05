use std::cmp::min;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{io, pin::Pin};

use bytes::{BufMut, Bytes, BytesMut};
use futures::sink::Sink;
use futures::stream::Stream;
use futures::SinkExt;
use futures::StreamExt;
use futures::{
    ready,
    task::{Context, Poll},
    Future,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex as TokioMutex;

use crate::proxy::ProxyStream;

#[cfg(feature = "inbound-amux")]
pub mod inbound;
#[cfg(feature = "outbound-amux")]
pub mod outbound;

pub static NAME: &str = "amux";

pub const FRAME_STREAM: u8 = 0x01;
pub const FRAME_STREAM_FIN: u8 = 0x02;
pub const FRAME_STREAM_RST: u8 = 0x03;
pub const FRAME_CONNECTION_RST: u8 = 0x04;

type StreamId = u16;

pub enum MuxFrame {
    /// A frame to send stream data. The frame opens new stream implicitly, when
    /// the server side receives a Stream frame with an unseen stream ID, it should
    /// create a new stream for it.
    Stream(StreamId, Vec<u8>), // |type(1,0x01)|id(2)|len(2)|data|
    /// A frame to close the send half of a stream.
    StreamFin(StreamId), // |type(1,0x02)|id(2)|
    /// A frame to reset the connection. Although the underlying connection is
    /// a reliable stream, it need not be a TCP connection, and need not has a
    /// connection close mechanism, e.g. we don't rely on the EOF signal, and
    /// you don't have an EOF signal when using WebSocket as transport, instead
    /// we explicitly use a RST frame for closing the mux connection.
    ConnRst, // |type(1,0x04)|
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
            MuxFrame::ConnRst => {
                buf.put_u8(FRAME_CONNECTION_RST);
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
            MuxFrame::ConnRst => {
                write!(f, "ConnRst")
            }
        }
    }
}

pub type Streams = Arc<TokioMutex<HashMap<StreamId, Sender<Vec<u8>>>>>;

pub struct MuxStream {
    stream_id: StreamId,
    stream_read_rx: Receiver<Vec<u8>>,
    frame_write_tx: Sender<MuxFrame>,
    buf: BytesMut,
}

impl MuxStream {
    pub fn new(
        stream_id: StreamId,
        stream_read_rx: Receiver<Vec<u8>>,
        frame_write_tx: Sender<MuxFrame>,
    ) -> Self {
        MuxStream {
            stream_id,
            stream_read_rx,
            frame_write_tx,
            buf: BytesMut::new(),
        }
    }

    pub fn id(&self) -> StreamId {
        self.stream_id
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        log::trace!("drop mux stream {}", self.stream_id);
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
    item: Option<Bytes>,
}

impl<S> MuxConnection<S> {
    pub fn new(inner: S) -> Self {
        MuxConnection { inner, item: None }
    }
}

impl<S: AsyncRead + Unpin> Stream for MuxConnection<S> {
    type Item = io::Result<MuxFrame>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let me = &mut *self;
        let mut ftype = [0u8; 1];
        ready!(Pin::new(&mut AsyncReadExt::read_exact(&mut me.inner, &mut ftype)).poll(cx))?;
        match ftype[0] {
            FRAME_STREAM => {
                let mut stream_id = [0u8; 2];
                ready!(
                    Pin::new(&mut AsyncReadExt::read_exact(&mut me.inner, &mut stream_id)).poll(cx)
                )?;
                let stream_id = u16::from_be_bytes(stream_id);
                let mut len = [0u8; 2];
                ready!(Pin::new(&mut AsyncReadExt::read_exact(&mut me.inner, &mut len)).poll(cx))?;
                let len = u16::from_be_bytes(len) as usize;
                let mut data = vec![0u8; len];
                ready!(Pin::new(&mut AsyncReadExt::read_exact(&mut me.inner, &mut data)).poll(cx))?;
                Poll::Ready(Some(Ok(MuxFrame::Stream(stream_id, data))))
            }
            FRAME_STREAM_FIN => {
                let mut stream_id = [0u8; 2];
                ready!(
                    Pin::new(&mut AsyncReadExt::read_exact(&mut me.inner, &mut stream_id)).poll(cx)
                )?;
                let stream_id = u16::from_be_bytes(stream_id);
                Poll::Ready(Some(Ok(MuxFrame::StreamFin(stream_id))))
            }
            FRAME_CONNECTION_RST => Poll::Ready(Some(Ok(MuxFrame::ConnRst))),
            _ => Poll::Ready(None),
        }
    }
}

impl<S: AsyncWrite + Unpin> Sink<MuxFrame> for MuxConnection<S> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.item.is_none() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: MuxFrame) -> Result<(), Self::Error> {
        // TODO perhaps store multiple items in VecDeque?
        self.item.replace(item.to_bytes());
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let me = &mut *self;
        if let Some(item) = me.item.take() {
            ready!(Pin::new(&mut AsyncWriteExt::write_all(&mut me.inner, &item)).poll(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // TODO manual flush?
        let me = &mut *self;
        if me.item.is_none() {
            let frame = MuxFrame::ConnRst;
            ready!(Pin::new(&mut AsyncWriteExt::write_all(
                &mut me.inner,
                &frame.to_bytes()
            ))
            .poll(cx))?;
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

pub struct MuxClientConnection {
    stream_concurrency: u32,
    max_accept_streams: u32,
    accepted_streams: u32,
    frame_write_tx: Sender<MuxFrame>,
    streams: Streams,
    done: Arc<AtomicBool>,
}

impl MuxClientConnection {
    pub fn new(conn: Box<dyn ProxyStream>) -> Self {
        let (mut frame_sink, mut frame_stream) = MuxConnection::new(conn).split();
        let (frame_write_tx, mut frame_write_rx) = mpsc::channel::<MuxFrame>(64);
        let streams: Streams = Arc::new(TokioMutex::new(HashMap::new()));
        let streams2 = streams.clone();
        let done = Arc::new(AtomicBool::new(false));
        let done2 = done.clone();
        tokio::spawn(async move {
            while let Some(frame) = frame_stream.next().await {
                match frame {
                    Ok(frame) => {
                        match frame {
                            MuxFrame::Stream(stream_id, data) => {
                                if let Some(stream_read_tx) =
                                    streams2.lock().await.get_mut(&stream_id)
                                {
                                    // Send frame data to the stream.
                                    if let Err(e) = stream_read_tx.send(data).await {
                                        log::warn!("stream_read_tx send error: {}", e);
                                    }
                                }
                            }
                            MuxFrame::StreamFin(stream_id) => {
                                if let Some(stream_read_tx) =
                                    streams2.lock().await.get_mut(&stream_id)
                                {
                                    // Send an empty buffer to indicate EOF.
                                    if let Err(e) = stream_read_tx.send(Vec::new()).await {
                                        log::warn!("stream_read_tx send error: {}", e);
                                    }
                                }
                                // streams2.lock().await.remove(&stream_id);
                            }
                            MuxFrame::ConnRst => {
                                log::warn!("mux connection rst");
                                streams2.lock().await.clear();
                                done2.store(true, Ordering::SeqCst);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("read mux connection failed: {}", e);
                        streams2.lock().await.clear();
                        done2.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
        });

        let done2 = done.clone();
        // Collect and send out frames coming from mux stream writes.
        tokio::spawn(async move {
            while let Some(frame) = frame_write_rx.recv().await {
                if let Err(e) = frame_sink.send(frame).await {
                    log::warn!("send mux frame failed: {}", e);
                    // RST
                    done2.store(true, Ordering::SeqCst);
                    return;
                }
            }
            // EOF
            if let Err(e) = frame_sink.close().await {
                log::warn!("close mux conn failed: {}", e);
            }
            done2.store(true, Ordering::SeqCst);
        });

        MuxClientConnection {
            stream_concurrency: 0xffff,
            max_accept_streams: 0xffff,
            accepted_streams: 0,
            frame_write_tx,
            streams,
            done,
        }
    }

    pub async fn should_remove(&self) -> bool {
        if self.streams.lock().await.len() > 0 {
            return false;
        }
        if self.accepted_streams < self.max_accept_streams {
            return false;
        }
        if self.done.load(Ordering::SeqCst) {
            return true;
        }
        true
    }

    pub async fn new_stream(&mut self) -> io::Result<MuxStream> {
        if self.accepted_streams >= self.max_accept_streams {
            return Err(io::Error::new(io::ErrorKind::Other, "max_accept_streams"));
        }
        if self.streams.lock().await.len() >= self.stream_concurrency as usize {
            return Err(io::Error::new(io::ErrorKind::Other, "stream_concurrency"));
        }
        if self.done.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Other, "done"));
        }

        let frame_write_tx = self.frame_write_tx.clone();
        let (stream_read_tx, stream_read_rx) = mpsc::channel(64);

        use rand::{rngs::StdRng, RngCore, SeedableRng};
        let mut buf = [0u8; 2];
        let mut rng = StdRng::from_entropy();
        rng.fill_bytes(&mut buf);
        let stream_id = u16::from_be_bytes(buf);

        self.streams.lock().await.insert(stream_id, stream_read_tx);
        self.accepted_streams += 1;
        Ok(MuxStream::new(stream_id, stream_read_rx, frame_write_tx))
    }
}

pub struct MuxServerConnection {
    stream_accept_rx: Receiver<MuxStream>,
}

impl MuxServerConnection {
    pub fn new(conn: Box<dyn ProxyStream>) -> Self {
        let (mut frame_sink, mut frame_stream) = MuxConnection::new(conn).split();
        let (frame_write_tx, mut frame_write_rx) = mpsc::channel::<MuxFrame>(64);
        let streams: Streams = Arc::new(TokioMutex::new(HashMap::new()));
        let (mut stream_accept_tx, stream_accept_rx) = mpsc::channel(64);
        tokio::spawn(async move {
            while let Some(frame) = frame_stream.next().await {
                match frame {
                    Ok(frame) => {
                        match frame {
                            MuxFrame::Stream(stream_id, data) => {
                                if !streams.lock().await.contains_key(&stream_id) {
                                    let (stream_read_tx, stream_read_rx) = mpsc::channel(64);
                                    streams.lock().await.insert(stream_id, stream_read_tx);
                                    let mux_stream = MuxStream::new(
                                        stream_id,
                                        stream_read_rx,
                                        frame_write_tx.clone(),
                                    );
                                    if let Err(e) = stream_accept_tx.send(mux_stream).await {
                                        log::warn!("stream_accept_tx send error: {}", e);
                                    }
                                }
                                if let Some(stream_read_tx) =
                                    streams.lock().await.get_mut(&stream_id)
                                {
                                    if let Err(e) = stream_read_tx.send(data).await {
                                        log::warn!(
                                            "stream_read_tx {} send error: {}",
                                            &stream_id,
                                            e
                                        );
                                    }
                                }
                            }
                            MuxFrame::StreamFin(stream_id) => {
                                if let Some(stream_read_tx) =
                                    streams.lock().await.get_mut(&stream_id)
                                {
                                    log::warn!("fin read from {}", stream_id);
                                    if let Err(e) = stream_read_tx.send(Vec::new()).await {
                                        log::warn!("stream_read_tx send error: {}", e);
                                    }
                                }
                                // streams.lock().await.remove(&stream_id);
                            }
                            MuxFrame::ConnRst => {
                                log::warn!("mux connection rst");
                                streams.lock().await.clear();
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("receive mux frame failed: {}", e);
                        streams.lock().await.clear();
                        break;
                    }
                }
            }
        });

        // Collect and send out frames coming from mux stream writes.
        tokio::spawn(async move {
            while let Some(frame) = frame_write_rx.recv().await {
                if let Err(e) = frame_sink.send(frame).await {
                    log::warn!("send mux frame failed: {}", e);
                    // RST
                    return;
                }
            }
            // EOF
            if let Err(e) = frame_sink.close().await {
                log::warn!("close mux conn failed: {}", e);
            }
        });

        MuxServerConnection { stream_accept_rx }
    }
}

impl Stream for MuxServerConnection {
    type Item = MuxStream;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream_accept_rx.poll_recv(cx)
    }
}
