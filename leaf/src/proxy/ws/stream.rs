use std::cmp::min;
use std::io;
use std::pin::Pin;

use bytes::BytesMut;
use futures::sink::Sink;
use futures::stream::Stream;
use futures::{
    ready,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tungstenite::error::Error as WsError;
use tungstenite::Message;

pub struct WebSocketToStream<S> {
    buf: BytesMut,
    inner: S,
}

impl<S> WebSocketToStream<S> {
    pub fn new(stream: S) -> Self {
        WebSocketToStream {
            buf: BytesMut::new(),
            inner: stream,
        }
    }
}

fn broken_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "broken pipe")
}

fn invalid_frame() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "invalid frame")
}

impl<S: Stream<Item = Result<Message, WsError>> + Sink<Message> + Unpin> AsyncRead
    for WebSocketToStream<S>
{
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
        Poll::Ready(ready!(Pin::new(&mut self.inner).poll_next(cx)).map_or(
            Err(broken_pipe()),
            |item| {
                item.map_or(Err(broken_pipe()), |msg| match msg {
                    Message::Binary(data) => {
                        let to_read = min(buf.remaining(), data.len());
                        buf.put_slice(&data[..to_read]);
                        if data.len() > to_read {
                            self.buf.extend_from_slice(&data[to_read..]);
                        }
                        Ok(())
                    }
                    Message::Close(_) => Ok(()),
                    _ => Err(invalid_frame()),
                })
            },
        ))
    }
}

impl<S: Sink<Message> + Unpin> AsyncWrite for WebSocketToStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(Pin::new(&mut self.inner)
            .poll_ready(cx)
            .map_err(|_| broken_pipe()))?;

        let msg = Message::Binary(buf.to_vec());
        Pin::new(&mut self.inner)
            .start_send(msg)
            .map_err(|_| broken_pipe())?;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|_| broken_pipe())
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        // We're using WebSocket as a transport, a shutdown on the write side
        // means a half close of the stream, it seems that WebSocket lacks this
        // half closing capability, sending a close frame means closing the
        // whole socket. In order to support half close connections, we do not
        // call poll_close() and instead wait for downlink timeout to cancel
        // the underlying connection.
        Poll::Ready(Ok(()))
    }
}
