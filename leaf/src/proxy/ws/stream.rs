use std::cmp::min;
use std::io;
use std::pin::Pin;

use bytes::BytesMut;
use futures::sink::Sink;
use futures::stream::Stream;
use futures::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
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

impl<S: Stream<Item = Result<Message, WsError>> + Sink<Message> + Unpin> AsyncRead
    for WebSocketToStream<S>
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.buf.is_empty() {
            let to_read = min(buf.len(), self.buf.len());
            let for_read = self.buf.split_to(to_read);
            (&mut buf[..to_read]).copy_from_slice(&for_read[..to_read]);
            return Poll::Ready(Ok(to_read));
        }
        let item = match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(item) => item,
            Poll::Pending => return Poll::Pending,
        };
        match item {
            Some(item) => {
                match item {
                    Ok(msg) => {
                        match msg {
                            Message::Binary(data) => {
                                let to_read = min(buf.len(), data.len());
                                (&mut buf[..to_read]).copy_from_slice(&data[..to_read]);
                                if data.len() > to_read {
                                    self.buf.extend_from_slice(&data[to_read..]);
                                }
                                Poll::Ready(Ok(to_read))
                            }
                            Message::Close(_) => {
                                // FIXME should we send close here?
                                Pin::new(&mut self.inner)
                                    .poll_close(cx)
                                    .map_ok(|_| 0)
                                    .map_err(|_| {
                                        io::Error::new(io::ErrorKind::Other, "error closing")
                                    })
                            }
                            _ => {
                                // FIXME
                                Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::Interrupted,
                                    "unexpected ws msg",
                                )))
                            }
                        }
                    }
                    Err(err) => {
                        // FIXME
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            format!("ws error: {}", err),
                        )))
                    }
                }
            }
            None => {
                // FIXME
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "none msg")))
            }
        }
    }
}

impl<S: Sink<Message> + Unpin> AsyncWrite for WebSocketToStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Poll::Pending = Pin::new(&mut self.inner).poll_ready(cx) {
            return Poll::Pending;
        }

        let msg = Message::Binary(Vec::from(buf));
        match Pin::new(&mut self.inner).start_send(msg) {
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "ws send error",
            ))),
            Ok(()) => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_close(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => Poll::Ready(Ok(())),
        }
    }
}
