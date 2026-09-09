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
use tracing::trace;
use tungstenite::error::Error as WsError;
use tungstenite::Message;

pub struct WebSocketToStream<S> {
    buf: BytesMut,
    inner: S,
    /// Whether the frame that stands in for a half-close has been handed to
    /// the sink yet. `poll_shutdown` can be polled more than once, and the
    /// frame goes out exactly once.
    end_signalled: bool,
}

impl<S> WebSocketToStream<S> {
    pub fn new(stream: S) -> Self {
        WebSocketToStream {
            buf: BytesMut::new(),
            inner: stream,
            end_signalled: false,
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
                    Message::Binary(data) if !data.is_empty() => {
                        let to_read = min(buf.remaining(), data.len());
                        buf.put_slice(&data[..to_read]);
                        if data.len() > to_read {
                            self.buf.extend_from_slice(&data[to_read..]);
                        }
                        trace!("poll_read {} bytes", buf.filled().len());
                        Ok(())
                    }
                    // Either shape of "nothing more from this side": a Close
                    // frame, or the empty frame `poll_shutdown` sends. Both
                    // fill no bytes, which is what an end of stream is.
                    Message::Binary(_) | Message::Close(_) => Ok(()),
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
        trace!("poll_write {} bytes", buf.len());
        if buf.is_empty() {
            // An empty frame is how `poll_shutdown` says this side has
            // finished. Nobody should be able to say it by accident.
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut self.inner)
            .poll_ready(cx)
            .map_err(|_| broken_pipe()))?;

        let msg = Message::Binary(buf.to_vec());
        Pin::new(&mut self.inner)
            .start_send(msg)
            .map_err(|_| broken_pipe())?;

        let _ = Pin::new(&mut self.inner).poll_flush(cx);

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|_| broken_pipe())
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // WebSocket is a transport here, and a shutdown of the write side is a
        // half close: this side has finished sending and goes on reading.
        // WebSocket has no such thing of its own.
        //
        // A Close frame is the obvious candidate and the wrong one. RFC 6455
        // makes it the start of closing the whole connection, and tungstenite
        // enforces that on both ends: once a Close has been received, the
        // connection will not carry another data frame, so the reply still on
        // its way back is lost. That is worse than saying nothing.
        //
        // An empty binary frame says the same thing and costs nothing. It is
        // an ordinary data frame carrying no bytes, so a peer that does not
        // understand it delivers nothing to its application and carries on --
        // exactly today's behaviour. The read side above has always turned a
        // frame with no bytes into an end of stream, so between two leaf nodes
        // this is precisely the signal that was missing.
        //
        // Still behind an option, because a peer that treats an empty frame as
        // an error rather than as nothing would end a session that works
        // today. `poll_close` is not called either way: closing the sink would
        // end the direction that is still carrying the reply.
        if !*crate::option::WS_HALF_CLOSE {
            return Poll::Ready(Ok(()));
        }
        if !self.end_signalled {
            ready!(Pin::new(&mut self.inner)
                .poll_ready(cx)
                .map_err(|_| broken_pipe()))?;
            Pin::new(&mut self.inner)
                .start_send(Message::Binary(Vec::new()))
                .map_err(|_| broken_pipe())?;
            self.end_signalled = true;
        }
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|_| broken_pipe())
    }
}

#[cfg(test)]
mod tests {
    use futures::channel::mpsc;
    use tokio::io::AsyncWriteExt;

    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// A shutdown of the write side emits a Close frame, or nothing at all,
    /// according to the option -- and never closes the sink, which would end
    /// the direction still carrying the reply.
    #[test]
    fn shutdown_signals_the_end_of_this_side_only_when_asked_to() {
        runtime().block_on(async {
            let (sink, mut frames) = mpsc::channel::<Message>(4);
            let mut stream = WebSocketToStream::new(sink);

            stream.write_all(b"a request").await.unwrap();
            stream.shutdown().await.unwrap();

            // Nothing here is awaited: whatever the shutdown had to say has
            // been said by the time it returns, and awaiting what is not
            // coming would hang rather than fail.
            assert!(
                matches!(frames.try_recv(), Ok(Message::Binary(ref data)) if data == b"a request"),
                "the request itself should arrive as one binary frame"
            );
            let closing = frames.try_recv();
            if *crate::option::WS_HALF_CLOSE {
                assert!(
                    matches!(closing, Ok(Message::Binary(ref data)) if data.is_empty()),
                    "a half close should be signalled with an empty frame, got {:?}",
                    closing
                );
            } else {
                // Nothing sent, and the channel still open: the sink was not
                // closed either, so the direction carrying the reply survives.
                assert!(
                    closing.is_err(),
                    "nothing should be sent and the sink should stay open, got {:?}",
                    closing
                );
            }
        });
    }

    #[test]
    fn half_close_is_off_unless_asked_for() {
        if std::env::var("WS_HALF_CLOSE").is_ok() {
            // The environment chose; the case above covers both ways.
            return;
        }
        assert!(!*crate::option::WS_HALF_CLOSE);
    }
}
