use std::{io, pin::Pin};

use bytes::BytesMut;
use futures::{
    ready,
    task::{Context, Poll},
    Future,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::ProxyStream;

/// A proxy stream simply wraps a stream implements `AsyncRead` and `AsyncWrite`.
pub struct SimpleProxyStream<T>(pub T);

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> ProxyStream for SimpleProxyStream<T> {}

impl<T: AsyncRead + Unpin> AsyncRead for SimpleProxyStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for SimpleProxyStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}

/// A proxy stream writes a header along with the first payload.
pub struct BufHeadProxyStream<T> {
    pub inner: T,
    pub head: Option<BytesMut>,
}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> ProxyStream for BufHeadProxyStream<T> {}

impl<T> AsyncRead for BufHeadProxyStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for BufHeadProxyStream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.head.is_some() {
            if let Some(mut head) = self.head.take() {
                let payload_size = buf.len();
                head.extend_from_slice(buf);
                ready!(Pin::new(&mut self.inner.write_all(&head)).poll(cx))?;
                return Poll::Ready(Ok(payload_size));
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
