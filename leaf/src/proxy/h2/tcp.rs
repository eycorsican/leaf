use std::cmp::min;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::stream::Stream;
use futures::TryFutureExt;
use log::*;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use url::Url;

use crate::{
    proxy::{OutboundConnect, ProxyStream, SimpleProxyStream, TcpOutboundHandler},
    session::Session,
};

struct Adapter {
    send_stream: h2::SendStream<Bytes>,
    recv_stream: h2::RecvStream,
    recv_buf: BytesMut,
}

impl AsyncRead for Adapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        if !self.recv_buf.is_empty() {
            let to_read = min(buf.remaining(), self.recv_buf.len());
            let for_read = self.recv_buf.split_to(to_read);
            buf.put_slice(&for_read[..to_read]);
            return Poll::Ready(Ok(()));
        }
        if self.recv_stream.is_end_stream() {
            return Poll::Ready(Ok(()));
        }
        let item = match Pin::new(&mut self.recv_stream).poll_next(cx) {
            Poll::Ready(item) => item,
            Poll::Pending => return Poll::Pending,
        };
        match item {
            Some(res) => match res {
                Ok(data) => {
                    let to_read = min(buf.remaining(), data.len());
                    buf.put_slice(&data[..to_read]);
                    if data.len() > to_read {
                        self.recv_buf.extend_from_slice(&data[to_read..]);
                    }
                    Poll::Ready(Ok(()))
                }
                Err(e) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("receive data failed: {}", e),
                ))),
            },
            None => {
                panic!("could never happend, we already checked stream end");
            }
        }
    }
}

impl AsyncWrite for Adapter {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // FIXME reserve capacity before sending to avoid memory issue
        let mut buf2 = BytesMut::new();
        buf2.extend_from_slice(buf);
        match me.send_stream.send_data(buf2.freeze(), false) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("send data failed: {}", e),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub struct Handler {
    pub path: String,
    pub host: String,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    async fn handle_tcp<'a>(
        &'a self,
        _sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        match stream {
            Some(stream) => {
                // stream is aussumed to be a connection ready for h2 handshake,
                // e.g. a TLS connection negotiated with alpn h2.
                let (client, conn) = h2::client::handshake(stream)
                    .map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, format!("handshake failed: {}", e))
                    })
                    .await?;
                let mut url = Url::parse(&format!("https://{}", self.host)).unwrap();
                url = url.join(self.path.as_str()).unwrap();
                let req = http::Request::builder()
                    .method(http::Method::PUT)
                    .uri(&url.to_string())
                    .body(())
                    .unwrap();

                let mut client = client
                    .ready()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 error: {}", e)))
                    .await?;
                let (resp, send_stream) = client.send_request(req, false).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("h2 error: {}", e))
                })?;

                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        debug!("connection failed: {}", e);
                    }
                });

                let (parts, recv_stream) = resp
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 error: {}", e)))
                    .await?
                    .into_parts();
                if parts.status != http::status::StatusCode::OK {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("h2 failed with status code: {}", parts.status),
                    ));
                }
                let h2_stream = Adapter {
                    send_stream,
                    recv_stream,
                    recv_buf: BytesMut::new(),
                };
                Ok(Box::new(SimpleProxyStream(h2_stream)))
            }
            None => Err(io::Error::new(io::ErrorKind::Other, "invalid h2 input")),
        }
    }
}
