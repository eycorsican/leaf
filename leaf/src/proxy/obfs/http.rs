use std::io::Cursor;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use base64::prelude::*;
use memchr::memmem;
use rand::{thread_rng, RngCore};
use tokio::io::ReadBuf;
use tokio_util::io::poll_write_buf;

use crate::proxy::*;

const RESPONSE_BUFFER_SIZE: usize = 1024;

pub struct Handler {
    req_line: Arc<[u8]>,
}

enum ReadState {
    AwaitingResponse { res_buf: Vec<u8> },
    ConsumingResponse { res: Cursor<Vec<u8>> },
    Transfer,
}

enum WriteState {
    Initial { req_line: Arc<[u8]> },
    WritingRequest(Cursor<Vec<u8>>),
    Transfer,
}

struct Stream {
    stream: AnyStream,
    read_state: ReadState,
    write_state: WriteState,
}

impl Handler {
    pub fn new(path: &[u8], host: &[u8]) -> Self {
        let mut req_line = Vec::with_capacity(120 + path.len() + host.len());
        req_line.extend_from_slice(b"GET ");
        req_line.extend_from_slice(path);
        req_line.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        req_line.extend_from_slice(host);
        req_line.extend_from_slice(b"\r\nUser-Agent: curl/7.");
        let mut thread_rng = thread_rng();
        req_line.extend_from_slice((thread_rng.next_u32() % 51).to_string().as_bytes());
        req_line.push(b'.');
        req_line.extend_from_slice((thread_rng.next_u32() % 2).to_string().as_bytes());
        req_line.extend_from_slice(
            b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-Websocket-Key: ",
        );
        Self {
            req_line: req_line.into(),
        }
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Next
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let stream = stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))?;

        Ok(Box::new(Stream::new(self.req_line.clone(), stream)))
    }
}

impl Stream {
    fn new(req_line: Arc<[u8]>, stream: AnyStream) -> Self {
        Self {
            stream,
            read_state: ReadState::AwaitingResponse {
                res_buf: Vec::with_capacity(RESPONSE_BUFFER_SIZE),
            },
            write_state: WriteState::Initial { req_line },
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let Self {
                read_state, stream, ..
            } = &mut *self;
            match read_state {
                ReadState::AwaitingResponse { res_buf } => {
                    if res_buf.len() >= RESPONSE_BUFFER_SIZE {
                        // The response may be too large. This should not happen in obfs.
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            "obfs response too large",
                        )));
                    }
                    let read_len =
                        ready!(tokio_util::io::poll_read_buf(Pin::new(stream), cx, res_buf))?;
                    if read_len == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            "obfs response too short",
                        )));
                    }
                    let req_body_pos = match memmem::find(res_buf, b"\r\n\r\n") {
                        Some(p) => p + 4,
                        None => continue,
                    };
                    let mut payload = Cursor::new(std::mem::take(res_buf));
                    payload.set_position(req_body_pos as u64);
                    *read_state = ReadState::ConsumingResponse { res: payload };
                }
                ReadState::ConsumingResponse { res } => {
                    let remaining = &res.get_ref()[res.position() as usize..];
                    let to_write = remaining.len().min(buf.remaining());
                    buf.put_slice(&remaining[..to_write]);
                    res.set_position(res.position() + to_write as u64);
                    if res.position() as usize == res.get_ref().len() {
                        *read_state = ReadState::Transfer;
                    }
                    return Poll::Ready(Ok(()));
                }
                ReadState::Transfer => return Pin::new(stream).poll_read(cx, buf),
            };
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Self {
            write_state,
            stream,
            ..
        } = &mut *self;
        loop {
            match write_state {
                WriteState::Initial { req_line } => {
                    let req = generate_http_request(req_line, buf);
                    *write_state = WriteState::WritingRequest(Cursor::new(req));
                }
                WriteState::WritingRequest(req) => {
                    ready!(poll_write_buf(Pin::new(stream), cx, req))?;
                    if req.position() as usize == req.get_ref().len() {
                        *write_state = WriteState::Transfer;
                        return Poll::Ready(Ok(buf.len()));
                    }
                }
                WriteState::Transfer => break,
            }
        }
        Pin::new(&mut *stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn generate_http_request(req_line: &[u8], body: &[u8]) -> Vec<u8> {
    let mut req = Vec::with_capacity(req_line.len() + 120);
    req.extend_from_slice(&req_line);
    let mut ws_key = [0; 16];
    thread_rng().fill_bytes(&mut ws_key);
    let mut b64 = [0; 32];
    let b64_len = BASE64_URL_SAFE
        .encode_slice(&ws_key, &mut b64)
        .expect("A base64 repr of 16 bytes should not exceed 32 chars");
    req.extend_from_slice(&b64[..b64_len]);
    req.extend_from_slice(b"\r\nContent-Length: ");
    req.extend_from_slice(body.len().to_string().as_bytes());
    req.extend_from_slice(b"\r\n\r\n");
    req.extend_from_slice(body);
    req
}
