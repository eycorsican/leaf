use std::io::{Cursor, IoSlice};
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use rand::{thread_rng, RngCore};
use tokio::io::ReadBuf;
use tokio_util::io::poll_write_buf;

use crate::proxy::*;

mod packet;
mod template;

const RESPONSE_HANDSHAKE_SIZE: usize = 96 /* server hello */
     + 6 /* change cipher spec */  + 3 /* encrypted handshake */ ;
const LEN_HEADER_BUFFER_SIZE: usize = 3;
const LEN_BUFFER_SIZE: usize = 5;
const MAX_TLS_CHUNK_SIZE: u16 = 16 * 1024;

pub struct Handler {
    host: Arc<[u8]>,
}

enum ReadState {
    AwaitingResponse { remaining_read_len: usize },
    HeaderIncomplete(Cursor<[u8; LEN_BUFFER_SIZE]>),
    HeaderComplete { chunk_remaining: usize },
}

enum WriteState {
    Initial {
        host: Arc<[u8]>,
    },
    WritingRequest(Cursor<Vec<u8>>),
    WritingHeader {
        payload_len: u16,
        write_offset: usize,
    },
    WritingPayload {
        chunk_remaining: usize,
    },
}

struct Stream {
    stream: AnyStream,
    read_state: ReadState,
    write_state: WriteState,
}

impl Handler {
    pub fn new(host: &[u8]) -> Self {
        Self { host: host.into() }
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
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let stream = stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))?;

        Ok(Box::new(Stream::new(self.host.clone(), stream)))
    }
}

impl ReadState {
    fn merge_chunks(&mut self, data: &mut [u8]) -> usize {
        let mut write_index = 0;
        let mut read_index = 0;
        while read_index < data.len() {
            let mut part = &mut data[read_index..];
            match self {
                ReadState::AwaitingResponse { remaining_read_len } => {
                    let len = part.len().min(*remaining_read_len);
                    read_index += len;
                    *remaining_read_len -= len;
                    if *remaining_read_len == 0 {
                        let mut cursor = Cursor::new([0; LEN_BUFFER_SIZE]);
                        cursor.set_position(LEN_HEADER_BUFFER_SIZE as u64);
                        *self = ReadState::HeaderIncomplete(cursor);
                    }
                }
                ReadState::HeaderIncomplete(header_buf) => {
                    let pos = header_buf.position() as usize;
                    let len = part.len().min(LEN_BUFFER_SIZE - pos);
                    part = &mut part[..len];
                    read_index += len;
                    header_buf.get_mut()[pos..][..len].copy_from_slice(part);
                    header_buf.set_position(pos as u64 + len as u64);
                    if header_buf.position() as usize == LEN_BUFFER_SIZE {
                        let len = u16::from_be_bytes(
                            header_buf.get_ref()[LEN_HEADER_BUFFER_SIZE..]
                                .try_into()
                                .expect("obfs tls packet len size != 2"),
                        ) as usize;
                        *self = ReadState::HeaderComplete {
                            chunk_remaining: len,
                        };
                    }
                }
                ReadState::HeaderComplete { chunk_remaining } => {
                    let len = part.len().min(*chunk_remaining);
                    *chunk_remaining -= len;
                    data.copy_within(read_index..(read_index + len), write_index);
                    write_index += len;
                    read_index += len;
                    if *chunk_remaining == 0 {
                        *self = ReadState::HeaderIncomplete(Default::default());
                    }
                }
            }
        }
        write_index
    }
}

impl Stream {
    fn new(host: Arc<[u8]>, stream: AnyStream) -> Self {
        Self {
            stream,
            read_state: ReadState::AwaitingResponse {
                remaining_read_len: RESPONSE_HANDSHAKE_SIZE,
            },
            write_state: WriteState::Initial { host },
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut total_read_len = 0;
        let mut new_inited = 0;
        while total_read_len == 0 {
            let Self {
                read_state, stream, ..
            } = &mut *self;
            total_read_len = if let ReadState::AwaitingResponse { remaining_read_len } = read_state
            {
                let mut header_buf = [MaybeUninit::<u8>::uninit(); RESPONSE_HANDSHAKE_SIZE];
                let mut read_buf = ReadBuf::uninit(&mut header_buf[..*remaining_read_len]);
                ready!(Pin::new(stream).poll_read(cx, &mut read_buf))?;
                if read_buf.filled().is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "obfs tls server hello eof",
                    )));
                }
                read_state.merge_chunks(read_buf.filled_mut()); // Data should not contain any chunks.
                continue;
            } else {
                // Safety: the uninitialized part is managed by the new ReadBuf.
                let mut read_buf = ReadBuf::uninit(unsafe { buf.unfilled_mut() });
                ready!(Pin::new(stream).poll_read(cx, &mut read_buf))?;
                if read_buf.filled().is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "obfs tls eof",
                    )));
                }
                new_inited = new_inited.max(read_buf.initialized().len());
                read_state.merge_chunks(read_buf.filled_mut())
            };
        }
        // Safety: new_inited bytes is initialized by an inner read_buf.
        unsafe {
            buf.assume_init(new_inited);
        }
        buf.advance(total_read_len);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut payload_written = 0;
        while payload_written == 0 {
            let Self {
                stream,
                write_state,
                ..
            } = &mut *self;
            match write_state {
                WriteState::Initial { host } => {
                    buf = &buf[..buf.len().min(MAX_TLS_CHUNK_SIZE as usize)];
                    let req = generate_tls_request(&host, buf);
                    *write_state = WriteState::WritingRequest(Cursor::new(req));
                }
                WriteState::WritingRequest(req) => {
                    ready!(poll_write_buf(Pin::new(stream), cx, req))?;
                    if req.position() as usize == req.get_ref().len() {
                        *write_state = WriteState::WritingPayload { chunk_remaining: 0 };
                        return Poll::Ready(Ok(buf.len()));
                    }
                }
                WriteState::WritingHeader {
                    payload_len,
                    write_offset,
                } => {
                    let header = generate_header(*payload_len);
                    let buf_len = buf.len().min(*payload_len as usize);
                    let iov = [
                        IoSlice::new(&header[*write_offset..]),
                        IoSlice::new(&buf[..buf_len]),
                    ];
                    let write_len = ready!(Pin::new(stream).poll_write_vectored(cx, &iov))?;
                    *write_offset += write_len;
                    if let Some(chunk_written) = write_offset.checked_sub(LEN_BUFFER_SIZE) {
                        *write_state = WriteState::WritingPayload {
                            chunk_remaining: *payload_len as usize - chunk_written,
                        };
                        payload_written += chunk_written;
                        buf = &buf[chunk_written..];
                    }
                }
                WriteState::WritingPayload { chunk_remaining: 0 } => {
                    *write_state = WriteState::WritingHeader {
                        payload_len: buf.len().try_into().unwrap_or(MAX_TLS_CHUNK_SIZE),
                        write_offset: 0,
                    };
                }
                WriteState::WritingPayload { chunk_remaining } => {
                    let buf_len = buf.len().min(*chunk_remaining);
                    let write_len = ready!(Pin::new(stream).poll_write(cx, &buf[..buf_len]))?;
                    *chunk_remaining -= write_len;
                    payload_written += write_len;
                    buf = &buf[write_len..];
                }
            }
        }
        Poll::Ready(Ok(payload_written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn generate_tls_request(host: &[u8], payload: &[u8]) -> Vec<u8> {
    use std::mem::{size_of_val, transmute};
    use std::time::SystemTime;
    let mut rng = thread_rng();

    let mut hello = template::CLIENT_HELLO;
    let mut server_name = template::EXT_SERVER_NAME;
    let mut ticket = template::EXT_SESSION_TICKET;
    let other = template::EXT_OTHERS;
    let total_len = payload.len()
        + size_of_val(&hello)
        + size_of_val(&server_name)
        + host.len()
        + size_of_val(&ticket)
        + size_of_val(&other);

    hello.0.len = (total_len as u16 - 5).to_be();
    hello.0.handshake_len_2 = (total_len as u16 - 9).to_be();
    hello.0.random_unix_time = (SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32)
        .to_be();
    rng.fill_bytes(&mut hello.0.random_bytes);
    rng.fill_bytes(&mut hello.0.session_id);
    hello.0.ext_len = ((total_len - size_of_val(&hello)) as u16).to_be();
    ticket.0.session_ticket_ext_len = (payload.len() as u16).to_be();
    server_name.0.ext_len = (host.len() as u16 + 3 + 2).to_be();
    server_name.0.server_name_list_len = (host.len() as u16 + 3).to_be();
    server_name.0.server_name_len = (host.len() as u16).to_be();

    let mut req = Vec::with_capacity(total_len);
    unsafe {
        req.extend_from_slice(&transmute::<_, [u8; 138]>(hello));
        req.extend_from_slice(&transmute::<_, [u8; 4]>(ticket));
        req.extend_from_slice(payload);
        req.extend_from_slice(&transmute::<_, [u8; 9]>(server_name));
        req.extend_from_slice(host);
        req.extend_from_slice(&transmute::<_, [u8; 66]>(other));
    }
    req
}

fn generate_header(payload_len: u16) -> [u8; LEN_BUFFER_SIZE] {
    let mut tls_data_header = [
        0x17, 0x03, 0x03, /* 2 bytes of len goes here */ 0x00, 0x00,
    ];
    tls_data_header[3] = payload_len.to_be_bytes()[0];
    tls_data_header[4] = payload_len.to_be_bytes()[1];
    tls_data_header
}
