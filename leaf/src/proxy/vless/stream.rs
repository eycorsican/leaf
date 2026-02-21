pub fn build_vless_tcp_header(
    uuid_bytes: &[u8; 16],
    dst_addr: &str,
    dst_port: u16,
    addr_type: u8,
) -> Vec<u8> {
    let mut vless_header = vec![];
    vless_header.push(0x00); // Version
    vless_header.extend_from_slice(uuid_bytes);

    // TCP - Use Vision Flow
    let flow_str = b"xtls-rprx-vision";
    vless_header.push(18); // Extensions length
    vless_header.push(0x0a); // Protobuf Field 1, Type Length-Delimited
    vless_header.push(16); // String length
    vless_header.extend_from_slice(flow_str);
    vless_header.push(0x01); // Command: TCP

    vless_header.push((dst_port >> 8) as u8);
    vless_header.push((dst_port & 0xFF) as u8);
    vless_header.push(addr_type);

    match addr_type {
        1 => {
            let parts: Vec<u8> = dst_addr.split('.').map(|s| s.parse().unwrap()).collect();
            vless_header.extend_from_slice(&parts);
        }
        2 => {
            vless_header.push(dst_addr.len() as u8);
            vless_header.extend_from_slice(dst_addr.as_bytes());
        }
        3 => {
            let addr: std::net::Ipv6Addr = dst_addr.parse().unwrap();
            vless_header.extend_from_slice(&addr.octets());
        }
        _ => unreachable!(),
    }
    vless_header
}

pub struct VisionParser {
    uuid_bytes: [u8; 16],
    v_remaining_cmd: i32,
    v_remaining_content: i32,
    v_remaining_padding: i32,
    v_current_cmd: u8,
    v_buffer: Vec<u8>,
    vless_response_header_parsed: bool,
    pub v_direct_copy_rx: bool,
    pub v_vision_done: bool,
}

impl VisionParser {
    pub fn new(uuid_bytes: [u8; 16]) -> Self {
        Self {
            uuid_bytes,
            v_remaining_cmd: -1,
            v_remaining_content: -1,
            v_remaining_padding: -1,
            v_current_cmd: 0,
            v_buffer: Vec::new(),
            vless_response_header_parsed: false,
            v_direct_copy_rx: false,
            v_vision_done: false,
        }
    }

    pub fn parse(&mut self, data: &[u8]) -> Vec<u8> {
        self.v_buffer.extend_from_slice(data);
        let mut to_client = Vec::new();
        let mut offset = 0;

        if !self.vless_response_header_parsed {
            if self.v_buffer.len() >= 2 {
                self.vless_response_header_parsed = true;
                offset += 2; // Skip 0x00 0x00 VLESS response header
            } else {
                return to_client; // Wait for more data
            }
        }

        while offset < self.v_buffer.len() {
            if self.v_direct_copy_rx {
                to_client.extend_from_slice(&self.v_buffer[offset..]);
                offset = self.v_buffer.len();
                break;
            }

            if self.v_remaining_cmd == -1
                && self.v_remaining_content == -1
                && self.v_remaining_padding == -1
            {
                if self.v_buffer.len() - offset >= 21
                    && &self.v_buffer[offset..offset + 16] == self.uuid_bytes.as_slice()
                {
                    offset += 16;
                    self.v_remaining_cmd = 5;
                } else if self.v_buffer.len() - offset < 21 {
                    // Wait for more data to check UUID
                    break;
                } else {
                    // UUID not found and buffer is large enough: Vision parsing is done.
                    self.v_vision_done = true;
                    to_client.extend_from_slice(&self.v_buffer[offset..]);
                    offset = self.v_buffer.len();
                    break;
                }
            }

            while offset < self.v_buffer.len() && self.v_remaining_cmd > 0 {
                let data = self.v_buffer[offset];
                offset += 1;
                match self.v_remaining_cmd {
                    5 => self.v_current_cmd = data,
                    4 => self.v_remaining_content = (data as i32) << 8,
                    3 => self.v_remaining_content |= data as i32,
                    2 => self.v_remaining_padding = (data as i32) << 8,
                    1 => self.v_remaining_padding |= data as i32,
                    _ => {}
                }
                self.v_remaining_cmd -= 1;
            }

            if self.v_remaining_cmd <= 0 && self.v_remaining_content > 0 {
                let available = (self.v_buffer.len() - offset) as i32;
                let consume = if available < self.v_remaining_content {
                    available
                } else {
                    self.v_remaining_content
                };
                if consume > 0 {
                    let consume_usize = consume as usize;
                    to_client.extend_from_slice(&self.v_buffer[offset..offset + consume_usize]);
                    offset += consume_usize;
                    self.v_remaining_content -= consume;
                }
            } else if self.v_remaining_cmd <= 0 && self.v_remaining_padding > 0 {
                let available = (self.v_buffer.len() - offset) as i32;
                let consume = if available < self.v_remaining_padding {
                    available
                } else {
                    self.v_remaining_padding
                };
                if consume > 0 {
                    offset += consume as usize;
                    self.v_remaining_padding -= consume;
                }
            }

            if self.v_remaining_cmd <= 0
                && self.v_remaining_content <= 0
                && self.v_remaining_padding <= 0
            {
                if self.v_current_cmd == 0 {
                    // CommandPaddingContinue
                    self.v_remaining_cmd = 5;
                } else {
                    // cmd=1 (PaddingEnd) or cmd=2 (PaddingDirect)
                    self.v_remaining_cmd = -1;
                    self.v_remaining_content = -1;
                    self.v_remaining_padding = -1;
                    if self.v_current_cmd == 2 {
                        self.v_direct_copy_rx = true;
                    } else {
                        self.v_vision_done = true;
                    }
                    // Drain remaining bytes to client
                    if offset < self.v_buffer.len() {
                        to_client.extend_from_slice(&self.v_buffer[offset..]);
                        offset = self.v_buffer.len();
                    }
                    break;
                }
            }
        }

        if offset < self.v_buffer.len() {
            // Drain consumed bytes
            let remaining = self.v_buffer.len() - offset;
            let mut new_vec = Vec::with_capacity(remaining);
            new_vec.extend_from_slice(&self.v_buffer[offset..]);
            self.v_buffer = new_vec;
        } else {
            self.v_buffer.clear();
        }

        to_client
    }
}

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct VlessStream<S> {
    stream: S,
    vision_parser: VisionParser,
    plaintext_buffer: Vec<u8>,
    is_direct_copy: bool,
    shared_read_raw: Option<Arc<AtomicBool>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> VlessStream<S> {
    pub fn new(stream: S, uuid_bytes: [u8; 16], shared_read_raw: Option<Arc<AtomicBool>>) -> Self {
        Self {
            stream,
            vision_parser: VisionParser::new(uuid_bytes),
            plaintext_buffer: Vec::new(),
            is_direct_copy: false,
            shared_read_raw,
        }
    }

    pub fn get_stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn is_direct_copy(&self) -> bool {
        self.is_direct_copy
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            if !this.plaintext_buffer.is_empty() {
                let len = std::cmp::min(buf.remaining(), this.plaintext_buffer.len());
                buf.put_slice(&this.plaintext_buffer[..len]);
                this.plaintext_buffer.drain(..len);
                return Poll::Ready(Ok(()));
            }

            let mut temp_buf = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut temp_buf);
            match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let bytes_read = read_buf.filled().len();
                    if bytes_read == 0 {
                        return Poll::Ready(Ok(()));
                    }

                    let decrypted = this.vision_parser.parse(&temp_buf[..bytes_read]);

                    if this.vision_parser.v_direct_copy_rx && !this.is_direct_copy {
                        this.is_direct_copy = true;
                        if let Some(shared) = &this.shared_read_raw {
                            shared.store(true, Ordering::Relaxed);
                        }
                    }

                    if decrypted.is_empty() {
                        // Data consumed but no plaintext yielded. Loop around and poll inner again!
                        continue;
                    }

                    let len = std::cmp::min(buf.remaining(), decrypted.len());
                    buf.put_slice(&decrypted[..len]);
                    if decrypted.len() > len {
                        this.plaintext_buffer.extend_from_slice(&decrypted[len..]);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}
