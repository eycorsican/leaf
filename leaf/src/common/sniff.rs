use std::cmp::min;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::time::timeout;

pub struct SniffingStream<T> {
    inner: T,
    buf: BytesMut,
}

impl<T> SniffingStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(inner: T) -> Self {
        SniffingStream {
            inner,
            buf: BytesMut::new(),
        }
    }

    // sniff tcp stream by port
    pub async fn try_sniff(&mut self, port: u16) -> io::Result<Option<String>> {
        if port == 443 {
            return self.try_sniff_tls().await;
        } else if port == 80 {
            return self.try_sniff_http().await;
        }
        Ok(None)
    }

    // sniff http stream
    // 1. \r\n parse http protocol
    // 2. read http method to match
    // 3. extract the host -> session.domain
    async fn try_sniff_http(&mut self) -> io::Result<Option<String>> {
        let mut buf = vec![0u8; 2 * 1024];
        match timeout(Duration::from_millis(100), self.inner.read(&mut buf)).await {
            Ok(res) => match res {
                Ok(n) => {
                    self.buf.extend_from_slice(&buf[..n]);

                    let bytes_str = String::from_utf8_lossy(&buf[..n]);
                    let parts: Vec<&str> = bytes_str.split("\r\n").collect();

                    if parts.len() == 0 {
                        return Ok(None);
                    }

                    // debug!("---> the split http protocol info = {:?}", parts);

                    let http_methods = ["get", "post", "head", "put", "delete", "options", "connect", "patch", "trace"];
                    let method_str = parts[0];

                    let matched_method = http_methods
                        .into_iter()
                        .filter(|item| {
                            method_str.to_lowercase().contains(item)
                        }).count();

                    if matched_method == 0 {
                        return Ok(None);
                    }

                    for (idx, &el) in parts.iter().enumerate() {
                        if idx == 0 || el == "" {
                            continue;
                        }
                        let inner_parts: Vec<&str> = el.split(":").collect();
                        if inner_parts.len() != 2 {
                            continue;
                        }
                        if inner_parts[0].to_lowercase() == "host" {
                            return Ok(Some(inner_parts[1].trim().to_string()))
                        }
                    }

                    Ok(None)
                },
                Err(e) => {
                    Err(e)
                }
            },
            Err(_) => {
                Ok(None)
            }
        }
    }

    async fn try_sniff_tls(&mut self) -> io::Result<Option<String>> {
        let mut buf = vec![0u8; 2 * 1024];
        'outer: for _ in 0..2 {
            match timeout(Duration::from_millis(100), self.inner.read(&mut buf)).await {
                Ok(res) => match res {
                    Ok(n) => {
                        self.buf.extend_from_slice(&buf[..n]);

                        // https://tls.ulfheim.net/

                        let sbuf = &self.buf[..];
                        if sbuf.len() < 5 {
                            continue;
                        }
                        // handshake record type
                        if sbuf[0] != 0x16 {
                            return Ok(None);
                        }
                        // protocol version
                        if sbuf[1] != 0x3 {
                            return Ok(None);
                        }
                        let header_len = BigEndian::read_u16(&sbuf[3..5]) as usize;
                        if sbuf.len() < 5 + header_len {
                            continue;
                        }
                        let sbuf = &sbuf[5..5 + header_len];
                        // ?
                        if sbuf.len() < 42 {
                            continue;
                        }
                        let session_id_len = sbuf[38] as usize;
                        if session_id_len > 32 || sbuf.len() < 39 + session_id_len {
                            continue;
                        }
                        let sbuf = &sbuf[39 + session_id_len..];
                        if sbuf.len() < 2 {
                            continue;
                        }
                        let cipher_suite_bytes = BigEndian::read_u16(&sbuf[..2]) as usize;
                        if sbuf.len() < 2 + cipher_suite_bytes {
                            continue;
                        }
                        let sbuf = &sbuf[2 + cipher_suite_bytes..];
                        if sbuf.is_empty() {
                            continue;
                        }
                        let compression_method_bytes = sbuf[0] as usize;
                        if sbuf.len() < 1 + compression_method_bytes {
                            continue;
                        }
                        let sbuf = &sbuf[1 + compression_method_bytes..];
                        if sbuf.len() < 2 {
                            continue;
                        }
                        let extensions_bytes = BigEndian::read_u16(&sbuf[..2]) as usize;
                        if sbuf.len() < 2 + extensions_bytes {
                            continue;
                        }
                        let mut sbuf = &sbuf[2..2 + extensions_bytes];
                        while !sbuf.is_empty() {
                            // extension + extension-specific-len
                            if sbuf.len() < 4 {
                                continue 'outer;
                            }
                            let extension = BigEndian::read_u16(&sbuf[..2]);
                            let extension_len = BigEndian::read_u16(&sbuf[2..4]) as usize;
                            sbuf = &sbuf[4..];
                            if sbuf.len() < extension_len {
                                continue 'outer;
                            }
                            // extension "server name"
                            if extension == 0x0 {
                                let mut ebuf = &sbuf[..extension_len];
                                if ebuf.len() < 2 {
                                    continue 'outer;
                                }
                                let entry_len = BigEndian::read_u16(&ebuf[..2]) as usize;
                                ebuf = &ebuf[2..];
                                if ebuf.len() < entry_len {
                                    continue 'outer;
                                }
                                // just make sure no oob
                                if ebuf.is_empty() {
                                    continue 'outer;
                                }
                                let entry_type = ebuf[0];
                                // type "DNS hostname"
                                if entry_type == 0x0 {
                                    ebuf = &ebuf[1..];
                                    // just make sure no oob
                                    if ebuf.len() < 2 {
                                        continue 'outer;
                                    }
                                    let hostname_len = BigEndian::read_u16(&ebuf[..2]) as usize;
                                    ebuf = &ebuf[2..];
                                    if ebuf.len() < hostname_len {
                                        continue 'outer;
                                    }
                                    return Ok(Some(
                                        String::from_utf8_lossy(&ebuf[..hostname_len]).into(),
                                    ));
                                } else {
                                    // TODO
                                    // I assume there's only "DNS hostname" type
                                    // in the the "server name" extension, should
                                    // check if this is true later.
                                    //
                                    // I also assume there's only one entry in the
                                    // "server name" extension list.
                                    return Ok(None);
                                }
                            } else {
                                sbuf = &sbuf[extension_len..];
                            }
                        }
                    }
                    Err(e) => {
                        return Err(e);
                    }
                },
                Err(_) => {
                    return Ok(None);
                }
            }
        }
        Ok(None)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for SniffingStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.buf.is_empty() {
            let to_read = min(buf.remaining(), self.buf.len());
            let for_read = self.buf.split_to(to_read);
            buf.put_slice(&for_read[..to_read]);
            Poll::Ready(Ok(()))
        } else {
            AsyncRead::poll_read(Pin::new(&mut self.inner), cx, buf)
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for SniffingStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.inner), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.inner), cx)
    }
}
