use std::cmp::min;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::time::timeout;

use crate::option;
use crate::session::Session;

fn should_sniff_tls(sess: &Session) -> bool {
    if *option::TLS_DOMAIN_SNIFFING {
        if !*option::TLS_DOMAIN_SNIFFING_ALL && sess.destination.port() != 443 {
            return false;
        }
        true
    } else {
        false
    }
}

fn should_sniff_http(sess: &Session) -> bool {
    if *option::HTTP_DOMAIN_SNIFFING {
        if !*option::HTTP_DOMAIN_SNIFFING_ALL && sess.destination.port() != 80 {
            return false;
        }
        true
    } else {
        false
    }
}

pub fn should_sniff(sess: &Session) -> bool {
    !sess.destination.is_domain() && (should_sniff_tls(sess) || should_sniff_http(sess))
}

pub struct SniffingStream<T> {
    inner: T,
    buf: BytesMut,
}

enum SniffResult {
    NotMatch,
    NotEnoughData,
    Domain(String),
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

    fn sniff_http_host(&self, buf: &[u8]) -> SniffResult {
        // Credits https://github.com/eycorsican/leaf/pull/288

        let bytes_str = String::from_utf8_lossy(buf);
        let parts: Vec<&str> = bytes_str.split("\r\n").collect();

        if parts.is_empty() {
            return SniffResult::NotMatch;
        }

        let http_methods = [
            "get", "post", "head", "put", "delete", "options", "connect", "patch", "trace",
        ];
        let method_str = parts[0];

        let matched_method = http_methods
            .into_iter()
            .filter(|item| method_str.to_lowercase().contains(item))
            .count();

        if matched_method == 0 {
            return SniffResult::NotMatch;
        }

        for (idx, &el) in parts.iter().enumerate() {
            if idx == 0 || el.is_empty() {
                continue;
            }
            let inner_parts: Vec<&str> = el.split(":").collect();
            if inner_parts.len() != 2 {
                continue;
            }
            if inner_parts[0].to_lowercase() == "host" {
                return SniffResult::Domain(inner_parts[1].trim().to_string());
            }
        }

        SniffResult::NotMatch
    }

    fn sniff_tls_sni(&self, buf: &[u8]) -> SniffResult {
        // https://tls.ulfheim.net/

        let sbuf = buf;
        if sbuf.len() < 5 {
            return SniffResult::NotEnoughData;
        }
        // handshake record type
        if sbuf[0] != 0x16 {
            return SniffResult::NotMatch;
        }
        // protocol version
        if sbuf[1] != 0x3 {
            return SniffResult::NotMatch;
        }
        let header_len = u16::from_be_bytes(sbuf[3..5].try_into().unwrap()) as usize;
        if sbuf.len() < 5 + header_len {
            return SniffResult::NotEnoughData;
        }
        let sbuf = &sbuf[5..5 + header_len];
        // ?
        if sbuf.len() < 42 {
            return SniffResult::NotEnoughData;
        }
        let session_id_len = sbuf[38] as usize;
        if session_id_len > 32 || sbuf.len() < 39 + session_id_len {
            return SniffResult::NotEnoughData;
        }
        let sbuf = &sbuf[39 + session_id_len..];
        if sbuf.len() < 2 {
            return SniffResult::NotEnoughData;
        }
        let cipher_suite_bytes = u16::from_be_bytes(sbuf[..2].try_into().unwrap()) as usize;
        if sbuf.len() < 2 + cipher_suite_bytes {
            return SniffResult::NotEnoughData;
        }
        let sbuf = &sbuf[2 + cipher_suite_bytes..];
        if sbuf.is_empty() {
            return SniffResult::NotEnoughData;
        }
        let compression_method_bytes = sbuf[0] as usize;
        if sbuf.len() < 1 + compression_method_bytes {
            return SniffResult::NotEnoughData;
        }
        let sbuf = &sbuf[1 + compression_method_bytes..];
        if sbuf.len() < 2 {
            return SniffResult::NotEnoughData;
        }
        let extensions_bytes = u16::from_be_bytes(sbuf[..2].try_into().unwrap()) as usize;
        if sbuf.len() < 2 + extensions_bytes {
            return SniffResult::NotEnoughData;
        }
        let mut sbuf = &sbuf[2..2 + extensions_bytes];
        while !sbuf.is_empty() {
            // extension + extension-specific-len
            if sbuf.len() < 4 {
                return SniffResult::NotEnoughData;
            }
            let extension = u16::from_be_bytes(sbuf[..2].try_into().unwrap());
            let extension_len = u16::from_be_bytes(sbuf[2..4].try_into().unwrap()) as usize;
            sbuf = &sbuf[4..];
            if sbuf.len() < extension_len {
                return SniffResult::NotEnoughData;
            }
            // extension "server name"
            if extension == 0x0 {
                let mut ebuf = &sbuf[..extension_len];
                if ebuf.len() < 2 {
                    return SniffResult::NotEnoughData;
                }
                let entry_len = u16::from_be_bytes(ebuf[..2].try_into().unwrap()) as usize;
                ebuf = &ebuf[2..];
                if ebuf.len() < entry_len {
                    return SniffResult::NotEnoughData;
                }
                // just make sure no oob
                if ebuf.is_empty() {
                    return SniffResult::NotEnoughData;
                }
                let entry_type = ebuf[0];
                // type "DNS hostname"
                if entry_type == 0x0 {
                    ebuf = &ebuf[1..];
                    // just make sure no oob
                    if ebuf.len() < 2 {
                        return SniffResult::NotEnoughData;
                    }
                    let hostname_len = u16::from_be_bytes(ebuf[..2].try_into().unwrap()) as usize;
                    ebuf = &ebuf[2..];
                    if ebuf.len() < hostname_len {
                        return SniffResult::NotEnoughData;
                    }
                    return SniffResult::Domain(
                        String::from_utf8_lossy(&ebuf[..hostname_len]).into(),
                    );
                } else {
                    // TODO
                    // I assume there's only "DNS hostname" type
                    // in the the "server name" extension, should
                    // check if this is true later.
                    //
                    // I also assume there's only one entry in the
                    // "server name" extension list.
                    return SniffResult::NotMatch;
                }
            } else {
                sbuf = &sbuf[extension_len..];
            }
        }
        SniffResult::NotEnoughData
    }

    pub async fn sniff(&mut self, sess: &Session) -> io::Result<Option<String>> {
        let mut buf = vec![0u8; 2 * 1024];
        for _ in 0..2 {
            match timeout(Duration::from_millis(100), self.inner.read(&mut buf)).await {
                Ok(res) => match res {
                    Ok(n) => {
                        self.buf.extend_from_slice(&buf[..n]);
                        let mut tls_not_match = true;
                        let mut http_not_match = true;
                        if should_sniff_tls(sess) {
                            tls_not_match = false;
                            match self.sniff_tls_sni(&buf[..n]) {
                                SniffResult::NotEnoughData => (),
                                SniffResult::NotMatch => tls_not_match = true,
                                SniffResult::Domain(domain) => return Ok(Some(domain)),
                            }
                        }
                        if should_sniff_http(sess) {
                            http_not_match = false;
                            match self.sniff_http_host(&buf[..n]) {
                                SniffResult::NotEnoughData => (),
                                SniffResult::NotMatch => http_not_match = true,
                                SniffResult::Domain(domain) => return Ok(Some(domain)),
                            }
                        }
                        if tls_not_match && http_not_match {
                            return Ok(None);
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
