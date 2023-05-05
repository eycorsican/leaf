use std::io;
use std::str;
use std::cmp;
use std::convert::TryFrom;
use std::{net::IpAddr, pin::Pin, task::Poll, task::Context};

use anyhow::Result;
use tokio::io::{AsyncWriteExt, AsyncReadExt, ReadBuf};
use bytes::BytesMut;
use async_trait::async_trait;
use ::http::{Method, Uri};

use crate::{
    proxy::*,
    session::{Session, SocksAddr},
};

const BUFFER_SIZE: usize = 1024;
const EOL: [u8; 2] = [13, 10];
const EOH: [u8; 4] = [13, 10, 13, 10];

/// Parse destination
impl TryFrom<&Uri> for SocksAddr {
    type Error = io::Error;
    fn try_from(uri: &Uri) -> Result<Self, Self::Error> {
        let (host, port) = (
            uri.host().ok_or(io::Error::new(io::ErrorKind::InvalidInput, format!("malformed uri: {}", uri)))?,
            uri.port_u16().or_else(|| {
                match uri.scheme_str() {
                    Some("ssh") => Some(22),
                    Some("smtp") => Some(25),
                    Some("http") => Some(80),
                    Some("https") => Some(443),
                    _ => None,
                }
            }).ok_or(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown scheme '{}' must provide a port", uri.scheme_str().unwrap_or(""))))?
        );
        let addr = if let Ok(host) = host.parse::<IpAddr>() {
            SocksAddr::from((host, port))
        } else {
            SocksAddr::try_from((host, port))?
        };
        Ok(addr)
    }
}

struct HttpStream {
    cache: Vec<u8>,
    destination: Option<SocksAddr>,
    origin: AnyStream,
}

impl HttpStream {
    async fn sniff(&mut self) -> io::Result<()> {
        let (head, mut rest) = self.drain(&EOH).await?;
        let (request_line, mut header) = self.split_slice_once(&head, &EOL)
            .ok_or(io::Error::new(io::ErrorKind::InvalidInput, "malformed request"))?;
        let (method, uri, version) = self.parse_request_line(&request_line)?;

        self.destination = Some(SocksAddr::try_from(&uri)?);

        // different target formats for different strategies, see: https://www.rfc-editor.org/rfc/rfc7230#section-5.3
        // authority format (for https request)
        if method == Method::CONNECT {
            self.origin.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
            return Ok(());
        }
        // absolute uri format (for http request)
        else if uri.scheme().is_some() {
            let path_and_query = uri.path_and_query().map(|paq| paq.as_str()).unwrap_or("/");
            let new_request_line = format!("{} {} {}", method, path_and_query, version);
            self.cache.clear();
            self.cache.append(&mut new_request_line.into_bytes());
            self.cache.append(&mut header);
            self.cache.append(&mut rest);
            return Ok(());
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported request target form"));
        }
    }

    async fn drain(&mut self, stop_sign: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut data = Vec::new();
        let mut buf = BytesMut::with_capacity(BUFFER_SIZE);
        loop {
            buf.clear();
            let n = self.origin.read_buf(&mut buf).await?;
            data.extend_from_slice(&buf[..n]);
            match self.split_slice_once(&data, stop_sign) {
                Some(v) => return Ok(v),
                None => continue,
            }
        }
    }

    fn split_slice_once(&self, s: &[u8], sep: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        s.windows(sep.len()).position(|w| w == sep).map(|loc| (s[..loc].to_vec(), s[loc..].to_vec()))
    }

    fn parse_request_line(&self, request_line: &[u8]) -> io::Result<(Method, Uri, String)> {
        let mut tokens = str::from_utf8(request_line).unwrap_or("").splitn(3, ' ');
        let method = match Method::try_from(tokens.next().unwrap_or("")) {
            Ok(v) => v,
            Err(_e) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid method")),
        };
        let uri = match Uri::try_from(tokens.next().unwrap_or("")) {
            Ok(v) => v,
            Err(_e) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid uri")),
        };
        let version = tokens.next().unwrap_or("HTTP/1.1");
        Ok((method, uri, version.to_string()))
    }
}

impl AsyncRead for HttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.cache.is_empty() {
            let n = cmp::min(buf.capacity(), self.cache.len());
            let cached_data = self.cache.drain(..n);
            buf.put_slice(cached_data.as_slice());
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.origin).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.origin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.origin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.origin).poll_shutdown(cx)
    }
}

pub struct Handler;

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        let mut http_stream = HttpStream {
            cache: Vec::new(),
            destination: None,
            origin: stream,
        };
        http_stream.sniff().await?;

        sess.destination = http_stream.destination.clone().ok_or(io::Error::new(io::ErrorKind::InvalidInput, "unspecified"))?;

        Ok(InboundTransport::Stream(Box::new(http_stream), sess))
    }
}
