use std::io;
use std::str;
use std::time::Duration;

use async_trait::async_trait;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

use crate::proxy::*;

const BUFFER_SIZE: usize = 8192;
const EOH: [u8; 4] = [13, 10, 13, 10]; // \r\n\r\n

fn bad_request() -> io::Error {
    io::Error::other("bad request")
}

fn not_found() -> io::Error {
    io::Error::other("not found")
}

fn split_slice_once(s: &[u8], sep: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    s.windows(sep.len())
        .position(|w| w == sep)
        .map(|loc| (s[..loc].to_vec(), s[loc + sep.len()..].to_vec()))
}

pub struct Handler {
    path: String,
    request: String,
    response: String,
}

impl Handler {
    pub fn new(path: String, request: String, response: String) -> Self {
        Handler {
            path,
            request,
            response,
        }
    }

    async fn handle_request(&self, stream: &mut AnyStream) -> io::Result<()> {
        // Read HTTP request headers
        let (headers, body_remaining) = self.read_until_eoh(stream).await?;

        let headers_str = match str::from_utf8(&headers) {
            Ok(s) => s,
            Err(_) => return Err(bad_request()),
        };

        // Parse request line to get method and path
        let request_line = headers_str.lines().next().ok_or(bad_request())?;
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(bad_request());
        }

        let method = parts[0];
        let request_path = parts[1];

        // Check if the path matches
        if request_path != self.path {
            return Err(not_found());
        }

        // Determine expected method based on request configuration
        let is_get_request = self.request.is_empty();
        let expected_method = if is_get_request { "GET" } else { "POST" };

        // Check if the method matches
        if method != expected_method {
            return Err(bad_request());
        }

        // For POST requests, read and check the body
        if !is_get_request {
            let mut request_body = String::new();
            if let Some(content_length) = self.extract_content_length(headers_str) {
                if content_length > 0 && content_length <= BUFFER_SIZE {
                    let mut body = Vec::new();
                    body.extend_from_slice(&body_remaining);

                    // Read the remaining body if needed
                    let mut remaining_to_read = content_length.saturating_sub(body.len());
                    while remaining_to_read > 0 {
                        let mut buf = vec![0u8; remaining_to_read.min(BUFFER_SIZE)];
                        let n = stream.read(&mut buf).await?;
                        if n == 0 {
                            break;
                        }
                        body.extend_from_slice(&buf[..n]);
                        remaining_to_read = remaining_to_read.saturating_sub(n);
                    }

                    // Ensure we don't read more than content_length
                    if body.len() > content_length {
                        body.truncate(content_length);
                    }

                    request_body = String::from_utf8_lossy(&body).to_string();
                }
            }

            // Check if the request body matches
            if request_body != self.request {
                return Err(bad_request());
            }
        }

        // Send the configured response
        let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}", 
                               self.response.len(), self.response);
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;

        Ok(())
    }

    async fn delay_and_close(&self) {
        // Random delay between 0 and 10 seconds
        let delay_seconds = rand::thread_rng().gen_range(0.0..10.0);
        sleep(Duration::from_secs_f64(delay_seconds)).await;
    }

    async fn read_until_eoh(&self, stream: &mut AnyStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut data = Vec::new();
        let mut buf = vec![0u8; BUFFER_SIZE];

        loop {
            buf.clear();
            buf.resize(BUFFER_SIZE, 0);

            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }

            data.extend_from_slice(&buf[..n]);

            if let Some((headers, remaining)) = split_slice_once(&data, &EOH) {
                return Ok((headers, remaining));
            }

            if data.len() > 65536 {
                // Prevent excessive memory usage
                return Err(bad_request());
            }
        }
    }

    fn extract_content_length(&self, headers: &str) -> Option<usize> {
        for line in headers.lines() {
            if line.to_lowercase().starts_with("content-length:") {
                if let Some(len_str) = line.split(':').nth(1) {
                    if let Ok(len) = len_str.trim().parse::<usize>() {
                        return Some(len);
                    }
                }
            }
        }
        None
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        _sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream session: {:?}", _sess);
        // Handle the HTTP request and send response
        if let Err(_e) = self.handle_request(&mut stream).await {
            self.delay_and_close().await;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection closed after delay",
            ));
        }

        // Close the connection after sending response
        let _ = stream.shutdown().await;
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "connection closed",
        ))
    }
}
