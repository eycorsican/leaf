use reality::{RealityConnectionState, X25519RealityGroup};
use reality_rustls::crypto::ring::default_provider;
use reality_rustls::pki_types::ServerName;
use reality_rustls::{ClientConfig, ClientConnection};
use std::io::{ErrorKind, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
struct DebugVerifier(Arc<dyn reality_rustls::client::danger::ServerCertVerifier>);

impl reality_rustls::client::danger::ServerCertVerifier for DebugVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &reality_rustls::pki_types::CertificateDer<'_>,
        intermediates: &[reality_rustls::pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: reality_rustls::pki_types::UnixTime,
    ) -> Result<reality_rustls::client::danger::ServerCertVerified, reality_rustls::Error> {
        self.0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &reality_rustls::pki_types::CertificateDer<'_>,
        dss: &reality_rustls::DigitallySignedStruct,
    ) -> Result<reality_rustls::client::danger::HandshakeSignatureValid, reality_rustls::Error>
    {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &reality_rustls::pki_types::CertificateDer<'_>,
        dss: &reality_rustls::DigitallySignedStruct,
    ) -> Result<reality_rustls::client::danger::HandshakeSignatureValid, reality_rustls::Error>
    {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<reality_rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[reality_rustls::DistinguishedName]> {
        self.0.root_hint_subjects()
    }
}

pub fn create_reality_provider() -> Arc<reality_rustls::crypto::CryptoProvider> {
    let mut provider = default_provider();
    let mut new_kx_groups = vec![];
    for group in provider.kx_groups.iter() {
        if group.name() == reality_rustls::NamedGroup::X25519 {
            new_kx_groups
                .push(&X25519RealityGroup as &'static dyn reality_rustls::crypto::SupportedKxGroup);
        } else {
            new_kx_groups.push(*group);
        }
    }
    provider.kx_groups = new_kx_groups;
    Arc::new(provider)
}

pub fn build_rustls_config(
    provider_arc: Arc<reality_rustls::crypto::CryptoProvider>,
    fallback_verifier: Arc<dyn reality_rustls::client::danger::ServerCertVerifier>,
    server_public_key: [u8; 32],
    short_id: [u8; 8],
) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    let reality_state = Arc::new(RealityConnectionState::new(
        server_public_key,
        short_id,
        Arc::new(DebugVerifier(fallback_verifier)),
    ));

    let mut config = ClientConfig::builder_with_provider(provider_arc)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(reality_state.clone())
        .with_no_client_auth();

    config.reality_callback = Some(reality_state);
    config.alpn_protocols = vec![b"h2".to_vec().into(), b"http/1.1".to_vec().into()];

    Ok(Arc::new(config))
}

pub struct RealityStream<S> {
    conn: ClientConnection,
    stream: S,
    read_raw: bool,
    shared_read_raw: Option<Arc<std::sync::atomic::AtomicBool>>,
}

struct TlsBridge<'a, 'b, S> {
    stream: Pin<&'a mut S>,
    cx: &'a mut Context<'b>,
    safe_byte_read: bool,
}

impl<'a, 'b, S: AsyncRead> Read for TlsBridge<'a, 'b, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let read_len = if self.safe_byte_read { 1 } else { buf.len() };
        let mut read_buf = ReadBuf::new(&mut buf[..read_len]);
        match self.stream.as_mut().poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                Ok(n)
            }
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(std::io::Error::new(ErrorKind::WouldBlock, "WouldBlock")),
        }
    }
}

impl<'a, 'b, S: AsyncWrite> Write for TlsBridge<'a, 'b, S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.stream.as_mut().poll_write(self.cx, buf) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(std::io::Error::new(ErrorKind::WouldBlock, "WouldBlock")),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self.stream.as_mut().poll_flush(self.cx) {
            Poll::Ready(Ok(())) => Ok(()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(std::io::Error::new(ErrorKind::WouldBlock, "WouldBlock")),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> RealityStream<S> {
    pub fn new(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        stream: S,
        shared_read_raw: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Result<Self, reality_rustls::Error> {
        let conn = ClientConnection::new(config, name)?;
        Ok(Self {
            conn,
            stream,
            read_raw: false,
            shared_read_raw,
        })
    }

    pub fn set_read_raw(&mut self, raw: bool) {
        self.read_raw = raw;
    }

    pub fn get_conn_mut(&mut self) -> &mut ClientConnection {
        &mut self.conn
    }

    pub fn get_stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub async fn perform_handshake(&mut self) -> std::io::Result<()> {
        std::future::poll_fn(|cx| {
            let mut progress = false;
            while self.conn.is_handshaking() {
                while self.conn.wants_write() {
                    let mut bridge = TlsBridge {
                        stream: Pin::new(&mut self.stream),
                        cx,
                        safe_byte_read: false,
                    };
                    match self.conn.write_tls(&mut bridge) {
                        Ok(n) if n > 0 => {
                            progress = true;
                        }
                        Ok(_) => break,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }

                if self.conn.wants_read() {
                    let mut bridge = TlsBridge {
                        stream: Pin::new(&mut self.stream),
                        cx,
                        safe_byte_read: false,
                    };
                    match self.conn.read_tls(&mut bridge) {
                        Ok(0) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "Connection closed during Reality handshake",
                            )));
                        }
                        Ok(_) => {
                            if let Err(e) = self.conn.process_new_packets() {
                                return Poll::Ready(Err(std::io::Error::new(
                                    ErrorKind::InvalidData,
                                    format!("TLS Error: {}", e),
                                )));
                            }
                            progress = true;
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }

                if !progress {
                    return Poll::Pending;
                }
                progress = false;
            }
            Poll::Ready(Ok(()))
        })
        .await
    }

    fn pump_read(&mut self, cx: &mut Context<'_>) -> std::io::Result<usize> {
        if self.conn.wants_read() {
            let mut bridge = TlsBridge {
                stream: Pin::new(&mut self.stream),
                cx,
                safe_byte_read: true,
            };
            match self.conn.read_tls(&mut bridge) {
                Ok(0) => return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "EOF")),
                Ok(n) => {
                    self.conn.process_new_packets().map_err(|e| {
                        std::io::Error::new(ErrorKind::InvalidData, format!("TLS Error: {}", e))
                    })?;
                    return Ok(n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(0),
                Err(e) => return Err(e),
            }
        }
        Ok(0)
    }

    fn pump_write(&mut self, cx: &mut Context<'_>) -> std::io::Result<bool> {
        while self.conn.wants_write() {
            let mut bridge = TlsBridge {
                stream: Pin::new(&mut self.stream),
                cx,
                safe_byte_read: false,
            };
            match self.conn.write_tls(&mut bridge) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RealityStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        let mut read_raw = this.read_raw;
        if !read_raw {
            if let Some(shared) = &this.shared_read_raw {
                read_raw = shared.load(std::sync::atomic::Ordering::Relaxed);
                if read_raw {
                    this.read_raw = true; // Cache it
                }
            }
        }

        if read_raw {
            return Pin::new(&mut this.stream).poll_read(cx, buf);
        }

        // Ensure any pending writes are flushed to network
        let _ = this.pump_write(cx)?;

        loop {
            let slice = buf.initialize_unfilled();
            match this.conn.reader().read(slice) {
                Ok(n) if n > 0 => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                _ => {
                    if this.conn.wants_read() {
                        let n = this.pump_read(cx)?;
                        if n == 0 {
                            return Poll::Pending; // Awaits socket read wake
                        }
                    } else if this.conn.wants_write() {
                        let _ = this.pump_write(cx)?;
                        // wait for writes to clear, though want_read was false so it might still be pending
                        return Poll::Pending;
                    } else {
                        // Reached EOF and cleanly terminated TLS?
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RealityStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let n = this.conn.writer().write(buf)?;
        let _ = this.pump_write(cx)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.conn.writer().flush()?;
        if !this.pump_write(cx)? {
            return Poll::Pending;
        }
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.conn.send_close_notify();
        let _ = this.pump_write(cx)?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}
