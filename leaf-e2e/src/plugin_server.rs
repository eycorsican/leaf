//! An https server that hands out plugin files, and misbehaves on request.
//!
//! This is what the `fetch/` cases download from. Each path has a [`Route`]
//! saying what to send and how: a length that is announced, omitted or wrong,
//! an error status, a redirect, or a body that stops at a [`Gate`] until the
//! case opens it. Gates are how the cases get the timing they need -- a
//! download that is provably in flight, a server that provably never answers
//! -- without sleeping and hoping.
//!
//! The certificate is issued by a CA generated per server, and the client side
//! trusts that CA explicitly through `FetchOptions::extra_roots`. Nothing else
//! does, which is what lets a case check that an untrusted server is refused.
//!
//! HTTP is written out by hand rather than served by a library, because
//! several routes exist to say things a correct server never would.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Holds a body back after `after` bytes until [`Gate::open`] is called. A
/// gate that is never opened is a server that stalls.
#[derive(Clone)]
pub struct Gate {
    after: usize,
    open: Arc<watch::Sender<bool>>,
}

impl Gate {
    pub fn after(bytes: usize) -> Self {
        Self {
            after: bytes,
            open: Arc::new(watch::channel(false).0),
        }
    }

    pub fn open(&self) {
        self.open.send_replace(true);
    }

    async fn wait(&self) {
        let mut open = self.open.subscribe();
        let _ = open.wait_for(|open| *open).await;
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Length {
    /// `Content-Length` is the size of the body.
    Exact,
    /// `Transfer-Encoding: chunked`, so the client learns the size only at the
    /// end.
    Chunked,
    /// `Content-Length` says this, whatever the body is.
    Claim(u64),
}

#[derive(Clone)]
pub struct Route {
    status: u16,
    body: Arc<Vec<u8>>,
    length: Length,
    location: Option<String>,
    gate: Option<Gate>,
}

impl Route {
    pub fn ok(body: impl Into<Arc<Vec<u8>>>) -> Self {
        Self {
            status: 200,
            body: body.into(),
            length: Length::Exact,
            location: None,
            gate: None,
        }
    }

    pub fn status(status: u16) -> Self {
        Self {
            status,
            body: Arc::new(Vec::new()),
            length: Length::Exact,
            location: None,
            gate: None,
        }
    }

    pub fn redirect(location: impl Into<String>) -> Self {
        Self {
            location: Some(location.into()),
            ..Self::status(302)
        }
    }

    pub fn length(mut self, length: Length) -> Self {
        self.length = length;
        self
    }

    pub fn gate(mut self, gate: Gate) -> Self {
        self.gate = Some(gate);
        self
    }
}

#[derive(Default)]
struct State {
    routes: Mutex<HashMap<String, Route>>,
    requests: Mutex<HashMap<String, usize>>,
    /// Requests whose response is still being written.
    active: AtomicUsize,
    max_active: AtomicUsize,
}

/// Counts a request as active for as long as it is alive.
struct Active(Arc<State>);

impl Active {
    fn enter(state: &Arc<State>) -> Self {
        let now = state.active.fetch_add(1, Ordering::SeqCst) + 1;
        state.max_active.fetch_max(now, Ordering::SeqCst);
        Self(state.clone())
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct PluginServer {
    addr: SocketAddr,
    ca: CertificateDer<'static>,
    state: Arc<State>,
    task: JoinHandle<()>,
}

impl PluginServer {
    pub async fn start() -> Result<Self> {
        let (ca, chain, key) = issue_certificate()?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("choosing TLS versions")?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .context("installing the server certificate")?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(State::default());
        let serving = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, state) = (acceptor.clone(), serving.clone());
                tokio::spawn(async move {
                    // A client that gives up, or refuses the certificate, is
                    // one of the things under test; it is not a server error.
                    if let Ok(stream) = acceptor.accept(tcp).await {
                        let _ = serve(stream, state).await;
                    }
                });
            }
        });
        Ok(Self {
            addr,
            ca,
            state,
            task,
        })
    }

    /// The CA to hand the client as its extra trusted root.
    pub fn ca(&self) -> CertificateDer<'static> {
        self.ca.clone()
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://{}{}", self.addr, path)
    }

    pub fn route(&self, path: &str, route: Route) {
        self.state
            .routes
            .lock()
            .unwrap()
            .insert(path.to_string(), route);
    }

    pub fn requests(&self, path: &str) -> usize {
        self.state
            .requests
            .lock()
            .unwrap()
            .get(path)
            .copied()
            .unwrap_or(0)
    }

    pub fn total_requests(&self) -> usize {
        self.state.requests.lock().unwrap().values().sum()
    }

    pub fn active(&self) -> usize {
        self.state.active.load(Ordering::SeqCst)
    }

    pub fn max_active(&self) -> usize {
        self.state.max_active.load(Ordering::SeqCst)
    }
}

impl Drop for PluginServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve<S>(mut stream: S, state: Arc<State>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let path = read_request_path(&mut stream).await?;
    *state
        .requests
        .lock()
        .unwrap()
        .entry(path.clone())
        .or_default() += 1;
    let _active = Active::enter(&state);
    let route = state.routes.lock().unwrap().get(&path).cloned();
    let Some(route) = route else {
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(stream.shutdown().await?);
    };

    if route.status != 200 {
        let mut head = format!("HTTP/1.1 {} Scripted\r\n", route.status);
        if let Some(location) = &route.location {
            head.push_str(&format!("Location: {}\r\n", location));
        }
        head.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
        stream.write_all(head.as_bytes()).await?;
        return Ok(stream.shutdown().await?);
    }

    let mut head = String::from("HTTP/1.1 200 OK\r\nConnection: close\r\n");
    match route.length {
        Length::Exact => head.push_str(&format!("Content-Length: {}\r\n", route.body.len())),
        Length::Claim(claimed) => head.push_str(&format!("Content-Length: {}\r\n", claimed)),
        Length::Chunked => head.push_str("Transfer-Encoding: chunked\r\n"),
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await?;

    let chunked = matches!(route.length, Length::Chunked);
    let mut sent = 0;
    for chunk in route.body.chunks(16 * 1024) {
        if let Some(gate) = &route.gate {
            // Split the chunk that crosses the gate, so exactly `after` bytes
            // are out before it holds.
            if sent <= gate.after && gate.after < sent + chunk.len() {
                let (before, after) = chunk.split_at(gate.after - sent);
                write_body(&mut stream, before, chunked).await?;
                stream.flush().await?;
                gate.wait().await;
                write_body(&mut stream, after, chunked).await?;
                sent += chunk.len();
                continue;
            }
        }
        write_body(&mut stream, chunk, chunked).await?;
        sent += chunk.len();
    }
    if let Some(gate) = &route.gate {
        if gate.after >= route.body.len() {
            stream.flush().await?;
            gate.wait().await;
        }
    }
    if chunked {
        stream.write_all(b"0\r\n\r\n").await?;
    }
    stream.flush().await?;
    Ok(stream.shutdown().await?)
}

async fn write_body<S>(stream: &mut S, bytes: &[u8], chunked: bool) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if bytes.is_empty() {
        return Ok(());
    }
    if chunked {
        stream
            .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
            .await?;
        stream.write_all(bytes).await?;
        stream.write_all(b"\r\n").await?;
    } else {
        stream.write_all(bytes).await?;
    }
    Ok(())
}

/// Reads a request head and returns its path. Only GET is spoken here.
async fn read_request_path<S>(stream: &mut S) -> Result<String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err(anyhow!("request head is too long"));
        }
        if stream.read(&mut byte).await? == 0 {
            return Err(anyhow!("connection closed inside the request head"));
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    let line = head.lines().next().unwrap_or_default();
    let mut parts = line.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some("GET"), Some(path)) => Ok(path.to_string()),
        _ => Err(anyhow!("not a GET: [{}]", line)),
    }
}

/// A CA, and a certificate from it for the loopback address and `localhost`.
fn issue_certificate() -> Result<(
    CertificateDer<'static>,
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
)> {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "leaf-e2e plugin server CA");
    let ca_key = rcgen::KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;

    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "leaf-e2e plugin server");
    let key = rcgen::KeyPair::generate()?;
    let cert = params.signed_by(&key, &ca, &ca_key)?;

    Ok((
        ca.der().clone(),
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    ))
}
