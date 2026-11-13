//! The `kiri` outbound: TCP streams and UDP flows through a kiri client
//! (`Kiri::dial_tcp` / `dial_udp`). Domain targets go to kiri as names: the
//! egress resolves them.
//!
//! One client per outbound tag and settings ([`Shared`]), started at the
//! first connection and shared by every handler made from the same settings,
//! across config reloads too: a reload that leaves the outbound unchanged
//! keeps the client (and its sessions); one that changes or removes it stops
//! the old client once nothing holds it (its tasks end on drop). A client
//! stopped by a revocation is replaced at the next reload.
//!
//! `idle-stop=SECONDS` (default 0, never): that long after the last stream
//! or flow through the outbound ended, its client (session, directory
//! refresh, telemetry) is stopped; the next stream or flow starts it again,
//! as the first one does. For a mobile device that would otherwise keep
//! kiri's session alive behind a `standby` group that rarely needs it.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use protobuf::Message;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use ::kiri::embed::{ClientSettings, EmbeddedClient};
use kiri_core::{AsyncStream, DatagramSocket, TargetAddr};

use crate::config::internal;
use crate::proxy::*;
use crate::session::{Session, SocksAddr};

/// After a failed start, connections fail with the same error for this long
/// instead of starting again each time.
const START_RETRY: Duration = Duration::from_secs(10);

/// Tag and encoded settings.
type ClientKey = (String, Vec<u8>);

lazy_static::lazy_static! {
    static ref CLIENTS: Mutex<HashMap<ClientKey, Weak<Shared>>> = Mutex::new(HashMap::new());
    /// Client starts per outbound tag in this process.
    static ref STARTS: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
}

/// True while a client of the `kiri` outbound `tag` runs (with any settings).
pub fn client_running(tag: &str) -> bool {
    let m = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
    m.iter()
        .filter(|(k, _)| k.0 == tag)
        .filter_map(|(_, w)| w.upgrade())
        .any(|s| s.running.load(Ordering::SeqCst))
}

/// How many times a client of the `kiri` outbound `tag` started in this
/// process (the lazy first start, restarts after `idle-stop`, pre-warms).
pub fn client_starts(tag: &str) -> u64 {
    let m = STARTS.lock().unwrap_or_else(|e| e.into_inner());
    m.get(tag).copied().unwrap_or(0)
}

/// The client of one outbound tag and settings.
pub struct Shared {
    tag: String,
    settings: internal::KiriOutboundSettings,
    state: tokio::sync::Mutex<State>,
    running: AtomicBool,
    /// Streams and flows open or being opened ([`Use`]).
    active: AtomicUsize,
    /// When the last of them ended, or the client was (pre-)started.
    idle_since: Mutex<Instant>,
}

#[derive(Default)]
struct State {
    client: Option<Arc<EmbeddedClient>>,
    failed: Option<(Instant, String)>,
    /// Counts starts: an idle watcher stops only the client it was made for.
    generation: u64,
}

/// One stream or flow through the client (or one being opened), for
/// `idle-stop`. Taken before the client is asked for, so that an idle stop
/// never races a new stream.
struct Use(Arc<Shared>);

impl Use {
    fn new(s: Arc<Shared>) -> Self {
        s.active.fetch_add(1, Ordering::SeqCst);
        Self(s)
    }
}

impl Drop for Use {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.touch();
        }
    }
}

impl Shared {
    /// The client of `tag` with these (internal, encoded) settings: the
    /// running one if there is one, else a new one (started lazily).
    pub fn get(tag: &str, raw: &[u8]) -> anyhow::Result<Arc<Self>> {
        let settings = internal::KiriOutboundSettings::parse_from_bytes(raw)
            .map_err(|e| anyhow::anyhow!("invalid [{}] outbound settings: {}", tag, e))?;
        let key = (tag.to_string(), raw.to_vec());
        let mut m = CLIENTS.lock().unwrap();
        m.retain(|_, w| w.strong_count() > 0);
        if let Some(s) = m.get(&key).and_then(Weak::upgrade) {
            // Being started (locked) or running: keep. Stopped: replace.
            let stopped = s
                .state
                .try_lock()
                .map(|st| st.client.as_ref().is_some_and(|c| c.stopped()))
                .unwrap_or(false);
            if !stopped {
                return Ok(s);
            }
        }
        let s = Arc::new(Self {
            tag: tag.to_string(),
            settings,
            state: Default::default(),
            running: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            idle_since: Mutex::new(Instant::now()),
        });
        m.insert(key, Arc::downgrade(&s));
        Ok(s)
    }

    fn client_settings(&self) -> ClientSettings {
        let o = &self.settings;
        let dir = super::state_dir(
            &o.state_dir,
            &format!("client-{}", super::safe_name(&self.tag)),
            &format!("kiri[{}]", self.tag),
        );
        ClientSettings {
            common: super::settings(
                &o.root_pubkeys,
                &o.signed_config,
                dir,
                o.dev.as_ref(),
                o.tls_pin_only,
                o.system_resolver,
            ),
            bootstrap: o.bootstrap.clone(),
            paths: o.paths.max(1) as usize,
            egress_id: (!o.egress_id.is_empty()).then(|| o.egress_id.clone()),
            transports: o
                .dev
                .as_ref()
                .map(|d| d.transports.clone())
                .unwrap_or_default(),
            // Path events (a few per session, no addresses) in leaf's log.
            path_status: true,
            // Default on (§19.37 in kiri); `optimistic-open = false` waits.
            optimistic_open: !o.no_optimistic_open,
        }
    }

    fn touch(&self) {
        *self.idle_since.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.idle_since
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .elapsed()
    }

    /// The running client, started on first use.
    pub async fn client(self: &Arc<Self>) -> io::Result<Arc<EmbeddedClient>> {
        let mut st = self.state.lock().await;
        if let Some(c) = &st.client {
            return Ok(c.clone());
        }
        if let Some((at, e)) = &st.failed {
            if at.elapsed() < START_RETRY {
                return Err(io::Error::other(e.clone()));
            }
        }
        let prefix = format!("kiri[{}]", self.tag);
        match EmbeddedClient::start(self.client_settings(), super::say(prefix.clone())).await {
            Ok(c) => {
                tracing::info!("{}: started", prefix);
                let c = Arc::new(c);
                st.client = Some(c.clone());
                st.failed = None;
                st.generation += 1;
                self.running.store(true, Ordering::SeqCst);
                self.touch();
                *STARTS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(self.tag.clone())
                    .or_default() += 1;
                if self.settings.idle_stop > 0 {
                    self.spawn_idle_stop(st.generation);
                }
                Ok(c)
            }
            Err(e) => {
                let e = format!("{}: not started: {}", prefix, e);
                tracing::warn!("{}", e);
                st.failed = Some((Instant::now(), e.clone()));
                Err(io::Error::other(e))
            }
        }
    }

    /// Stops the client of start `generation` once nothing has gone through
    /// it for `idle-stop` seconds.
    fn spawn_idle_stop(self: &Arc<Self>, generation: u64) {
        let idle = Duration::from_secs(self.settings.idle_stop as u64);
        let tick = (idle / 4).clamp(Duration::from_millis(250), Duration::from_secs(30));
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tick).await;
                let Some(s) = weak.upgrade() else { return };
                if s.active.load(Ordering::SeqCst) > 0 || s.idle_for() < idle {
                    continue;
                }
                let mut st = s.state.lock().await;
                if st.generation != generation || st.client.is_none() {
                    return;
                }
                // Again under the lock: a new stream takes its `Use` first.
                if s.active.load(Ordering::SeqCst) > 0 || s.idle_for() < idle {
                    continue;
                }
                st.client = None;
                s.running.store(false, Ordering::SeqCst);
                tracing::info!(
                    "kiri[{}]: stopped after {}s without use (idle-stop)",
                    s.tag,
                    idle.as_secs()
                );
                return;
            }
        });
    }

    /// Starts the client without a stream (the `standby` group's pre-warm).
    fn prewarm(self: &Arc<Self>) {
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        self.touch();
        let s = self.clone();
        rt.spawn(async move {
            let _ = s.client().await;
        });
    }

    async fn kiri(self: &Arc<Self>) -> io::Result<Arc<kiri_core::Kiri>> {
        let c = self.client().await?;
        c.kiri()
            .map(Clone::clone)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

fn target(a: &SocksAddr) -> TargetAddr {
    match a {
        SocksAddr::Ip(a) => TargetAddr::Ip(*a),
        SocksAddr::Domain(d, p) => TargetAddr::Domain(d.clone(), *p),
    }
}

fn socks_addr(a: TargetAddr) -> SocksAddr {
    match a {
        TargetAddr::Ip(a) => SocksAddr::Ip(a),
        TargetAddr::Domain(d, p) => SocksAddr::Domain(d, p),
    }
}

/// A kiri stream as leaf's (which must be `Sync`). The mutex is never
/// locked: every use is through `&mut` (`get_mut`).
struct Stream(Mutex<Box<dyn AsyncStream>>, #[allow(dead_code)] Use);

impl Stream {
    fn inner(self: Pin<&mut Self>) -> Pin<&mut (dyn AsyncStream + 'static)> {
        let s = self
            .get_mut()
            .0
            .get_mut()
            .unwrap_or_else(|e| e.into_inner());
        Pin::new(&mut **s)
    }
}

/// A stream that failed before the destination answered, with nothing of
/// the client's bytes past the egress (kiri §19.37: they wait at the egress
/// until it connected, and are dropped there when it cannot), is marked
/// [`FlightNotSent`]: a `standby` group then sends the first flight to its
/// next actor. Not a session lost or an OPEN unanswered in time: the egress
/// may have passed bytes on.
fn mark(e: io::Error) -> io::Error {
    use kiri_core::Error as K;
    match kiri_core::api::stream_error(&e) {
        Some(K::Denied | K::Resolve | K::ConnectFailed | K::SessionFull) => FlightNotSent::wrap(e),
        _ => e,
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner().poll_read(cx, buf).map_err(mark)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.inner().poll_write(cx, buf).map_err(mark)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner().poll_shutdown(cx)
    }
}

pub struct StreamHandler(pub Arc<Shared>);

#[async_trait]
impl OutboundStreamHandler for StreamHandler {
    fn connect_addr(&self) -> OutboundConnect {
        // kiri makes its own connections.
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let u = Use::new(self.0.clone());
        let kiri = self.0.kiri().await?;
        let s = kiri
            .dial_tcp(target(&sess.destination))
            .await
            .map_err(io::Error::other)?;
        Ok(Box::new(Stream(Mutex::new(s), u)))
    }

    fn prewarm(&self) {
        self.0.prewarm();
    }
}

pub struct DatagramHandler(pub Arc<Shared>);

#[async_trait]
impl OutboundDatagramHandler for DatagramHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let u = Use::new(self.0.clone());
        let kiri = self.0.kiri().await?;
        let s = kiri.dial_udp().await.map_err(io::Error::other)?;
        Ok(Box::new(Datagram(Arc::from(s), Arc::new(u))))
    }
}

/// Both halves hold the flow's [`Use`]: it ends when both are gone.
struct Datagram(Arc<dyn DatagramSocket>, #[allow(dead_code)] Arc<Use>);

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (
            Box::new(Datagram(self.0.clone(), self.1.clone())),
            Box::new(Datagram(self.0, self.1)),
        )
    }
}

#[async_trait]
impl OutboundDatagramRecvHalf for Datagram {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (n, from) = self.0.recv_from(buf).await.map_err(io::Error::other)?;
        Ok((n, socks_addr(from)))
    }
}

#[async_trait]
impl OutboundDatagramSendHalf for Datagram {
    async fn send_to(&mut self, buf: &[u8], dst: &SocksAddr) -> io::Result<usize> {
        self.0
            .send_to(buf, &target(dst))
            .await
            .map_err(io::Error::other)
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}
