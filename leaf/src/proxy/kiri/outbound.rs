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
//!
//! The user's *connect* switch (§19.39, [`super::prefs`]): while it is off
//! the outbound is *disabled*: its client is stopped and never started (no
//! session, config or directory fetch, telemetry or pre-warm), the streams
//! and flows through it end at once when it flips, a `standby` group skips
//! it ([`OutboundStreamHandler::disabled`]), and a connection made to it
//! goes to its `fallback=TAG` outbound, or fails at once without one (never
//! silently direct). Switched on again, the client starts lazily as at
//! first.

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
use tokio::sync::watch;

use ::kiri::embed::{ClientSettings, EmbeddedClient};
use kiri_core::{AsyncStream, DatagramSocket, TargetAddr};

use super::prefs::{self, Prefs};
use crate::app::SyncDnsClient;
use crate::config::internal;
use crate::proxy::*;
use crate::session::{Session, SocksAddr};

/// After a failed start, connections fail with the same error for this long
/// instead of starting again each time.
const START_RETRY: Duration = Duration::from_secs(10);

/// The runtime's switches (by address), tag and encoded settings.
type ClientKey = (usize, String, Vec<u8>);

lazy_static::lazy_static! {
    static ref CLIENTS: Mutex<HashMap<ClientKey, Weak<Shared>>> = Mutex::new(HashMap::new());
    /// Client starts per outbound tag in this process.
    static ref STARTS: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
}

/// True while a client of the `kiri` outbound `tag` runs (with any settings).
pub fn client_running(tag: &str) -> bool {
    let m = CLIENTS.lock().unwrap_or_else(|e| e.into_inner());
    m.iter()
        .filter(|(k, _)| k.1 == tag)
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
    /// The user's switches of the runtime.
    prefs: Arc<Prefs>,
    /// Counts the times the user turned kiri off: streams and flows made
    /// before end ([`Cut`]).
    cut: watch::Sender<u64>,
    /// To stop the client from a thread outside the runtime.
    rt: Option<tokio::runtime::Handle>,
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
    pub fn get(tag: &str, raw: &[u8], prefs: Arc<Prefs>) -> anyhow::Result<Arc<Self>> {
        let settings = internal::KiriOutboundSettings::parse_from_bytes(raw)
            .map_err(|e| anyhow::anyhow!("invalid [{}] outbound settings: {}", tag, e))?;
        let key = (Arc::as_ptr(&prefs) as usize, tag.to_string(), raw.to_vec());
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
            prefs: prefs.clone(),
            cut: watch::Sender::new(0),
            rt: tokio::runtime::Handle::try_current().ok(),
        });
        m.insert(key, Arc::downgrade(&s));
        let weak: Weak<dyn prefs::Listener> = Arc::downgrade(&s) as Weak<Self>;
        prefs.listen(weak);
        Ok(s)
    }

    /// The `fallback` outbound's tag, if there is one.
    pub fn fallback_tag(&self) -> Option<&str> {
        Some(self.settings.fallback.as_str()).filter(|t| !t.is_empty())
    }

    /// The user turned kiri off.
    pub fn disabled(&self) -> bool {
        !self.prefs.connect()
    }

    fn disabled_error(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("kiri[{}]: turned off by the user", self.tag),
        )
    }

    /// Turned off: what the client carries ends (now), and the client stops.
    fn turn_off(self: &Arc<Self>) {
        self.cut.send_modify(|n| *n += 1);
        if let Ok(mut st) = self.state.try_lock() {
            self.stop_client(&mut st);
            return;
        }
        // Being started (the starter drops it when done) or briefly busy.
        if let Some(rt) = &self.rt {
            let s = self.clone();
            rt.spawn(async move {
                let mut st = s.state.lock().await;
                if s.disabled() {
                    s.stop_client(&mut st);
                }
            });
        }
    }

    fn stop_client(&self, st: &mut State) {
        st.failed = None;
        if st.client.take().is_some() {
            self.running.store(false, Ordering::SeqCst);
            tracing::info!("kiri[{}]: stopped (turned off by the user)", self.tag);
        }
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
        if self.disabled() {
            return Err(self.disabled_error());
        }
        let mut st = self.state.lock().await;
        if self.disabled() {
            self.stop_client(&mut st);
            return Err(self.disabled_error());
        }
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
            Ok(c) if self.disabled() => {
                // Turned off while it started: it never serves.
                drop(c);
                tracing::info!("{}: started and stopped (turned off by the user)", prefix);
                Err(self.disabled_error())
            }
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
        if self.disabled() {
            return;
        }
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

impl prefs::Listener for Shared {
    fn prefs_changed(self: Arc<Self>) {
        // On again: started lazily by the next stream or flow.
        if self.disabled() {
            self.turn_off();
        }
    }
}

/// Resolves once the user turned kiri off after it was made.
struct Cut {
    fut: Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    done: bool,
    rx: watch::Receiver<u64>,
    at: u64,
}

impl Cut {
    fn new(s: &Shared) -> Self {
        let mut rx = s.cut.subscribe();
        let at = *rx.borrow_and_update();
        let mut wait = rx.clone();
        Self {
            fut: Box::pin(async move {
                // An error: the sender is gone with the outbound; never cut.
                if wait.wait_for(|n| *n != at).await.is_err() {
                    std::future::pending::<()>().await;
                }
            }),
            done: false,
            rx,
            at,
        }
    }

    fn error() -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "kiri turned off by the user",
        )
    }

    /// Without waiting.
    fn fired(&self) -> bool {
        *self.rx.borrow() != self.at
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        if !self.done && self.fut.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.done = true;
        Poll::Ready(Self::error())
    }
}

/// Where a disabled outbound's connections go (`fallback=TAG`).
#[derive(Clone)]
pub struct Fallback {
    pub handler: AnyOutboundHandler,
    pub dns_client: SyncDnsClient,
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
/// locked: every use is through `&mut` (`get_mut`). Ends when the user turns
/// kiri off (one [`Cut`] per direction, each woken by its own task).
struct Stream(Mutex<StreamInner>, #[allow(dead_code)] Use);

struct StreamInner {
    s: Box<dyn AsyncStream>,
    read_cut: Cut,
    write_cut: Cut,
}

impl Stream {
    fn inner(self: Pin<&mut Self>) -> &mut StreamInner {
        self.get_mut()
            .0
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
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
        let me = self.inner();
        if let Poll::Ready(e) = me.read_cut.poll(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut *me.s).poll_read(cx, buf).map_err(mark)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.inner();
        if let Poll::Ready(e) = me.write_cut.poll(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut *me.s).poll_write(cx, buf).map_err(mark)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.inner();
        if let Poll::Ready(e) = me.write_cut.poll(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut *me.s).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner().s).poll_shutdown(cx)
    }
}

pub struct StreamHandler {
    shared: Arc<Shared>,
    fallback: Option<Fallback>,
}

impl StreamHandler {
    pub fn new(shared: Arc<Shared>, fallback: Option<Fallback>) -> Self {
        Self { shared, fallback }
    }
}

#[async_trait]
impl OutboundStreamHandler for StreamHandler {
    fn connect_addr(&self) -> OutboundConnect {
        // kiri makes its own connections (and a fallback's are dialed here).
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        if self.shared.disabled() {
            let Some(fb) = &self.fallback else {
                return Err(self.shared.disabled_error());
            };
            tracing::debug!(
                "kiri[{}]: turned off, to fallback [{}]",
                self.shared.tag,
                fb.handler.tag()
            );
            let stream = connect_stream_outbound(sess, fb.dns_client.clone(), &fb.handler).await?;
            return fb.handler.stream()?.handle(sess, lhs, stream).await;
        }
        let u = Use::new(self.shared.clone());
        let kiri = self.shared.kiri().await?;
        let s = kiri
            .dial_tcp(target(&sess.destination))
            .await
            .map_err(io::Error::other)?;
        let inner = StreamInner {
            s,
            read_cut: Cut::new(&self.shared),
            write_cut: Cut::new(&self.shared),
        };
        Ok(Box::new(Stream(Mutex::new(inner), u)))
    }

    fn prewarm(&self) {
        self.shared.prewarm();
    }

    fn disabled(&self) -> bool {
        self.shared.disabled()
    }
}

pub struct DatagramHandler {
    shared: Arc<Shared>,
    fallback: Option<Fallback>,
}

impl DatagramHandler {
    pub fn new(shared: Arc<Shared>, fallback: Option<Fallback>) -> Self {
        Self { shared, fallback }
    }
}

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
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        if self.shared.disabled() {
            let Some(fb) = &self.fallback else {
                return Err(self.shared.disabled_error());
            };
            let t = connect_datagram_outbound(sess, fb.dns_client.clone(), &fb.handler).await?;
            return fb.handler.datagram()?.handle(sess, t).await;
        }
        let u = Use::new(self.shared.clone());
        let kiri = self.shared.kiri().await?;
        let s = kiri.dial_udp().await.map_err(io::Error::other)?;
        Ok(Box::new(Datagram {
            sock: Arc::from(s),
            shared: self.shared.clone(),
            _use: Arc::new(u),
        }))
    }
}

/// Both halves hold the flow's [`Use`]: it ends when both are gone.
struct Datagram {
    sock: Arc<dyn DatagramSocket>,
    shared: Arc<Shared>,
    _use: Arc<Use>,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let half = |d: &Datagram| DatagramHalf {
            sock: d.sock.clone(),
            cut: Mutex::new(Cut::new(&d.shared)),
            _use: d._use.clone(),
        };
        (Box::new(half(&self)), Box::new(half(&self)))
    }
}

struct DatagramHalf {
    sock: Arc<dyn DatagramSocket>,
    /// Never locked: used through `&mut self` (`get_mut`), for `Sync`.
    cut: Mutex<Cut>,
    _use: Arc<Use>,
}

impl DatagramHalf {
    fn cut(&mut self) -> &mut Cut {
        self.cut.get_mut().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let sock = self.sock.clone();
        let cut = self.cut();
        tokio::select! {
            e = futures::future::poll_fn(|cx| cut.poll(cx)) => Err(e),
            r = sock.recv_from(buf) => {
                let (n, from) = r.map_err(io::Error::other)?;
                Ok((n, socks_addr(from)))
            }
        }
    }
}

#[async_trait]
impl OutboundDatagramSendHalf for DatagramHalf {
    async fn send_to(&mut self, buf: &[u8], dst: &SocksAddr) -> io::Result<usize> {
        if self.cut().fired() {
            return Err(Cut::error());
        }
        self.sock
            .send_to(buf, &target(dst))
            .await
            .map_err(io::Error::other)
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}
