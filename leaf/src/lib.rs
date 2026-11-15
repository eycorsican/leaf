use std::collections::HashMap;
use std::io;
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::anyhow;
use lazy_static::lazy_static;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};
use tracing::{info, trace, warn};

#[cfg(feature = "auto-reload")]
use notify::{
    event, Error as NotifyError, RecommendedWatcher, RecursiveMode, Result as NotifyResult, Watcher,
};

use app::{
    dispatcher::Dispatcher, dns::DnsClient, inbound::manager::InboundManager,
    nat_manager::NatManager, outbound::manager::OutboundManager, router::Router,
};

use crate::app::{stat_manager::StatManager, SyncStatManager};

#[cfg(feature = "api")]
use crate::app::api::api_server::ApiServer;

#[cfg(all(
    any(feature = "boring-tls", feature = "boring-aead"),
    any(feature = "openssl-tls", feature = "openssl-aead")
))]
compile_error!(
    "leaf: the BoringSSL features (`boring-tls`, `boring-aead`, `default-boring`) and the OpenSSL \
     features (`openssl-tls`, `openssl-aead`, `default-openssl`) cannot be combined: both libraries \
     export the same unprefixed symbols"
);
#[cfg(all(feature = "boring-tls", feature = "rustls-tls"))]
compile_error!(
    "leaf: choose one TLS backend, `boring-tls` (`default-boring`) or `rustls-tls` \
     (`default-aws-lc`, `default-ring`): build with `--no-default-features --features default-boring`"
);
#[cfg(all(
    feature = "kiri-host",
    any(feature = "openssl-tls", feature = "openssl-aead")
))]
compile_error!(
    "leaf: `kiri` links BoringSSL, which clashes with OpenSSL (`openssl-tls`, `openssl-aead`, \
     `default-openssl`): use `default-boring` (or the rustls default) with `kiri`"
);

pub mod app;
pub mod common;
pub mod config;
pub mod option;
pub mod proxy;
pub mod session;
pub mod util;

#[cfg(any(target_os = "ios", target_os = "macos", target_os = "android"))]
pub mod mobile;

#[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
mod sys;

#[cfg(all(feature = "inbound-tun", target_os = "windows"))]
mod winsys;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] anyhow::Error),
    #[error("no associated config file")]
    NoConfigFile,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[cfg(feature = "auto-reload")]
    #[error(transparent)]
    Watcher(#[from] NotifyError),
    #[error(transparent)]
    AsyncChannelSend(
        #[from] tokio::sync::mpsc::error::SendError<std::sync::mpsc::SyncSender<Result<(), Error>>>,
    ),
    #[error(transparent)]
    SyncChannelRecv(#[from] std::sync::mpsc::RecvError),
    #[error("runtime manager error")]
    RuntimeManager,
}

pub type Runner = futures::future::BoxFuture<'static, ()>;

pub struct RuntimeManager {
    #[cfg(feature = "auto-reload")]
    rt_id: RuntimeId,
    config_path: Option<String>,
    #[cfg(feature = "auto-reload")]
    auto_reload: bool,
    reload_tx: mpsc::Sender<std::sync::mpsc::SyncSender<Result<(), Error>>>,
    shutdown_tx: mpsc::Sender<()>,
    router: Arc<RwLock<Router>>,
    dns_client: Arc<RwLock<DnsClient>>,
    outbound_manager: Arc<RwLock<OutboundManager>>,
    stat_manager: SyncStatManager,
    #[cfg(feature = "auto-reload")]
    watcher: Mutex<Option<RecommendedWatcher>>,
    #[cfg(feature = "kiri-bridge")]
    kiri_bridge: Arc<app::kiri_bridge::BridgeService>,
    #[cfg(feature = "outbound-standby")]
    standby_groups: app::outbound::manager::StandbyGroups,
}

impl RuntimeManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        #[cfg(feature = "auto-reload")] rt_id: RuntimeId,
        config_path: Option<String>,
        #[cfg(feature = "auto-reload")] auto_reload: bool,
        reload_tx: mpsc::Sender<std::sync::mpsc::SyncSender<Result<(), Error>>>,
        shutdown_tx: mpsc::Sender<()>,
        router: Arc<RwLock<Router>>,
        dns_client: Arc<RwLock<DnsClient>>,
        outbound_manager: Arc<RwLock<OutboundManager>>,
        stat_manager: SyncStatManager,
        #[cfg(feature = "kiri-bridge")] kiri_bridge: Arc<app::kiri_bridge::BridgeService>,
        #[cfg(feature = "outbound-standby")] standby_groups: app::outbound::manager::StandbyGroups,
    ) -> Arc<Self> {
        Arc::new(Self {
            #[cfg(feature = "auto-reload")]
            rt_id,
            config_path,
            #[cfg(feature = "auto-reload")]
            auto_reload,
            reload_tx,
            shutdown_tx,
            router,
            dns_client,
            outbound_manager,
            stat_manager,
            #[cfg(feature = "auto-reload")]
            watcher: Mutex::new(None),
            #[cfg(feature = "kiri-bridge")]
            kiri_bridge,
            #[cfg(feature = "outbound-standby")]
            standby_groups,
        })
    }

    /// The device's network changed to `network_id` (an identity such as
    /// the Wi-Fi SSID or the carrier, kept only as its SHA-256; empty:
    /// unknown).
    /// Every `standby` group switches to its state for that network (fresh
    /// for a new or unknown one).
    #[allow(unused_variables)]
    pub fn network_changed(&self, network_id: &str) {
        #[cfg(feature = "outbound-standby")]
        for g in self.standby_groups.lock().unwrap().iter() {
            g.switch_network(network_id);
        }
    }

    /// Pauses (stops) or resumes the kiri bridge the config asks for
    /// (`[Kiri] bridge = true`), e.g. when the device leaves Wi-Fi or power.
    #[cfg(feature = "kiri-bridge")]
    pub fn set_kiri_bridge_paused(&self, paused: bool) {
        self.kiri_bridge.set_paused(paused);
    }

    /// True while a kiri bridge runs.
    #[cfg(feature = "kiri-bridge")]
    pub fn kiri_bridge_running(&self) -> bool {
        self.kiri_bridge.is_running()
    }

    /// Whether the kiri bridge is wanted, and why not.
    #[cfg(feature = "kiri-bridge")]
    pub fn kiri_bridge_state(&self) -> proxy::kiri::prefs::BridgeState {
        self.kiri_bridge.state()
    }

    /// What the kiri bridge has carried (counts only); `None` while none serves.
    #[cfg(feature = "kiri-bridge")]
    pub fn kiri_bridge_stats(&self) -> Option<kiri_core::bridge::BridgeStats> {
        self.kiri_bridge.stats()
    }

    pub fn stat_manager(&self) -> SyncStatManager {
        self.stat_manager.clone()
    }

    pub async fn health_check_outbound(
        &self,
        tag: &str,
        to: Option<Duration>,
    ) -> Result<
        (
            Result<Duration, anyhow::Error>,
            Result<Duration, anyhow::Error>,
        ),
        Error,
    > {
        let to = to.unwrap_or(Duration::from_secs(4));
        let dns_client = self.dns_client.clone();
        let handler = {
            let om = self.outbound_manager.read().await;
            om.get(tag)
                .ok_or_else(|| Error::Config(anyhow!("outbound {} not found", tag)))?
        };

        async fn test_tcp(
            dns_client: Arc<RwLock<DnsClient>>,
            handler: crate::proxy::AnyOutboundHandler,
        ) -> anyhow::Result<Duration> {
            crate::app::healthcheck::tcp(dns_client, handler).await
        }

        async fn test_udp(
            dns_client: Arc<RwLock<DnsClient>>,
            handler: crate::proxy::AnyOutboundHandler,
        ) -> anyhow::Result<Duration> {
            crate::app::healthcheck::udp(dns_client, handler).await
        }

        let (tcp_res, udp_res) = futures::future::join(
            timeout(to, test_tcp(dns_client.clone(), handler.clone())),
            timeout(to, test_udp(dns_client, handler)),
        )
        .await;

        let tcp_res = match tcp_res.map_err(|e| e.into()) {
            Err(e) => Err(e),
            Ok(res) => match res {
                Err(e) => Err(e),
                Ok(duration) => Ok(duration),
            },
        };
        let udp_res = match udp_res.map_err(|e| e.into()) {
            Err(e) => Err(e),
            Ok(res) => match res {
                Err(e) => Err(e),
                Ok(duration) => Ok(duration),
            },
        };
        Ok((tcp_res, udp_res))
    }

    #[cfg(feature = "outbound-select")]
    pub async fn set_outbound_selected(&self, outbound: &str, select: &str) -> Result<(), Error> {
        if let Some(selector) = self.outbound_manager.read().await.get_selector(outbound) {
            selector
                .write()
                .await
                .set_selected(select)
                .map_err(Error::Config)
        } else {
            Err(Error::Config(anyhow!("selector {} not found", outbound)))
        }
    }

    #[cfg(feature = "outbound-select")]
    pub async fn get_outbound_selected(&self, outbound: &str) -> Result<String, Error> {
        if let Some(selector) = self.outbound_manager.read().await.get_selector(outbound) {
            return Ok(selector.read().await.get_selected_tag());
        }
        Err(Error::Config(anyhow!("selector {} not found", outbound)))
    }

    #[cfg(feature = "outbound-select")]
    pub async fn get_outbound_selects(&self, outbound: &str) -> Result<Vec<String>, Error> {
        if let Some(selector) = self.outbound_manager.read().await.get_selector(outbound) {
            return Ok(selector.read().await.get_available_tags());
        }
        Err(Error::Config(anyhow!("selector {} not found", outbound)))
    }

    /// Get the last peer active time (in seconds) for an outbound
    pub async fn get_outbound_last_peer_active(
        &self,
        outbound: &str,
    ) -> Result<Option<u32>, Error> {
        Ok(self
            .stat_manager
            .read()
            .await
            .get_last_peer_active(outbound))
    }

    // This function could block by an in-progress connection dialing.
    //
    // TODO Reload FakeDns. And perhaps the inbounds as long as the listening
    // addresses haven't changed.
    pub async fn reload(&self) -> Result<(), Error> {
        let config_path = if let Some(p) = self.config_path.as_ref() {
            p
        } else {
            return Err(Error::NoConfigFile);
        };
        info!("reloading from config file: {}", config_path);
        let mut config = config::from_file(config_path).map_err(Error::Config)?;
        app::logger::setup_logger(&config.log)?;
        config::compat::log(&config.notes);
        self.router.write().await.reload(&mut config.router)?;
        self.dns_client.write().await.reload(&config.dns)?;
        self.outbound_manager
            .write()
            .await
            .reload(&config.outbounds, self.dns_client.clone())
            .await?;
        #[cfg(feature = "kiri-bridge")]
        self.kiri_bridge.apply(config.kiri.as_ref());
        info!("reloaded from config file: {}", config_path);
        Ok(())
    }

    pub fn blocking_reload(&self) -> Result<(), Error> {
        let tx = self.reload_tx.clone();
        let (res_tx, res_rx) = sync_channel(0);
        if let Err(e) = tx.blocking_send(res_tx) {
            return Err(Error::AsyncChannelSend(e));
        }
        match res_rx.recv() {
            Ok(res) => res,
            Err(e) => Err(Error::SyncChannelRecv(e)),
        }
    }

    pub async fn shutdown(&self) -> bool {
        let tx = self.shutdown_tx.clone();
        if let Err(e) = tx.send(()).await {
            warn!("sending shutdown signal failed: {}", e);
            return false;
        }
        true
    }

    pub fn blocking_shutdown(&self) -> bool {
        let tx = self.shutdown_tx.clone();
        if let Err(e) = tx.blocking_send(()) {
            warn!("sending shutdown signal failed: {}", e);
            return false;
        }
        true
    }

    #[cfg(feature = "auto-reload")]
    pub(crate) fn new_watcher(&self) -> Result<(), Error> {
        let config_path = if let Some(p) = self.config_path.as_ref() {
            p
        } else {
            return Err(Error::NoConfigFile);
        };
        if self.auto_reload {
            trace!("starting new watcher for config file: {}", config_path);
            let rt_id = self.rt_id;
            let mut watcher: RecommendedWatcher =
                notify::recommended_watcher(move |res: NotifyResult<event::Event>| {
                    match res {
                        // FIXME Not sure what are the most appropriate events to
                        // filter on different platforms.
                        Ok(ev) => {
                            match ev.kind {
                                #[cfg(any(target_os = "macos", target_os = "ios"))]
                                event::EventKind::Modify(event::ModifyKind::Data(
                                    event::DataChange::Content,
                                )) => {
                                    info!("config file event matched: {:?}", ev);
                                    if let Err(e) = reload(rt_id) {
                                        warn!("reload config file failed: {}", e);
                                    }
                                }
                                #[cfg(any(target_os = "linux", target_os = "android"))]
                                event::EventKind::Access(event::AccessKind::Close(
                                    event::AccessMode::Write,
                                ))
                                | event::EventKind::Remove(event::RemoveKind::File) => {
                                    info!("config file event matched: {:?}", ev);
                                    if let Err(e) = reload(rt_id) {
                                        warn!("reload config file failed: {}", e);
                                    }
                                }
                                #[cfg(target_os = "windows")]
                                event::EventKind::Modify(event::ModifyKind::Data(
                                    event::DataChange::Any,
                                )) => {
                                    info!("config file event matched: {:?}", ev);
                                    if let Err(e) = reload(rt_id) {
                                        warn!("reload config file failed: {}", e);
                                    }
                                }
                                _ => {
                                    trace!("skip config file event: {:?}", ev);
                                }
                            }
                            // The config file could somehow be removed and re-created
                            // by an editor, in that case create a new watcher to watch
                            // the new file.
                            if let event::EventKind::Remove(event::RemoveKind::File) = ev.kind {
                                if let Some(m) = RUNTIME_MANAGER.lock().unwrap().get(&rt_id) {
                                    let _ = m.new_watcher();
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("config file watch error: {:?}", e);
                        }
                    }
                })
                .map_err(Error::Watcher)?;
            watcher
                .watch(
                    std::path::Path::new(&config_path),
                    RecursiveMode::NonRecursive,
                )
                .map_err(Error::Watcher)?;
            info!("watching changes of file: {}", config_path);
            self.watcher.lock().unwrap().replace(watcher);
        }
        Ok(())
    }
}

pub type RuntimeId = u16;

lazy_static! {
    pub static ref RUNTIME_MANAGER: Mutex<HashMap<RuntimeId, Arc<RuntimeManager>>> =
        Mutex::new(HashMap::new());
}

pub fn reload(key: RuntimeId) -> Result<(), Error> {
    if let Some(m) = RUNTIME_MANAGER
        .lock()
        .map_err(|_| Error::RuntimeManager)?
        .get(&key)
    {
        return m.blocking_reload();
    }
    Err(Error::RuntimeManager)
}

pub fn shutdown(key: RuntimeId) -> bool {
    if let Some(m) = RUNTIME_MANAGER.lock().unwrap().get(&key) {
        return m.blocking_shutdown();
    }
    false
}

/// Pauses (stops) or resumes the kiri bridge of runtime `key`. False if no
/// such runtime runs.
#[cfg(feature = "kiri-bridge")]
pub fn set_kiri_bridge_paused(key: RuntimeId, paused: bool) -> bool {
    if let Ok(g) = RUNTIME_MANAGER.lock() {
        if let Some(m) = g.get(&key) {
            m.set_kiri_bridge_paused(paused);
            return true;
        }
    }
    false
}

/// True while runtime `key` runs a kiri bridge.
#[cfg(feature = "kiri-bridge")]
pub fn kiri_bridge_running(key: RuntimeId) -> bool {
    RUNTIME_MANAGER
        .lock()
        .ok()
        .and_then(|g| g.get(&key).map(|m| m.kiri_bridge_running()))
        .unwrap_or(false)
}

/// What runtime `key`'s kiri bridge has carried so far: live circuits,
/// circuits opened, bytes forwarded, client offers and connections (counts
/// and fixed categories only, no addresses). `None` if no runtime with
/// that id runs or its bridge does not serve.
#[cfg(feature = "kiri-bridge")]
pub fn kiri_bridge_stats(key: RuntimeId) -> Option<kiri_core::bridge::BridgeStats> {
    RUNTIME_MANAGER
        .lock()
        .ok()
        .and_then(|g| g.get(&key).cloned())
        .and_then(|m| m.kiri_bridge_stats())
}

/// Turns runtime `key`'s kiri bridge's client activity lines on or off
/// (`kiri bridge: client offer …`, `client connected …`, `circuit opened …`,
/// `traffic: …`; kiri design §19.41). Off by default: they are per-session
/// records with their times (S1), a diagnostic for testing a bridge, not for
/// normal use. Before the start (kept for `key`, like the user's switches)
/// or while it runs (at once). True if the runtime runs.
#[cfg(feature = "kiri-bridge")]
pub fn set_kiri_bridge_activity_log(key: RuntimeId, on: bool) -> bool {
    proxy::kiri::prefs::Prefs::of(key).set_bridge_activity_log(on);
    is_running(key)
}

/// The user's kiri switches for runtime `key` (kiri design §19.39), before
/// it starts or while it runs (at once, no reload): `connect` false disables
/// every `kiri` outbound (client stopped, its connections closed, a
/// `standby` group skips it, used directly its connections go to its
/// `fallback` or are refused); `bridge` the user's choice for the bridge
/// (`None`: the conf's `[Kiri] bridge`; the conf's `bridge-override = off`
/// wins over it). Kept for `key` across restarts. True if the runtime runs.
#[cfg(feature = "kiri-host")]
pub fn set_kiri_user_prefs(key: RuntimeId, connect: bool, bridge: Option<bool>) -> bool {
    proxy::kiri::prefs::Prefs::of(key).set(connect, bridge);
    is_running(key)
}

/// Runtime `key`'s kiri state for the app's UI: every `kiri` outbound with
/// its client's session and paths (bridge address, round trips to the
/// bridge and to the egress, traffic; kiri design §19.44), and the
/// bridge's state and counts. Local only (bridge addresses, never a
/// destination); costs no traffic. Blocks for at most about 2 s: call it
/// from a thread outside leaf's runtime (an app's UI timer, ~1 s), not from
/// inside it.
#[cfg(feature = "kiri-host")]
pub fn kiri_status_snapshot(key: RuntimeId) -> proxy::kiri::status::Snapshot {
    #[cfg(feature = "kiri-bridge")]
    let (running, stats) = (kiri_bridge_running(key), kiri_bridge_stats(key));
    #[cfg(not(feature = "kiri-bridge"))]
    let (running, stats) = (false, None);
    let part = proxy::kiri::status::BridgePart {
        state: kiri_bridge_state(key) as i32,
        running,
        stats,
    };
    proxy::kiri::status::snapshot(key, part)
}

/// [`kiri_status_snapshot`] as JSON (what `leaf_kiri_status` returns);
/// schema: [`proxy::kiri::status`].
#[cfg(feature = "kiri-host")]
pub fn kiri_status(key: RuntimeId) -> String {
    proxy::kiri::status::to_json(&kiri_status_snapshot(key))
}

/// The user's kiri switches for runtime `key` (as set, or the defaults).
#[cfg(feature = "kiri-host")]
pub fn kiri_user_prefs(key: RuntimeId) -> (bool, Option<bool>) {
    let p = proxy::kiri::prefs::Prefs::of(key);
    (p.connect(), p.bridge())
}

/// Whether runtime `key`'s kiri bridge is wanted, and why not (for the app's
/// switch: e.g. greyed out while forced off by the server).
#[cfg(feature = "kiri-host")]
#[allow(unused_variables)]
pub fn kiri_bridge_state(key: RuntimeId) -> proxy::kiri::prefs::BridgeState {
    use proxy::kiri::prefs::BridgeState;
    if !cfg!(feature = "kiri-bridge") {
        return BridgeState::NotBuilt;
    }
    #[cfg(feature = "kiri-bridge")]
    if let Some(m) = RUNTIME_MANAGER
        .lock()
        .ok()
        .and_then(|g| g.get(&key).cloned())
    {
        return m.kiri_bridge_state();
    }
    BridgeState::NoRuntime
}

/// Tells runtime `key` that the device's network changed to `network_id`
/// (an app calls this on a path change: `NWPathMonitor`,
/// `ConnectivityManager`; the id is opaque, e.g. the SSID or the carrier,
/// kept only as its SHA-256, empty if unknown): every `standby` group switches to that
/// network's remembered state (fresh for a new or unknown network), and the
/// runtime's kiri clients forget what bridges said about reaching their
/// egress on the old network (kiri's egress failover). False if no such
/// runtime runs.
pub fn network_changed(key: RuntimeId, network_id: &str) -> bool {
    let m = RUNTIME_MANAGER
        .lock()
        .ok()
        .and_then(|g| g.get(&key).cloned());
    match m {
        Some(m) => {
            m.network_changed(network_id);
            #[cfg(feature = "outbound-kiri")]
            proxy::kiri::outbound::network_changed(&proxy::kiri::prefs::Prefs::of(key));
            true
        }
        None => false,
    }
}

pub fn is_running(key: RuntimeId) -> bool {
    RUNTIME_MANAGER.lock().unwrap().contains_key(&key)
}

pub fn test_config(config_path: &str) -> Result<(), Error> {
    config::from_file(config_path)
        .map(|_| ())
        .map_err(Error::Config)
}

fn new_runtime(opt: &RuntimeOption) -> Result<tokio::runtime::Runtime, Error> {
    match opt {
        RuntimeOption::SingleThread => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(Error::Io),
        RuntimeOption::MultiThreadAuto(stack_size) => tokio::runtime::Builder::new_multi_thread()
            .thread_stack_size(*stack_size)
            .enable_all()
            .build()
            .map_err(Error::Io),
        RuntimeOption::MultiThread(worker_threads, stack_size) => {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(*worker_threads)
                .thread_stack_size(*stack_size)
                .enable_all()
                .build()
                .map_err(Error::Io)
        }
    }
}

#[derive(Debug)]
pub enum RuntimeOption {
    // Single-threaded runtime.
    SingleThread,
    // Multi-threaded runtime with thread stack size.
    MultiThreadAuto(usize),
    // Multi-threaded runtime with the number of worker threads and thread stack size.
    MultiThread(usize, usize),
}

#[derive(Debug)]
pub enum Config {
    File(String),
    Str(String),
    Internal(config::Config),
}

#[derive(Debug)]
pub struct StartOptions {
    // The path of the config.
    pub config: Config,
    // Enable auto reload, take effect only when "auto-reload" feature is enabled.
    #[cfg(feature = "auto-reload")]
    pub auto_reload: bool,
    // Tokio runtime options.
    pub runtime_opt: RuntimeOption,
}

pub fn start(rt_id: RuntimeId, opts: StartOptions) -> Result<(), Error> {
    #[cfg(debug_assertions)]
    println!("start with options:\n{:#?}", opts);

    let (reload_tx, mut reload_rx) = mpsc::channel(1);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

    let config_path = match opts.config {
        Config::File(ref p) => Some(p.to_owned()),
        _ => None,
    };

    let mut config = match opts.config {
        Config::File(p) => config::from_file(&p).map_err(Error::Config)?,
        Config::Str(s) => config::from_string(&s).map_err(Error::Config)?,
        Config::Internal(c) => c,
    };

    app::logger::setup_logger(&config.log)?;
    config::compat::log(&config.notes);

    let rt = new_runtime(&opts.runtime_opt)?;
    let _g = rt.enter();

    let mut tasks: Vec<Runner> = Vec::new();
    let mut runners = Vec::new();

    let dns_client = Arc::new(RwLock::new(
        DnsClient::new(&config.dns).map_err(Error::Config)?,
    ));
    // The user's kiri switches, read before anything kiri starts.
    #[cfg(feature = "kiri-host")]
    let kiri_prefs = proxy::kiri::prefs::Prefs::of(rt_id);
    #[cfg(feature = "outbound-kiri")]
    let outbound_kiri_prefs = kiri_prefs.clone();
    #[cfg(not(feature = "outbound-kiri"))]
    let outbound_kiri_prefs = ();
    let outbound_manager = OutboundManager::new_with_kiri_prefs(
        &config.outbounds,
        dns_client.clone(),
        outbound_kiri_prefs,
    )
    .map_err(Error::Config)?;
    #[cfg(feature = "outbound-standby")]
    let standby_groups = outbound_manager.standby_groups();
    let outbound_manager = Arc::new(RwLock::new(outbound_manager));
    let router = Arc::new(RwLock::new(Router::new(
        &mut config.router,
        dns_client.clone(),
    )));
    let stat_manager = Arc::new(RwLock::new(StatManager::new()));
    runners.push(StatManager::cleanup_task(stat_manager.clone()));
    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager.clone(),
        router.clone(),
        dns_client.clone(),
        stat_manager.clone(),
    ));

    let dispatcher_weak = Arc::downgrade(&dispatcher);
    let dns_client_cloned = dns_client.clone();
    rt.block_on(async move {
        dns_client_cloned
            .write()
            .await
            .replace_dispatcher(dispatcher_weak);
    });

    let nat_manager = Arc::new(NatManager::new(dispatcher.clone()));
    let inbound_manager =
        InboundManager::new(&config.inbounds, dispatcher, nat_manager).map_err(Error::Config)?;
    let mut inbound_net_runners = inbound_manager
        .get_network_runners()
        .map_err(Error::Config)?;
    runners.append(&mut inbound_net_runners);

    #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
    let net_info = if inbound_manager.has_tun_listener() && inbound_manager.tun_auto() {
        sys::get_net_info()
    } else {
        sys::NetInfo::default()
    };

    #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
    {
        if let sys::NetInfo {
            default_interface: Some(iface),
            ..
        } = &net_info
        {
            let binds = if let Ok(v) = std::env::var("OUTBOUND_INTERFACE") {
                format!("{},{}", v, iface)
            } else {
                iface.clone()
            };
            std::env::set_var("OUTBOUND_INTERFACE", binds);
        }
    }

    // Only when a TUN inbound is actually going to route through this process,
    // which is the same condition the other platforms apply above. Setting it
    // unconditionally pins every outbound socket that asks for the wildcard
    // bind to the default interface, and a socket bound to that interface
    // cannot reach a destination the interface does not serve -- loopback
    // most of all, where it fails with WSAEADDRNOTAVAIL.
    #[cfg(all(feature = "inbound-tun", target_os = "windows"))]
    if inbound_manager.has_tun_listener() && inbound_manager.tun_auto() {
        std::env::set_var("OUTBOUND_INTERFACE", winsys::get_default_interface_ips());
    }

    #[cfg(feature = "inbound-tun")]
    if let Some(r) = inbound_manager.get_tun_runner() {
        runners.push(r.map_err(Error::Config)?);
    }

    #[cfg(feature = "inbound-cat")]
    if let Some(r) = inbound_manager.get_cat_runner() {
        runners.push(r.map_err(Error::Config)?);
    }

    #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
    sys::post_tun_creation_setup(&net_info);

    // After the tun setup above, which may set `OUTBOUND_INTERFACE`: the
    // bridge's sockets follow it (`proxy::kiri::protect`), and it is read
    // once per process.
    #[cfg(feature = "kiri-bridge")]
    let kiri_bridge = {
        let b = app::kiri_bridge::BridgeService::new(kiri_prefs.clone());
        b.apply(config.kiri.as_ref());
        b
    };

    let runtime_manager = RuntimeManager::new(
        #[cfg(feature = "auto-reload")]
        rt_id,
        config_path,
        #[cfg(feature = "auto-reload")]
        opts.auto_reload,
        reload_tx,
        shutdown_tx,
        router,
        dns_client,
        outbound_manager,
        stat_manager,
        #[cfg(feature = "kiri-bridge")]
        kiri_bridge.clone(),
        #[cfg(feature = "outbound-standby")]
        standby_groups,
    );

    // Monitor config file changes.
    #[cfg(feature = "auto-reload")]
    {
        if let Err(e) = runtime_manager.new_watcher() {
            warn!("start config file watcher failed: {}", e);
        }
    }

    #[cfg(feature = "api")]
    {
        use std::net::SocketAddr;
        let listen_addr = if !option::API_LISTEN.is_empty() {
            Some(
                option::API_LISTEN
                    .parse::<SocketAddr>()
                    .map_err(|e| Error::Config(anyhow!("parse SocketAddr failed: {}", e)))?,
            )
        } else {
            None
        };
        if let Some(listen_addr) = listen_addr {
            let api_server = ApiServer::new(runtime_manager.clone());
            runners.push(api_server.serve(listen_addr));
        }
    }

    drop(config); // explicitly free the memory

    // Monitor reload signal.
    let rm = runtime_manager.clone();
    tasks.push(Box::pin(async move {
        loop {
            if let Some(res_tx) = reload_rx.recv().await {
                let res = rm.reload().await;
                if let Err(e) = res_tx.send(res) {
                    warn!("sending reload result failed: {}", e);
                }
            } else {
                warn!("receiving none reload signal");
            }
        }
    }));

    // The main task joining all runners.
    tasks.push(Box::pin(async move {
        futures::future::join_all(runners).await;
    }));

    // Monitor shutdown signal.
    tasks.push(Box::pin(async move {
        let _ = shutdown_rx.recv().await;
    }));

    // Monitor ctrl-c exit signal.
    #[cfg(feature = "ctrlc")]
    tasks.push(Box::pin(async move {
        let _ = tokio::signal::ctrl_c().await;
    }));

    RUNTIME_MANAGER
        .lock()
        .map_err(|_| Error::RuntimeManager)?
        .insert(rt_id, runtime_manager);

    trace!("added runtime {}", &rt_id);

    rt.block_on(futures::future::select_all(tasks));

    // The kiri clients' goodbye goes out while the runtime and the network
    // setup are still there (kiri §19.40; bounded, about a second at most).
    #[cfg(feature = "outbound-kiri")]
    rt.block_on(async {
        let close = proxy::kiri::outbound::close_clients(&kiri_prefs);
        let _ = tokio::time::timeout(std::time::Duration::from_millis(1500), close).await;
    });

    #[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
    sys::post_tun_completion_setup(&net_info);

    drop(inbound_manager);

    // Unlinks from the registrars before the runtime's tasks are dropped.
    #[cfg(feature = "kiri-bridge")]
    kiri_bridge.stop();

    RUNTIME_MANAGER
        .lock()
        .map_err(|_| Error::RuntimeManager)?
        .remove(&rt_id);

    rt.shutdown_background();

    trace!("removed runtime {}", &rt_id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_restart() {
        let conf = r#"
[General]
loglevel = trace
dns-server = 1.1.1.1
socks-interface = 127.0.0.1
socks-port = 1080
# tun = auto

[Proxy]
Direct = direct
"#;

        for _i in 1..3 {
            thread::spawn(move || {
                let opts = StartOptions {
                    config: Config::Str(conf.to_string()),
                    #[cfg(feature = "auto-reload")]
                    auto_reload: false,
                    runtime_opt: RuntimeOption::SingleThread,
                };
                start(0, opts).unwrap();
            });
            thread::sleep(std::time::Duration::from_secs(2));
            assert!(shutdown(0));
            loop {
                thread::sleep(std::time::Duration::from_secs(1));
                if !is_running(0) {
                    break;
                }
            }
        }
    }
}
