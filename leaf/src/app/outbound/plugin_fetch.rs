//! Downloading the plugins a config names by url.
//!
//! A plugin outbound that gives a `url` instead of a `path` is fetched into a
//! cache keyed by its digest -- `<cache>/<sha256>/<file>` -- and its `path` is
//! filled in before any outbound is built. The digest is the version: the same
//! `sha256` is never downloaded twice, a config that moves to a new build moves
//! to a new directory, and a cache that already holds every file is all a start
//! needs, network or not.
//!
//! The rules that make that safe:
//!
//! * Only `https`, including every redirect along the way, and only together
//!   with a `sha256`. The config is what vouches for the file, so the file has
//!   to be pinned by it; a url alone would let whoever serves it decide what
//!   runs.
//! * A download is written to a temporary file beside its destination, hashed
//!   as it arrives, and renamed into place only once the digest matches. A
//!   partial or wrong file is never at the path the host loads. The host checks
//!   the pin again when it opens the library, which also covers the window
//!   between this check and that one.
//! * A download that runs past the size the config declared, or past
//!   [`MAX_UNDECLARED_SIZE`] when it declared none, is stopped there.
//!
//! [`prefetch`] reports what it does through a callback, on the calling thread
//! and never concurrently, with a fixed shape an embedding app can build a UI
//! on: one `Queued` or `Cached` event per plugin before any download starts,
//! then `Started`, `Progress` and exactly one `Done` or `Failed` for each one
//! it downloads. A download that has not finished is reported at least once a
//! second -- as `Progress`, even before the server has answered -- so the
//! callback can cancel one stuck connecting as well as one stuck mid-body. The
//! callback returns `false` to cancel.
//!
//! Where the cache lives is the embedding app's decision, not this module's:
//! whether a directory is safe to load code from depends on who can write to
//! it, which only the app and its installer know. It comes from
//! [`FetchOptions`], or from `PLUGIN_CACHE_DIR`, and there is no default.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use protobuf::Message;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::Instant;
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};
use tracing::{debug, info, warn};

use crate::config::internal;

/// Where downloaded plugins are cached, when [`FetchOptions`] are not given.
pub const ENV_CACHE_DIR: &str = "PLUGIN_CACHE_DIR";

/// How long, in seconds, the download a start falls back to may take.
pub const ENV_TIMEOUT: &str = "PLUGIN_FETCH_TIMEOUT";

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

pub const DEFAULT_MAX_CONCURRENT: usize = 4;

/// The most a download may bring in when the config declares no size.
pub const MAX_UNDECLARED_SIZE: u64 = 64 * 1024 * 1024;

const MAX_REDIRECTS: usize = 5;

/// How often a download in progress is reported. Bytes arrive far more often
/// than any UI wants to hear about them.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// How long a download that has not finished may go unreported before it is
/// reported again with no new bytes. This is what gives the callback -- and so
/// the app -- a chance to cancel a download that has stalled, whether it is
/// stuck connecting, in the TLS handshake, waiting for a turn, or mid-body.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
pub struct FetchOptions {
    pub cache_dir: PathBuf,
    /// The whole prefetch, not each download. `None` waits as long as it takes.
    pub timeout: Option<Duration>,
    pub max_concurrent: usize,
    /// Trusted in addition to the public roots. Not reachable from a config
    /// file or the C API: it exists for a test that serves plugins itself.
    pub extra_roots: Vec<CertificateDer<'static>>,
}

impl FetchOptions {
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
            timeout: Some(DEFAULT_TIMEOUT),
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            extra_roots: Vec::new(),
        }
    }

    /// Options from `PLUGIN_CACHE_DIR` and `PLUGIN_FETCH_TIMEOUT`, read now
    /// rather than once per process, so an app can set them just before it
    /// calls in.
    pub fn from_env() -> anyhow::Result<Self> {
        let cache_dir = std::env::var_os(ENV_CACHE_DIR)
            .filter(|dir| !dir.is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "the config downloads plugins, but no cache directory was given; set {} to \
                     a directory only this app can write to",
                    ENV_CACHE_DIR
                )
            })?;
        let mut options = Self::new(cache_dir);
        if let Ok(secs) = std::env::var(ENV_TIMEOUT) {
            let secs: u64 = secs
                .trim()
                .parse()
                .map_err(|_| anyhow!("{} [{}] is not a number of seconds", ENV_TIMEOUT, secs))?;
            options.timeout = Some(Duration::from_secs(secs));
        }
        Ok(options)
    }
}

static DEFAULT_OPTIONS: Mutex<Option<FetchOptions>> = Mutex::new(None);

/// The options a start and a reload use, in place of the environment.
///
/// For an embedder that links leaf as a Rust library; the C API has
/// `PLUGIN_CACHE_DIR` instead.
pub fn set_default_options(options: Option<FetchOptions>) {
    *DEFAULT_OPTIONS.lock().unwrap() = options;
}

fn default_options() -> anyhow::Result<FetchOptions> {
    if let Some(options) = DEFAULT_OPTIONS.lock().unwrap().clone() {
        return Ok(options);
    }
    FetchOptions::from_env()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchEventKind {
    /// Not in the cache; will be downloaded.
    Queued,
    /// Already in the cache. Terminal.
    Cached,
    /// The server answered; `total` is known now if it was not before.
    Started,
    Progress,
    /// Downloaded, and the digest matched. Terminal.
    Done,
    /// Terminal; `error` says why.
    Failed,
}

impl FetchEventKind {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Cached | Self::Done | Self::Failed)
    }
}

#[derive(Clone, Debug)]
pub struct FetchEvent<'a> {
    pub kind: FetchEventKind,
    /// `0..count`, stable for the whole prefetch.
    pub index: usize,
    /// How many distinct plugins this prefetch covers. Plugins that share a
    /// digest are one file, and count once.
    pub count: usize,
    /// The name the config gave the plugin.
    pub plugin: &'a str,
    pub downloaded: u64,
    pub total: Option<u64>,
    /// Summed over the plugins being downloaded; cached ones are not counted.
    pub all_downloaded: u64,
    /// `None` while any download's size is unknown.
    pub all_total: Option<u64>,
    pub error: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct FetchFailure {
    pub plugin: String,
    pub reason: String,
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The config asks for something this module will not do, or there is
    /// nowhere to put the result. Nothing was downloaded.
    #[error(transparent)]
    Config(anyhow::Error),
    /// At least one plugin could not be fetched. The others were, and are in
    /// the cache.
    #[error("{}", describe_failures(.0))]
    Failed(Vec<FetchFailure>),
    #[error("plugin download cancelled")]
    Cancelled,
}

fn describe_failures(failures: &[FetchFailure]) -> String {
    let each: Vec<String> = failures
        .iter()
        .map(|f| format!("plugin [{}]: {}", f.plugin, f.reason))
        .collect();
    format!("failed to download plugins: {}", each.join("; "))
}

impl From<FetchError> for crate::Error {
    fn from(err: FetchError) -> Self {
        match err {
            FetchError::Config(err) => crate::Error::Config(err),
            FetchError::Failed(_) => crate::Error::PluginFetch(err.to_string()),
            FetchError::Cancelled => crate::Error::Cancelled,
        }
    }
}

/// One plugin outbound that is to come from a url.
struct UrlPlugin {
    /// Index into `config.outbounds`.
    outbound: usize,
    name: String,
    url: url::Url,
    sha256: String,
    size: Option<u64>,
}

/// One file to have in the cache. Outbounds that name the same digest share it.
#[derive(Clone)]
struct Job {
    name: String,
    url: url::Url,
    sha256: String,
    size: Option<u64>,
    path: PathBuf,
}

fn plugin_settings(
    outbound: &internal::Outbound,
) -> anyhow::Result<internal::PluginOutboundSettings> {
    internal::PluginOutboundSettings::parse_from_bytes(&outbound.settings)
        .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", outbound.tag, e))
}

/// The plugin outbounds that give a url and no path, validated.
fn url_plugins(config: &internal::Config) -> anyhow::Result<Vec<UrlPlugin>> {
    let mut found = Vec::new();
    for (index, outbound) in config.outbounds.iter().enumerate() {
        if outbound.protocol != "plugin" {
            continue;
        }
        let settings = plugin_settings(outbound)?;
        if settings.url.is_empty() || !settings.path.is_empty() {
            continue;
        }
        let name = if settings.name.is_empty() {
            outbound.tag.clone()
        } else {
            settings.name.clone()
        };
        let url = url::Url::parse(&settings.url).map_err(|e| {
            anyhow!(
                "plugin [{}]: url [{}] is not a url: {}",
                name,
                settings.url,
                e
            )
        })?;
        if url.scheme() != "https" {
            bail!(
                "plugin [{}]: url [{}] is not https; plugins are only downloaded over https",
                name,
                settings.url
            );
        }
        if url.host().is_none() {
            bail!("plugin [{}]: url [{}] names no host", name, settings.url);
        }
        let sha256 = settings.sha256.trim().to_ascii_lowercase();
        if sha256.is_empty() {
            bail!(
                "plugin [{}]: a plugin downloaded from a url has to be pinned with sha256; the \
                 config is what vouches for the file, so it has to say which file",
                name
            );
        }
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!(
                "plugin [{}]: sha256 [{}] is not 64 hex digits",
                name,
                settings.sha256
            );
        }
        found.push(UrlPlugin {
            outbound: index,
            name,
            url,
            sha256,
            size: (settings.size != 0).then_some(settings.size),
        });
    }
    Ok(found)
}

/// Whether the config names any plugin by url, which is what decides whether a
/// start needs a cache directory at all.
pub fn has_url_plugins(config: &internal::Config) -> anyhow::Result<bool> {
    Ok(!url_plugins(config)?.is_empty())
}

/// The last segment of the url's path, reduced to characters that are safe in
/// a file name on every platform. The name matters to nobody but a person
/// looking in the cache, and to Windows, which wants a `.dll` to load a DLL:
/// given a name with no extension, it looks for that name plus `.dll`, so a
/// name without one gets the platform's.
fn file_name_for(url: &url::Url) -> String {
    let last = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .unwrap_or("");
    let cleaned: String = last
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    // A trailing dot is one more way for Windows to read a name as having no
    // extension, and it drops the dot from the file anyway.
    let cleaned = cleaned.trim_matches('.');
    if cleaned.is_empty() {
        format!("plugin{}", std::env::consts::DLL_SUFFIX)
    } else if !cleaned.contains('.') {
        format!("{}{}", cleaned, std::env::consts::DLL_SUFFIX)
    } else {
        cleaned.to_string()
    }
}

/// One job per digest, in the order the config first names each one, and the
/// outbounds that each job's file serves.
fn plan(config: &internal::Config, cache_dir: &Path) -> anyhow::Result<Vec<(Job, Vec<usize>)>> {
    let mut jobs: Vec<(Job, Vec<usize>)> = Vec::new();
    for plugin in url_plugins(config)? {
        if let Some((_, outbounds)) = jobs.iter_mut().find(|(job, _)| job.sha256 == plugin.sha256) {
            outbounds.push(plugin.outbound);
            continue;
        }
        let path = cache_dir
            .join(&plugin.sha256)
            .join(file_name_for(&plugin.url));
        jobs.push((
            Job {
                name: plugin.name,
                url: plugin.url,
                sha256: plugin.sha256,
                size: plugin.size,
                path,
            },
            vec![plugin.outbound],
        ));
    }
    Ok(jobs)
}

/// Fills in `path` for every plugin outbound that gives a url, from the cache
/// alone. Fails, naming the plugin, if its file is not there.
pub fn resolve_from_cache(config: &mut internal::Config, cache_dir: &Path) -> anyhow::Result<()> {
    for (job, outbounds) in plan(config, cache_dir)? {
        if !job.path.is_file() {
            bail!(
                "plugin [{}] is not in the cache at [{}]",
                job.name,
                job.path.display()
            );
        }
        for index in outbounds {
            let outbound = &mut config.outbounds[index];
            let mut settings = plugin_settings(outbound)?;
            settings.path = job.path.display().to_string();
            outbound.settings = settings
                .write_to_bytes()
                .map_err(|e| anyhow!("re-encoding [{}] outbound settings: {}", outbound.tag, e))?;
        }
    }
    Ok(())
}

/// Downloads whatever the config names by url and the cache does not yet
/// hold, reporting through `on_event` on this thread. Blocks until every
/// plugin is in the cache, has failed, or `on_event` returned `false`.
///
/// It does not start anything, and it does not touch `config`; a start after
/// it finds everything in the cache.
pub fn prefetch(
    config: &internal::Config,
    options: &FetchOptions,
    on_event: &mut dyn FnMut(&FetchEvent<'_>) -> bool,
) -> Result<(), FetchError> {
    let jobs: Vec<Job> = plan(config, &options.cache_dir)
        .map_err(FetchError::Config)?
        .into_iter()
        .map(|(job, _)| job)
        .collect();
    if jobs.is_empty() {
        return Ok(());
    }
    // Current-thread, so that the callback runs on the caller's thread, which
    // is what the C API promises and what lets an app skip locking.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| FetchError::Config(anyhow!("creating the download runtime: {}", e)))?;
    rt.block_on(run(jobs, options, on_event))
}

/// What a start does before it builds any outbound: fetch what is missing,
/// then point the outbounds at the cache. A config that names nothing by url
/// needs no cache directory and costs nothing here.
pub fn prepare_for_start(config: &mut internal::Config) -> Result<(), crate::Error> {
    if !has_url_plugins(config).map_err(crate::Error::Config)? {
        return Ok(());
    }
    let options = default_options().map_err(crate::Error::Config)?;
    prefetch(config, &options, &mut log_event)?;
    resolve_from_cache(config, &options.cache_dir).map_err(crate::Error::Config)
}

/// What a reload does instead: the cache only, and never the network. Plugins
/// are not swapped under a running instance, so a reload that needs a plugin
/// the cache does not have is refused rather than half-applied.
pub fn prepare_for_reload(config: &mut internal::Config) -> Result<(), crate::Error> {
    if !has_url_plugins(config).map_err(crate::Error::Config)? {
        return Ok(());
    }
    let options = default_options().map_err(crate::Error::Config)?;
    resolve_from_cache(config, &options.cache_dir).map_err(|e| {
        crate::Error::Config(anyhow!(
            "{:#}; a reload does not download plugins, so a config that changes a plugin \
             requires a restart",
            e
        ))
    })
}

/// What an outbound test does: like a reload, the cache only. A test is not
/// the place for a download the app did not ask for, so a plugin the cache
/// does not hold fails the test until something puts it there: a start,
/// `prefetch`, or a copy made by hand.
pub fn prepare_for_test(config: &mut internal::Config) -> Result<(), crate::Error> {
    if !has_url_plugins(config).map_err(crate::Error::Config)? {
        return Ok(());
    }
    let options = default_options().map_err(crate::Error::Config)?;
    resolve_from_cache(config, &options.cache_dir).map_err(|e| {
        crate::Error::Config(anyhow!(
            "{:#}; testing an outbound does not download plugins, so fetch them first \
             (leaf_prefetch_plugins, or a start)",
            e
        ))
    })
}

fn log_event(event: &FetchEvent<'_>) -> bool {
    match event.kind {
        FetchEventKind::Cached => debug!(plugin = %event.plugin, "plugin is in the cache"),
        FetchEventKind::Queued => {
            info!(plugin = %event.plugin, total = ?event.total, "plugin will be downloaded")
        }
        FetchEventKind::Started => {
            info!(plugin = %event.plugin, total = ?event.total, "downloading plugin")
        }
        FetchEventKind::Progress => {}
        FetchEventKind::Done => {
            info!(plugin = %event.plugin, bytes = event.downloaded, "downloaded plugin")
        }
        FetchEventKind::Failed => warn!(
            plugin = %event.plugin,
            error = event.error.unwrap_or(""),
            "failed to download plugin"
        ),
    }
    true
}

/// What a download task tells the coordinator. Only the coordinator calls the
/// callback, so it is only ever called from one place, one event at a time.
enum Report {
    Started { index: usize, total: Option<u64> },
    Progress { index: usize, downloaded: u64 },
    Done { index: usize, downloaded: u64 },
    Failed { index: usize, reason: String },
}

struct Tracker<'a> {
    names: Vec<String>,
    cached: Vec<bool>,
    downloaded: Vec<u64>,
    total: Vec<Option<u64>>,
    terminal: Vec<bool>,
    last_report: Vec<Option<Instant>>,
    on_event: &'a mut dyn FnMut(&FetchEvent<'_>) -> bool,
}

impl Tracker<'_> {
    /// Reports one event, returning `false` when the callback asked to stop.
    fn report(&mut self, kind: FetchEventKind, index: usize, error: Option<&str>) -> bool {
        let downloading = || (0..self.names.len()).filter(|&i| !self.cached[i]);
        let all_downloaded = downloading().map(|i| self.downloaded[i]).sum();
        let all_total = downloading().map(|i| self.total[i]).sum::<Option<u64>>();
        if kind.is_terminal() {
            self.terminal[index] = true;
        }
        self.last_report[index] = Some(Instant::now());
        let event = FetchEvent {
            kind,
            index,
            count: self.names.len(),
            plugin: &self.names[index],
            downloaded: self.downloaded[index],
            total: self.total[index],
            all_downloaded,
            all_total,
            error,
        };
        (self.on_event)(&event)
    }

    /// Records what a task reported and passes it on, returning `false` when
    /// the callback asked to stop.
    fn apply(&mut self, message: Report, failures: &mut Vec<FetchFailure>) -> bool {
        match message {
            Report::Started { index, total } => {
                if self.total[index].is_none() {
                    self.total[index] = total;
                }
                self.report(FetchEventKind::Started, index, None)
            }
            Report::Progress { index, downloaded } => {
                self.downloaded[index] = downloaded;
                // By time alone. A rule that also reported every percent would
                // send a fast download's hundred of them in a tenth of a
                // second, which no UI can use; the final count comes with DONE.
                let due =
                    self.last_report[index].is_none_or(|at| at.elapsed() >= PROGRESS_INTERVAL);
                if due {
                    self.report(FetchEventKind::Progress, index, None)
                } else {
                    true
                }
            }
            Report::Done { index, downloaded } => {
                self.downloaded[index] = downloaded;
                self.report(FetchEventKind::Done, index, None)
            }
            Report::Failed { index, reason } => {
                failures.push(FetchFailure {
                    plugin: self.names[index].clone(),
                    reason: reason.clone(),
                });
                self.report(FetchEventKind::Failed, index, Some(&reason))
            }
        }
    }
}

async fn run(
    jobs: Vec<Job>,
    options: &FetchOptions,
    on_event: &mut dyn FnMut(&FetchEvent<'_>) -> bool,
) -> Result<(), FetchError> {
    let count = jobs.len();
    let cached: Vec<bool> = jobs.iter().map(is_cached).collect();
    let mut tracker = Tracker {
        names: jobs.iter().map(|job| job.name.clone()).collect(),
        cached: cached.clone(),
        downloaded: vec![0; count],
        total: jobs.iter().map(|job| job.size).collect(),
        terminal: vec![false; count],
        last_report: vec![None; count],
        on_event,
    };

    // Every plugin is announced before anything touches the network, so an app
    // can lay out its whole list, and its total, from the first events.
    for (index, &is_cached) in cached.iter().enumerate() {
        let kind = if is_cached {
            FetchEventKind::Cached
        } else {
            FetchEventKind::Queued
        };
        if !tracker.report(kind, index, None) {
            return Err(FetchError::Cancelled);
        }
    }
    if cached.iter().all(|&c| c) {
        return Ok(());
    }

    let tls = Arc::new(client_config(&options.extra_roots).map_err(FetchError::Config)?);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let permits = Arc::new(Semaphore::new(options.max_concurrent.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    for (index, job) in jobs.into_iter().enumerate() {
        if cached[index] {
            continue;
        }
        let (tls, permits, tx) = (tls.clone(), permits.clone(), tx.clone());
        tasks.spawn(async move {
            let Ok(_permit) = permits.acquire_owned().await else {
                return;
            };
            let message = match download(index, &job, &tls, &tx).await {
                Ok(downloaded) => Report::Done { index, downloaded },
                Err(err) => Report::Failed {
                    index,
                    reason: format!("{:#}", err),
                },
            };
            let _ = tx.send(message);
        });
    }
    // Once the tasks' senders are all gone, the channel ends, and so does the
    // loop below.
    drop(tx);

    let deadline = options.timeout.map(|timeout| Instant::now() + timeout);
    let mut failures = Vec::new();
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL / 2);
    let cancelled = loop {
        let expired = async {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };
        let message = tokio::select! {
            message = rx.recv() => message,
            _ = expired => {
                // Stop everything first, so that no task is still writing when
                // its temporary file is removed.
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                // A download can finish just as the deadline passes, with its
                // DONE still queued: its file is in the cache by then, since
                // nothing awaits between the rename and the send. Every task
                // has stopped, so what is queued is all that will come.
                let mut cancelled = false;
                while let Ok(message) = rx.try_recv() {
                    if !tracker.apply(message, &mut failures) {
                        cancelled = true;
                        break;
                    }
                }
                let reason = format!(
                    "timed out after {:?}",
                    options.timeout.unwrap_or_default()
                );
                for index in 0..count {
                    if cancelled {
                        break;
                    }
                    if tracker.terminal[index] {
                        continue;
                    }
                    failures.push(FetchFailure {
                        plugin: tracker.names[index].clone(),
                        reason: reason.clone(),
                    });
                    if !tracker.report(FetchEventKind::Failed, index, Some(&reason)) {
                        cancelled = true;
                        break;
                    }
                }
                break cancelled;
            }
            _ = heartbeat.tick() => {
                // Every download that has not finished, started or not: one
                // stuck connecting or in the handshake is as much in need of a
                // way to be cancelled as one stuck waiting for the body.
                let now = Instant::now();
                let stale: Vec<usize> = (0..count)
                    .filter(|&i| {
                        !tracker.terminal[i]
                            && !cached[i]
                            && tracker.last_report[i]
                                .is_some_and(|at| now.duration_since(at) >= HEARTBEAT_INTERVAL)
                    })
                    .collect();
                let mut keep_going = true;
                for index in stale {
                    if !tracker.report(FetchEventKind::Progress, index, None) {
                        keep_going = false;
                        break;
                    }
                }
                if !keep_going {
                    break true;
                }
                continue;
            }
        };
        let Some(message) = message else {
            break false;
        };
        if !tracker.apply(message, &mut failures) {
            break true;
        }
    };

    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    if cancelled {
        return Err(FetchError::Cancelled);
    }

    // A task that ended without saying how -- it panicked -- still owes its
    // plugin a terminal event.
    for index in 0..count {
        if !tracker.terminal[index] {
            let reason = "the download ended without a result".to_string();
            failures.push(FetchFailure {
                plugin: tracker.names[index].clone(),
                reason: reason.clone(),
            });
            if !tracker.report(FetchEventKind::Failed, index, Some(&reason)) {
                return Err(FetchError::Cancelled);
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(FetchError::Failed(failures))
    }
}

/// Whether the file for `job` is already in place, and is the file the config
/// pinned. A file that is there but wrong -- truncated by a disk that filled,
/// or replaced -- is removed, so that the download that follows can put the
/// right one in its place instead of failing on the pin forever.
fn is_cached(job: &Job) -> bool {
    if !job.path.is_file() {
        return false;
    }
    match super::plugin::plugin_file_digest(&job.path) {
        Ok(digest) if digest == job.sha256 => true,
        Ok(digest) => {
            warn!(
                plugin = %job.name,
                path = %job.path.display(),
                expected = %job.sha256,
                found = %digest,
                "cached plugin does not match its pin; downloading it again"
            );
            if let Err(err) = std::fs::remove_file(&job.path) {
                warn!(path = %job.path.display(), "failed to remove it: {}", err);
            }
            false
        }
        Err(err) => {
            warn!(plugin = %job.name, "cannot read cached plugin: {}", err);
            false
        }
    }
}

fn client_config(extra_roots: &[CertificateDer<'static>]) -> anyhow::Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for root in extra_roots {
        roots
            .add(root.clone())
            .map_err(|e| anyhow!("adding a trusted root: {}", e))?;
    }
    #[cfg(feature = "rustls-tls-aws-lc")]
    let provider = rustls::crypto::aws_lc_rs::default_provider().into();
    #[cfg(not(feature = "rustls-tls-aws-lc"))]
    let provider = rustls::crypto::ring::default_provider().into();
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("building the TLS client: {}", e))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// A download in progress, removed when dropped unless it was put in place --
/// which is what cleans up after a failure, a cancel and a timeout alike,
/// since each of them ends by dropping the task that owns it.
struct PartialFile {
    path: PathBuf,
    kept: bool,
}

impl PartialFile {
    fn beside(destination: &Path) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let file_name = destination
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        // Unique per process and per download, so that two processes, or two
        // prefetches in one, never write to the same temporary file.
        let temporary = format!(
            ".{}.{}.{}.partial",
            file_name,
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        Self {
            path: destination.with_file_name(temporary),
            kept: false,
        }
    }

    /// Moves the finished file to `destination`. When that fails because
    /// someone else got there first -- another prefetch into the same cache,
    /// or a loaded library Windows will not let anyone replace -- what is there
    /// is as good as this, provided it is the same file.
    fn persist(mut self, destination: &Path, sha256: &str) -> anyhow::Result<()> {
        match std::fs::rename(&self.path, destination) {
            Ok(()) => {
                self.kept = true;
                Ok(())
            }
            Err(err) => match super::plugin::plugin_file_digest(destination) {
                Ok(digest) if digest == sha256 => Ok(()),
                _ => Err(anyhow!(
                    "moving the download to [{}] failed: {}",
                    destination.display(),
                    err
                )),
            },
        }
    }
}

impl Drop for PartialFile {
    fn drop(&mut self) {
        if !self.kept {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Fetches one file into the cache, returning how many bytes it was.
async fn download(
    index: usize,
    job: &Job,
    tls: &Arc<ClientConfig>,
    tx: &mpsc::UnboundedSender<Report>,
) -> anyhow::Result<u64> {
    let response = get_following_redirects(&job.url, tls).await?;

    let content_length = response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    let limit = job.size.unwrap_or(MAX_UNDECLARED_SIZE);
    if let (Some(declared), Some(announced)) = (job.size, content_length) {
        if declared != announced {
            bail!(
                "the server says the file is {} bytes, and the config says {}",
                announced,
                declared
            );
        }
    }
    if let Some(announced) = content_length {
        if announced > limit {
            bail!(
                "the server says the file is {} bytes, more than the {} allowed",
                announced,
                limit
            );
        }
    }
    let _ = tx.send(Report::Started {
        index,
        total: job.size.or(content_length),
    });

    let directory = job
        .path
        .parent()
        .ok_or_else(|| anyhow!("[{}] has no parent directory", job.path.display()))?;
    tokio::fs::create_dir_all(directory)
        .await
        .with_context(|| format!("creating [{}]", directory.display()))?;
    let partial = PartialFile::beside(&job.path);
    let mut file = tokio::fs::File::create(&partial.path)
        .await
        .with_context(|| format!("creating [{}]", partial.path.display()))?;

    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;
    let mut body = response.into_body();
    while let Some(frame) = body.frame().await {
        let frame = frame.context("reading the response")?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        downloaded += data.len() as u64;
        if downloaded > limit {
            bail!(
                "the download ran past {} bytes, the most {} allows, and was stopped",
                limit,
                if job.size.is_some() {
                    "the size the config declares"
                } else {
                    "a plugin with no declared size"
                }
            );
        }
        hasher.update(&data);
        file.write_all(&data)
            .await
            .with_context(|| format!("writing [{}]", partial.path.display()))?;
        let _ = tx.send(Report::Progress { index, downloaded });
    }
    file.flush().await?;
    file.sync_all().await?;
    // Closed before the rename: Windows will not move a file that is open.
    drop(file);

    if let Some(declared) = job.size {
        if downloaded != declared {
            bail!("got {} bytes, and the config says {}", downloaded, declared);
        }
    }
    let digest = hex::encode(hasher.finalize());
    if digest != job.sha256 {
        bail!("sha256 mismatch: expected {}, found {}", job.sha256, digest);
    }
    partial.persist(&job.path, &job.sha256)?;
    debug!(plugin = %job.name, path = %job.path.display(), "plugin is in the cache");
    Ok(downloaded)
}

async fn get_following_redirects(
    url: &url::Url,
    tls: &Arc<ClientConfig>,
) -> anyhow::Result<hyper::Response<hyper::body::Incoming>> {
    let mut url = url.clone();
    for _ in 0..=MAX_REDIRECTS {
        let response = get(&url, tls).await?;
        let status = response.status();
        if status.is_redirection() {
            let location = response
                .headers()
                .get(http::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| anyhow!("HTTP {} from [{}] with no location", status, url))?;
            let next = url.join(location).map_err(|e| {
                anyhow!(
                    "HTTP {} to [{}], which is not a url: {}",
                    status,
                    location,
                    e
                )
            })?;
            if next.scheme() != "https" {
                bail!(
                    "[{}] redirects to [{}], which is not https; plugins are only downloaded \
                     over https",
                    url,
                    next
                );
            }
            debug!(from = %url, to = %next, "following redirect");
            url = next;
            continue;
        }
        if status != http::StatusCode::OK {
            bail!("HTTP {} from [{}]", status, url);
        }
        return Ok(response);
    }
    bail!("more than {} redirects from [{}]", MAX_REDIRECTS, url)
}

/// One GET, on a connection of its own. Plugins are few and fetched rarely, so
/// there is nothing a connection pool would save.
async fn get(
    url: &url::Url,
    tls: &Arc<ClientConfig>,
) -> anyhow::Result<hyper::Response<hyper::body::Incoming>> {
    let port = url.port_or_known_default().unwrap_or(443);
    let (server_name, tcp) = match url.host() {
        Some(url::Host::Domain(domain)) => (
            ServerName::try_from(domain.to_string())
                .map_err(|e| anyhow!("[{}] is not a valid server name: {}", domain, e))?,
            tokio::net::TcpStream::connect((domain, port)).await,
        ),
        Some(url::Host::Ipv4(ip)) => (
            ServerName::IpAddress(IpAddr::V4(ip).into()),
            tokio::net::TcpStream::connect((ip, port)).await,
        ),
        Some(url::Host::Ipv6(ip)) => (
            ServerName::IpAddress(IpAddr::V6(ip).into()),
            tokio::net::TcpStream::connect((ip, port)).await,
        ),
        None => bail!("[{}] names no host", url),
    };
    let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
    let tcp = tcp.with_context(|| format!("connecting to {}", authority))?;
    let stream = tokio_rustls::TlsConnector::from(tls.clone())
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TLS handshake with {}", authority))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .with_context(|| format!("HTTP handshake with {}", authority))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = hyper::Request::get(&url[url::Position::BeforePath..url::Position::AfterQuery])
        .header(http::header::HOST, authority)
        .header(http::header::USER_AGENT, "leaf-plugin-fetch")
        .header(http::header::ACCEPT_ENCODING, "identity")
        .body(Empty::<Bytes>::new())?;
    sender
        .send_request(request)
        .await
        .with_context(|| format!("requesting [{}]", url))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(plugins: &str, proxies: &str) -> internal::Config {
        crate::config::conf::from_string(&format!("[Plugin]\n{}\n[Proxy]\n{}\n", plugins, proxies))
            .unwrap()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("leaf-plugin-fetch-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    #[test]
    fn refuses_what_it_will_not_download() {
        for (plugin, expected) in [
            (
                format!("p = url=http://example.com/p.dll, sha256={SHA}"),
                "is not https",
            ),
            (
                "p = url=https://example.com/p.dll".to_string(),
                "has to be pinned with sha256",
            ),
            (
                "p = url=https://example.com/p.dll, sha256=abc".to_string(),
                "not 64 hex digits",
            ),
            (
                format!("p = url=example.com/p.dll, sha256={SHA}"),
                "is not a url",
            ),
        ] {
            let config = config(&plugin, "P = plugin, plugin=p");
            let err = has_url_plugins(&config).unwrap_err().to_string();
            assert!(err.contains(expected), "[{}]: {}", plugin, err);
        }
    }

    #[test]
    fn a_path_wins_over_a_url() {
        let config = config(
            &format!("p = path=./p.dll, url=https://example.com/p.dll, sha256={SHA}"),
            "P = plugin, plugin=p",
        );
        assert!(!has_url_plugins(&config).unwrap());
    }

    #[test]
    fn file_names_are_safe_on_every_platform() {
        let name = |url: &str| file_name_for(&url::Url::parse(url).unwrap());
        assert_eq!(name("https://x/a/tls_cabi_go.dll?v=2"), "tls_cabi_go.dll");
        assert_eq!(name("https://x/a/b%20c:d.dll"), "b_20c_d.dll");
        assert_eq!(
            name("https://x/a/..."),
            format!("plugin{}", std::env::consts::DLL_SUFFIX)
        );
        assert_eq!(
            name("https://x/"),
            format!("plugin{}", std::env::consts::DLL_SUFFIX)
        );
        // No extension, and a library loader has to be told what it is.
        assert_eq!(
            name("https://x/releases/download/v1/tls-plugin"),
            format!("tls-plugin{}", std::env::consts::DLL_SUFFIX)
        );
        assert_eq!(
            name("https://x/get."),
            format!("get{}", std::env::consts::DLL_SUFFIX)
        );
        // An extension of any kind is left alone: the loader then takes the
        // name as it is.
        assert_eq!(name("https://x/libfoo.so.1"), "libfoo.so.1");
    }

    /// Two names for one digest are one file: one job, and both outbounds
    /// pointed at it.
    #[test]
    fn plugins_that_share_a_digest_share_a_file() {
        let dir = scratch("share");
        let config_in = config(
            &format!(
                "a = url=https://x/one.dll, sha256={SHA}\nb = url=https://y/two.dll, sha256={}",
                SHA.to_ascii_uppercase()
            ),
            "A = plugin, plugin=a\nB = plugin, plugin=b\nC = plugin, plugin=a",
        );
        let jobs = plan(&config_in, &dir).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].1.len(), 3);
        assert_eq!(jobs[0].0.path, dir.join(SHA).join("one.dll"));

        let mut config_out = config_in.clone();
        let err = resolve_from_cache(&mut config_out, &dir)
            .unwrap_err()
            .to_string();
        assert!(err.contains("plugin [a] is not in the cache"), "{}", err);

        std::fs::create_dir_all(dir.join(SHA)).unwrap();
        std::fs::write(dir.join(SHA).join("one.dll"), b"x").unwrap();
        resolve_from_cache(&mut config_out, &dir).unwrap();
        for outbound in &config_out.outbounds {
            let settings = plugin_settings(outbound).unwrap();
            assert_eq!(PathBuf::from(&settings.path), dir.join(SHA).join("one.dll"));
        }
        assert!(
            !has_url_plugins(&config_out).unwrap(),
            "every path is filled in"
        );
    }

    /// A cache that already holds every file needs no network, and says so
    /// with one `Cached` event per plugin.
    #[test]
    fn a_full_cache_is_reported_without_touching_the_network() {
        let dir = scratch("full");
        let body = b"plugin bytes";
        let sha = sha256_hex(body);
        std::fs::create_dir_all(dir.join(&sha)).unwrap();
        std::fs::write(dir.join(&sha).join("p.dll"), body).unwrap();
        let config = config(
            // Port 9 on a documentation address: nothing answers there, so a
            // request would fail the test rather than succeed by accident.
            &format!("p = url=https://192.0.2.1:9/p.dll, sha256={sha}"),
            "P = plugin, plugin=p",
        );
        let mut events = Vec::new();
        prefetch(&config, &FetchOptions::new(&dir), &mut |event| {
            events.push((
                event.kind,
                event.index,
                event.count,
                event.plugin.to_string(),
            ));
            true
        })
        .unwrap();
        assert_eq!(
            events,
            vec![(FetchEventKind::Cached, 0, 1, "p".to_string())]
        );
    }

    /// A cached file that is not the one the config pinned is removed, so the
    /// download that follows can replace it instead of failing the pin forever.
    #[test]
    fn a_wrong_file_in_the_cache_is_not_cached() {
        let dir = scratch("wrong");
        std::fs::create_dir_all(dir.join(SHA)).unwrap();
        let path = dir.join(SHA).join("p.dll");
        std::fs::write(&path, b"not the pinned file").unwrap();
        let job = Job {
            name: "p".to_string(),
            url: url::Url::parse("https://x/p.dll").unwrap(),
            sha256: SHA.to_string(),
            size: None,
            path: path.clone(),
        };
        assert!(!is_cached(&job));
        assert!(!path.exists());
    }

    /// A server that takes the connection and then says nothing leaves the
    /// download stuck in the TLS handshake, before any `Started`. It is still
    /// reported once a second, so the callback can cancel it long before the
    /// timeout would.
    #[test]
    fn a_download_stuck_before_the_server_answers_can_be_cancelled() {
        let dir = scratch("stuck");
        // Never accepted: the kernel completes the connection from the
        // backlog, and nothing ever writes a byte back.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = config(
            &format!("p = url=https://127.0.0.1:{port}/p.dll, sha256={SHA}"),
            "P = plugin, plugin=p",
        );
        let mut options = FetchOptions::new(&dir);
        options.timeout = Some(Duration::from_secs(60));
        let mut seen = Vec::new();
        let began = std::time::Instant::now();
        let result = prefetch(&config, &options, &mut |event| {
            seen.push(event.kind);
            event.kind != FetchEventKind::Progress
        });
        assert!(matches!(result, Err(FetchError::Cancelled)), "{:?}", result);
        assert_eq!(seen, vec![FetchEventKind::Queued, FetchEventKind::Progress]);
        assert!(
            began.elapsed() < Duration::from_secs(10),
            "cancelled only after {:?}",
            began.elapsed()
        );
        drop(listener);
    }

    #[test]
    fn cancelling_from_the_first_event_stops_before_any_download() {
        let dir = scratch("cancel");
        let config = config(
            &format!("p = url=https://192.0.2.1:9/p.dll, sha256={SHA}"),
            "P = plugin, plugin=p",
        );
        let mut seen = Vec::new();
        let result = prefetch(&config, &FetchOptions::new(&dir), &mut |event| {
            seen.push(event.kind);
            false
        });
        assert!(matches!(result, Err(FetchError::Cancelled)), "{:?}", result);
        assert_eq!(seen, vec![FetchEventKind::Queued]);
    }

    #[test]
    fn a_config_without_url_plugins_needs_no_cache_directory() {
        let mut config = config("p = path=./p.dll", "P = plugin, plugin=p");
        // No options set, no environment: nothing to do, so nothing asked for.
        prepare_for_start(&mut config).unwrap();
    }
}
