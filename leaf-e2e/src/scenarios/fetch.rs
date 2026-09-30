//! Downloading plugins by url, observed from the outside.
//!
//! A client downloads its config, and the config names some of its plugins by
//! url. These cases serve those plugins from [`PluginServer`] and check what a
//! client relies on: that a start or a prefetch puts the right file in the
//! cache and nothing else, that a full cache needs no network, that a bad or
//! hostile server costs a clear failure and never a file, and that the events
//! an app builds its progress UI on keep the shape they promise.
//!
//! Every download case runs its events through [`check_contract`], which is
//! that promise written down once: every plugin announced before any download
//! starts, each one's events in order, exactly one terminal event each, totals
//! that only grow and add up, and every callback on the calling thread.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use leaf::app::outbound::plugin_fetch::{self, FetchError, FetchEventKind, FetchOptions};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::Socks5;
use crate::fixtures::Fixture;
use crate::flow;
use crate::net;
use crate::node::{cfg, Node};
use crate::paths;
use crate::plugin_server::{Gate, Length, PluginServer, Route};
use crate::scenario::{boxed, Scenario, Tag};
use crate::servers::Origin;

pub fn scenarios() -> Vec<Scenario> {
    let plain = |id: &str, run: fn() -> crate::scenario::CaseFuture| {
        Scenario::new(id.to_string(), "fetch", run)
            .tags([Tag::Fetch])
            .timeout(Duration::from_secs(30))
    };
    let with_plugin = |id: &str, run: fn() -> crate::scenario::CaseFuture| {
        Scenario::new(id.to_string(), "fetch", run)
            .tags([Tag::Fetch, Tag::Plugin])
            .needs([Fixture::Conformance])
            .timeout(Duration::from_secs(30))
    };
    vec![
        with_plugin("fetch/prefetch-then-carry-traffic", || {
            boxed(prefetch_then_carry_traffic())
        }),
        with_plugin("fetch/start-downloads-what-was-not-prefetched", || {
            boxed(start_downloads_what_was_not_prefetched())
        }),
        with_plugin("fetch/a-url-without-an-extension-loads", || {
            boxed(a_url_without_an_extension_loads())
        }),
        with_plugin("fetch/reload-uses-the-cache-only", || {
            boxed(reload_uses_the_cache_only())
        }),
        with_plugin("fetch/outbound-test-uses-the-cache-only", || {
            boxed(outbound_test_uses_the_cache_only())
        }),
        plain("fetch/start-fails-when-a-download-fails", || {
            boxed(start_fails_when_a_download_fails())
        }),
        plain("fetch/start-requires-a-cache-directory", || {
            boxed(start_requires_a_cache_directory())
        }),
        plain("fetch/cache-hit-needs-no-network", || {
            boxed(cache_hit_needs_no_network())
        }),
        plain("fetch/events/parallel-with-a-cached-plugin", || {
            boxed(parallel_with_a_cached_plugin())
        }),
        plain("fetch/events/unknown-size", || boxed(unknown_size())),
        plain("fetch/one-download-per-digest", || {
            boxed(one_download_per_digest())
        }),
        plain("fetch/rejects-a-digest-mismatch", || {
            boxed(rejects_a_digest_mismatch())
        }),
        plain("fetch/rejects-a-size-the-server-contradicts", || {
            boxed(rejects_a_size_the_server_contradicts())
        }),
        plain("fetch/stops-at-the-declared-size", || {
            boxed(stops_at_the_declared_size())
        }),
        plain("fetch/partial-failure-keeps-the-rest", || {
            boxed(partial_failure_keeps_the_rest())
        }),
        plain("fetch/cancel-mid-download", || boxed(cancel_mid_download())),
        plain("fetch/times-out-on-a-stalled-server", || {
            boxed(times_out_on_a_stalled_server())
        }),
        plain("fetch/refuses-insecure-configs", || {
            boxed(refuses_insecure_configs())
        }),
        plain("fetch/refuses-a-redirect-to-http", || {
            boxed(refuses_a_redirect_to_http())
        }),
        plain("fetch/follows-an-https-redirect", || {
            boxed(follows_an_https_redirect())
        }),
        plain("fetch/refuses-an-untrusted-server", || {
            boxed(refuses_an_untrusted_server())
        }),
        plain("fetch/concurrent-prefetches-share-a-cache", || {
            boxed(concurrent_prefetches_share_a_cache())
        }),
        plain("fetch/respects-the-concurrency-limit", || {
            boxed(respects_the_concurrency_limit())
        }),
    ]
}

// ---------------------------------------------------------------------------
// What a prefetch reported, and the contract it has to keep.

#[derive(Clone, Debug)]
struct Seen {
    kind: FetchEventKind,
    index: usize,
    count: usize,
    plugin: String,
    downloaded: u64,
    total: Option<u64>,
    all_downloaded: u64,
    all_total: Option<u64>,
    error: Option<String>,
    on_caller_thread: bool,
}

struct Outcome {
    result: Result<(), FetchError>,
    events: Vec<Seen>,
    elapsed: Duration,
}

impl Outcome {
    fn kinds(&self, index: usize) -> Vec<FetchEventKind> {
        self.events
            .iter()
            .filter(|e| e.index == index)
            .map(|e| e.kind)
            .collect()
    }

    fn failures(&self) -> Result<Vec<(String, String)>> {
        match &self.result {
            Err(FetchError::Failed(failures)) => Ok(failures
                .iter()
                .map(|f| (f.plugin.clone(), f.reason.clone()))
                .collect()),
            other => bail!("expected some downloads to fail, got {:?}", other),
        }
    }

    fn succeeded(&self) -> Result<()> {
        match &self.result {
            Ok(()) => Ok(()),
            Err(err) => bail!("prefetch failed: {}; events: {:#?}", err, self.events),
        }
    }
}

/// Runs a prefetch on a blocking thread, as an app would, so that the case's
/// runtime -- and the server on it -- keeps going meanwhile. `answer` decides
/// what the callback returns.
async fn prefetch(
    conf: &str,
    options: FetchOptions,
    mut answer: impl FnMut(&Seen) -> bool + Send + 'static,
) -> Result<Outcome> {
    let config = leaf::config::from_string(conf).map_err(|e| anyhow!("bad conf: {:#}", e))?;
    tokio::task::spawn_blocking(move || {
        let caller = std::thread::current().id();
        let mut events = Vec::new();
        let started = Instant::now();
        let result = plugin_fetch::prefetch(&config, &options, &mut |event| {
            let seen = Seen {
                kind: event.kind,
                index: event.index,
                count: event.count,
                plugin: event.plugin.to_string(),
                downloaded: event.downloaded,
                total: event.total,
                all_downloaded: event.all_downloaded,
                all_total: event.all_total,
                error: event.error.map(str::to_string),
                on_caller_thread: std::thread::current().id() == caller,
            };
            let keep_going = answer(&seen);
            events.push(seen);
            keep_going
        });
        Outcome {
            result,
            events,
            elapsed: started.elapsed(),
        }
    })
    .await
    .context("the prefetch thread panicked")
}

/// Where each plugin can be in its events.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Stage {
    Unannounced,
    Queued,
    Started,
    Finished,
}

/// The promise [`plugin_fetch::prefetch`] makes to whoever builds a UI on it.
/// A cancelled prefetch keeps all of it except that plugins may be left
/// unfinished.
fn check_contract(events: &[Seen], count: usize, cancelled: bool) -> Result<()> {
    let describe = || format!("{:#?}", events);
    ensure!(
        events.iter().all(|e| e.count == count && e.index < count),
        "every event must say count={} and carry an index below it: {}",
        count,
        describe()
    );
    ensure!(
        events.iter().all(|e| e.on_caller_thread),
        "a callback ran on a thread other than the caller's: {}",
        describe()
    );

    // Every plugin announced, in order, before anything else.
    let announced = count.min(events.len());
    ensure!(
        cancelled || announced == count,
        "only {} of {} plugins were announced: {}",
        announced,
        count,
        describe()
    );
    for (position, event) in events[..announced].iter().enumerate() {
        ensure!(
            matches!(event.kind, FetchEventKind::Queued | FetchEventKind::Cached)
                && event.index == position,
            "event {} should announce plugin {}: {}",
            position,
            position,
            describe()
        );
    }

    for event in events {
        ensure!(
            event.plugin == events[event.index].plugin,
            "plugin {} changed its name: {}",
            event.index,
            describe()
        );
    }

    let mut stages = vec![Stage::Unannounced; count];
    let mut downloaded = vec![0u64; count];
    let mut all_downloaded = 0u64;
    for event in events {
        let stage = &mut stages[event.index];
        *stage = match (*stage, event.kind) {
            (Stage::Unannounced, FetchEventKind::Queued) => Stage::Queued,
            (Stage::Unannounced, FetchEventKind::Cached) => Stage::Finished,
            // The heartbeat: a download still connecting is reported too,
            // so that it can be cancelled before the server answers.
            (Stage::Queued, FetchEventKind::Progress) => Stage::Queued,
            (Stage::Queued, FetchEventKind::Started) => Stage::Started,
            (Stage::Queued, FetchEventKind::Failed) => Stage::Finished,
            (Stage::Started, FetchEventKind::Progress) => Stage::Started,
            (Stage::Started, FetchEventKind::Done | FetchEventKind::Failed) => Stage::Finished,
            (from, kind) => bail!(
                "plugin {} went from {:?} on {:?}: {}",
                event.index,
                from,
                kind,
                describe()
            ),
        };
        ensure!(
            event.downloaded >= downloaded[event.index],
            "plugin {}'s download count went backwards: {}",
            event.index,
            describe()
        );
        downloaded[event.index] = event.downloaded;
        ensure!(
            event.all_downloaded >= all_downloaded,
            "the overall download count went backwards: {}",
            describe()
        );
        all_downloaded = event.all_downloaded;
        ensure!(
            (event.kind == FetchEventKind::Failed) == event.error.is_some(),
            "an error comes with FAILED and only with FAILED: {}",
            describe()
        );
        if event.kind == FetchEventKind::Done {
            if let Some(total) = event.total {
                ensure!(
                    event.downloaded == total,
                    "plugin {} finished at {} of {} bytes: {}",
                    event.index,
                    event.downloaded,
                    total,
                    describe()
                );
            }
        }
    }
    if !cancelled {
        ensure!(
            stages.iter().all(|s| *s == Stage::Finished),
            "a plugin was left without a terminal event: {:?}: {}",
            stages,
            describe()
        );
        let all_fine = events.iter().all(|e| e.kind != FetchEventKind::Failed);
        if let Some(last) = events.last() {
            if let (true, Some(all_total)) = (all_fine, last.all_total) {
                ensure!(
                    last.all_downloaded == all_total,
                    "everything finished at {} of {} bytes overall: {}",
                    last.all_downloaded,
                    all_total,
                    describe()
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Configs, caches and files.

fn sha256(bytes: &[u8]) -> String {
    flow::hex(&Sha256::digest(bytes))
}

fn plugin_line(name: &str, url: &str, sha: &str, size: Option<u64>) -> String {
    let mut line = format!("{} = url={}, sha256={}", name, url, sha);
    if let Some(size) = size {
        line.push_str(&format!(", size={}", size));
    }
    line
}

/// A conf that does nothing but name `plugins`: one proxy per plugin, which is
/// all a prefetch looks at.
fn prefetch_conf(plugins: &[String]) -> String {
    let proxies: Vec<String> = plugins
        .iter()
        .map(|line| {
            let name = line.split('=').next().unwrap_or_default().trim();
            format!("P-{} = plugin, plugin={}", name, name)
        })
        .collect();
    format!(
        "[Plugin]\n{}\n[Proxy]\n{}\n",
        plugins.join("\n"),
        proxies.join("\n")
    )
}

/// A conf a client could run: a socks inbound, one plugin relaying to
/// `origin`, and every connection through it.
fn relay_conf(socks_port: u16, plugin: &str, origin: std::net::SocketAddr) -> String {
    format!(
        "[General]\nloglevel = trace\nsocks-interface = 127.0.0.1\nsocks-port = {}\n\n\
         [Plugin]\n{}\n\n\
         [Proxy]\nRelay = plugin, {}, {}, plugin=relay\n\n\
         [Rule]\nFINAL, Relay\n",
        socks_port,
        plugin,
        origin.ip(),
        origin.port()
    )
}

/// An empty cache directory of this case's own, kept with its artifacts so a
/// failure leaves the evidence behind.
fn fresh_cache(label: &str) -> Result<PathBuf> {
    let case = crate::report::case().unwrap_or_else(|| "in-process".to_string());
    let dir = paths::artifacts_dir()?
        .join(paths::artifact_slug(&case))
        .join(format!("plugin-cache-{}", label));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

fn scaled(duration: Duration) -> Duration {
    duration.mul_f64(crate::runner::timeout_scale())
}

/// Options that trust `server`, and nothing else beyond the public roots.
fn trusting(server: &PluginServer, cache: &Path) -> FetchOptions {
    let mut options = FetchOptions::new(cache);
    options.extra_roots = vec![server.ca()];
    options.timeout = Some(scaled(Duration::from_secs(20)));
    options
}

fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// A failure has to cost a clear error and never a file: nothing half-written
/// and nothing unverified may be left where the host could load it.
fn ensure_nothing_in(cache: &Path) -> Result<()> {
    let files = files_in(cache);
    ensure!(
        files.is_empty(),
        "the cache should hold nothing, and holds {:?}",
        files
    );
    Ok(())
}

fn ensure_cached(cache: &Path, sha: &str) -> Result<PathBuf> {
    let files = files_in(&cache.join(sha));
    ensure!(
        files.len() == 1,
        "expected one file under {}, found {:?}",
        sha,
        files
    );
    let bytes = std::fs::read(&files[0])?;
    ensure!(
        sha256(&bytes) == sha,
        "the cached file is not the pinned one"
    );
    Ok(files[0].clone())
}

fn conformance_bytes() -> Result<(Vec<u8>, String)> {
    let path = Fixture::Conformance.path()?;
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("unnamed fixture"))?
        .to_string();
    Ok((bytes, name))
}

async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) -> Result<()> {
    let deadline = Instant::now() + scaled(Duration::from_secs(10));
    while !condition() {
        if Instant::now() >= deadline {
            bail!("gave up waiting until {}", what);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// With a real plugin: the file that was fetched is the file that runs.

/// The flow a client follows: prefetch with progress, then start, and the
/// start finds everything in the cache and loads the plugin from there.
async fn prefetch_then_carry_traffic() -> Result<()> {
    let server = PluginServer::start().await?;
    let (bytes, name) = conformance_bytes()?;
    let sha = sha256(&bytes);
    let path = format!("/plugins/{}", name);
    server.route(&path, Route::ok(bytes.clone()));
    let cache = fresh_cache("main")?;
    let origin = Origin::tcp_echo().await?;
    let socks_port = net::reserve_dual_port()?;
    let conf = relay_conf(
        socks_port,
        &plugin_line("relay", &server.url(&path), &sha, Some(bytes.len() as u64)),
        origin.addr(),
    );

    let outcome = prefetch(&conf, trusting(&server, &cache), |_| true).await?;
    outcome.succeeded()?;
    check_contract(&outcome.events, 1, false)?;
    ensure!(
        outcome.events[0].total == Some(bytes.len() as u64)
            && outcome.events[0].all_total == Some(bytes.len() as u64),
        "the declared size should be known from the first event: {:?}",
        outcome.events[0]
    );
    let cached = ensure_cached(&cache, &sha)?;
    ensure!(
        cached.file_name().and_then(|n| n.to_str()) == Some(name.as_str()),
        "the cached file should keep the url's name, got {}",
        cached.display()
    );

    plugin_fetch::set_default_options(Some(trusting(&server, &cache)));
    let node = Node::start_conf("client", &conf, socks_port).await?;
    ensure!(
        server.requests(&path) == 1,
        "the start downloaded again instead of using the cache"
    );
    let mut stream = Socks5::new(node.socks_addr()?)
        .connect(origin.addr())
        .await?;
    flow::echo_roundtrip(&mut stream, b"through a downloaded plugin").await?;
    drop(stream);
    node.shutdown().await
}

/// An app that skips the prefetch still starts: the start downloads what is
/// missing itself, and then runs it.
async fn start_downloads_what_was_not_prefetched() -> Result<()> {
    let server = PluginServer::start().await?;
    let (bytes, name) = conformance_bytes()?;
    let sha = sha256(&bytes);
    let path = format!("/plugins/{}", name);
    server.route(&path, Route::ok(bytes));
    let cache = fresh_cache("main")?;
    let origin = Origin::tcp_echo().await?;
    let socks_port = net::reserve_dual_port()?;
    let conf = relay_conf(
        socks_port,
        &plugin_line("relay", &server.url(&path), &sha, None),
        origin.addr(),
    );

    plugin_fetch::set_default_options(Some(trusting(&server, &cache)));
    let node = Node::start_conf("client", &conf, socks_port).await?;
    ensure!(server.requests(&path) == 1, "expected exactly one download");
    ensure_cached(&cache, &sha)?;
    let mut stream = Socks5::new(node.socks_addr()?)
        .connect(origin.addr())
        .await?;
    flow::echo_roundtrip(&mut stream, b"hello").await?;
    drop(stream);
    node.shutdown().await
}

/// A url whose last segment has no extension -- a release download, a `get`
/// endpoint -- still gives a file the platform's loader will open.
async fn a_url_without_an_extension_loads() -> Result<()> {
    let server = PluginServer::start().await?;
    let (bytes, _) = conformance_bytes()?;
    let sha = sha256(&bytes);
    let path = "/releases/download/v1/relay";
    server.route(path, Route::ok(bytes));
    let cache = fresh_cache("main")?;
    let origin = Origin::tcp_echo().await?;
    let socks_port = net::reserve_dual_port()?;
    let conf = relay_conf(
        socks_port,
        &plugin_line("relay", &server.url(path), &sha, None),
        origin.addr(),
    );

    plugin_fetch::set_default_options(Some(trusting(&server, &cache)));
    let node = Node::start_conf("client", &conf, socks_port).await?;
    let cached = ensure_cached(&cache, &sha)?;
    let expected = format!("relay{}", std::env::consts::DLL_SUFFIX);
    ensure!(
        cached.file_name().and_then(|n| n.to_str()) == Some(expected.as_str()),
        "the cached file should be named {}, got {}",
        expected,
        cached.display()
    );
    let mut stream = Socks5::new(node.socks_addr()?)
        .connect(origin.addr())
        .await?;
    flow::echo_roundtrip(&mut stream, b"hello").await?;
    drop(stream);
    node.shutdown().await
}

/// A reload never downloads. With the plugin unchanged it goes through from
/// the cache; with a plugin the cache has never seen it is refused, says a
/// restart is needed, and leaves the running config as it was.
async fn reload_uses_the_cache_only() -> Result<()> {
    let server = PluginServer::start().await?;
    let (bytes, name) = conformance_bytes()?;
    let sha = sha256(&bytes);
    let path = format!("/plugins/{}", name);
    server.route(&path, Route::ok(bytes.clone()));
    let other = flow::pseudo_random(4096, 7);
    server.route("/plugins/other.dll", Route::ok(other.clone()));
    let cache = fresh_cache("main")?;
    let origin = Origin::tcp_echo().await?;

    let outbound = |url: &str, sha: &str| {
        json!({
            "protocol": "plugin",
            "tag": "relay",
            "settings": {
                "url": url,
                "sha256": sha,
                "name": "relay",
                "host": origin.addr().ip().to_string(),
                "port": origin.addr().port(),
            },
        })
    };
    // One socks port for every version of the config: a reload keeps the
    // inbounds it started with, and the file should say so too.
    let socks_port = net::reserve_dual_port()?;
    let node_config = |url: &str, sha: &str| {
        Node::new("client")
            .inbound(cfg::socks_inbound("socks-in", socks_port))
            .outbound(outbound(url, sha))
    };

    plugin_fetch::set_default_options(Some(trusting(&server, &cache)));
    let node = node_config(&server.url(&path), &sha)
        .start_reloadable()
        .await?;
    ensure!(
        server.requests(&path) == 1,
        "the start should download once"
    );

    // Same plugin: from the cache, no request.
    node.reload_to(&node_config(&server.url(&path), &sha))
        .await
        .map_err(|e| anyhow!("an unchanged plugin should reload from the cache: {:#}", e))?;
    ensure!(server.requests(&path) == 1, "the reload downloaded");

    // A plugin the cache does not have: refused, and nothing fetched.
    let refused = node
        .reload_to(&node_config(
            &server.url("/plugins/other.dll"),
            &sha256(&other),
        ))
        .await;
    let message = match refused {
        Ok(()) => bail!("a reload that needs a new plugin should have been refused"),
        Err(err) => format!("{:#}", err),
    };
    ensure!(
        message.contains("requires a restart"),
        "unexpected error: {}",
        message
    );
    ensure!(
        server.requests("/plugins/other.dll") == 0,
        "the reload downloaded"
    );

    let mut stream = Socks5::new(net::loopback(socks_port))
        .connect(origin.addr())
        .await?;
    flow::echo_roundtrip(&mut stream, b"still the old config").await?;
    drop(stream);
    node.shutdown().await
}

/// Testing an outbound never downloads, but reads the cache: it fails, saying
/// so, until the plugin is there, and a file put there by hand is as good as
/// a downloaded one.
async fn outbound_test_uses_the_cache_only() -> Result<()> {
    let server = PluginServer::start().await?;
    let (bytes, name) = conformance_bytes()?;
    let sha = sha256(&bytes);
    let path = format!("/plugins/{}", name);
    server.route(&path, Route::ok(bytes.clone()));
    let cache = fresh_cache("main")?;
    let origin = Origin::tcp_echo().await?;
    let conf = relay_conf(
        net::reserve_dual_port()?,
        &plugin_line("relay", &server.url(&path), &sha, None),
        origin.addr(),
    );
    let config = leaf::config::from_string(&conf)?;
    plugin_fetch::set_default_options(Some(trusting(&server, &cache)));

    let message = match leaf::util::test_outbound("Relay", &config, None).await {
        Ok(_) => bail!("testing a plugin the cache does not have should fail"),
        Err(err) => format!("{:#}", err),
    };
    ensure!(
        message.contains("does not download plugins"),
        "unexpected error: {}",
        message
    );
    ensure!(server.requests(&path) == 0, "the test downloaded");

    // What a manual download leaves: the file at the place the cache names.
    std::fs::create_dir_all(cache.join(&sha))?;
    std::fs::write(cache.join(&sha).join(&name), &bytes)?;
    // What the test then reaches is not the point here, only that it gets
    // as far as trying.
    let _ = leaf::util::test_outbound("Relay", &config, None)
        .await
        .map_err(|e| anyhow!("a cached plugin should build for a test: {:#}", e))?;
    ensure!(server.requests(&path) == 0, "the test downloaded");
    Ok(())
}

// ---------------------------------------------------------------------------
// Starts that cannot get their plugins.

async fn start_fails_when_a_download_fails() -> Result<()> {
    let server = PluginServer::start().await?;
    server.route("/plugins/gone.dll", Route::status(404));
    let cache = fresh_cache("main")?;
    let conf = relay_conf(
        net::reserve_dual_port()?,
        &plugin_line(
            "relay",
            &server.url("/plugins/gone.dll"),
            &sha256(b"x"),
            None,
        ),
        net::loopback(9),
    );
    plugin_fetch::set_default_options(Some(trusting(&server, &cache)));
    let error = Node::start_conf_expecting_failure("client", &conf).await?;
    ensure!(
        error.contains("plugin [relay]") && error.contains("HTTP 404"),
        "the error should name the plugin and the reason: {}",
        error
    );
    ensure_nothing_in(&cache)
}

/// There is no default cache: where code may be loaded from is the app's call.
async fn start_requires_a_cache_directory() -> Result<()> {
    let server = PluginServer::start().await?;
    plugin_fetch::set_default_options(None);
    std::env::remove_var(plugin_fetch::ENV_CACHE_DIR);
    let conf = relay_conf(
        net::reserve_dual_port()?,
        &plugin_line("relay", &server.url("/p.dll"), &sha256(b"x"), None),
        net::loopback(9),
    );
    let error = Node::start_conf_expecting_failure("client", &conf).await?;
    ensure!(
        error.contains(plugin_fetch::ENV_CACHE_DIR),
        "the error should say what to set: {}",
        error
    );
    ensure!(server.total_requests() == 0, "nothing should be requested");
    Ok(())
}

// ---------------------------------------------------------------------------
// Prefetch: the cache, and the events.

async fn cache_hit_needs_no_network() -> Result<()> {
    let server = PluginServer::start().await?;
    let body = flow::pseudo_random(100_000, 1);
    let sha = sha256(&body);
    server.route("/p.dll", Route::ok(body));
    let cache = fresh_cache("main")?;
    let conf = prefetch_conf(&[plugin_line("p", &server.url("/p.dll"), &sha, None)]);
    let options = trusting(&server, &cache);

    prefetch(&conf, options.clone(), |_| true)
        .await?
        .succeeded()?;
    drop(server);

    let again = prefetch(&conf, options, |_| true).await?;
    again.succeeded()?;
    check_contract(&again.events, 1, false)?;
    ensure!(
        again.kinds(0) == [FetchEventKind::Cached],
        "a second prefetch should only report the cache: {:?}",
        again.events
    );
    Ok(())
}

/// One cached plugin and two downloads running side by side: the list and the
/// overall total are there from the first events, and add up at the end.
async fn parallel_with_a_cached_plugin() -> Result<()> {
    let server = PluginServer::start().await?;
    let cache = fresh_cache("main")?;
    let cached = flow::pseudo_random(10_000, 1);
    let small = flow::pseudo_random(300_000, 2);
    let large = flow::pseudo_random(1_000_000, 3);
    std::fs::create_dir_all(cache.join(sha256(&cached)))?;
    std::fs::write(cache.join(sha256(&cached)).join("cached.dll"), &cached)?;
    server.route("/small.dll", Route::ok(small.clone()));
    server.route("/large.dll", Route::ok(large.clone()));
    let conf = prefetch_conf(&[
        plugin_line("cached", &server.url("/cached.dll"), &sha256(&cached), None),
        plugin_line(
            "small",
            &server.url("/small.dll"),
            &sha256(&small),
            Some(300_000),
        ),
        plugin_line(
            "large",
            &server.url("/large.dll"),
            &sha256(&large),
            Some(1_000_000),
        ),
    ]);

    let outcome = prefetch(&conf, trusting(&server, &cache), |_| true).await?;
    outcome.succeeded()?;
    check_contract(&outcome.events, 3, false)?;
    let first: Vec<_> = outcome.events[..3].iter().map(|e| e.kind).collect();
    ensure!(
        first
            == [
                FetchEventKind::Cached,
                FetchEventKind::Queued,
                FetchEventKind::Queued
            ],
        "unexpected announcements: {:?}",
        first
    );
    ensure!(
        outcome.events[..3]
            .iter()
            .all(|e| e.all_total == Some(1_300_000)),
        "the overall total should be known before any download: {:?}",
        &outcome.events[..3]
    );
    ensure!(
        server.requests("/cached.dll") == 0,
        "a cached plugin was requested"
    );
    ensure_cached(&cache, &sha256(&small))?;
    ensure_cached(&cache, &sha256(&large))?;
    Ok(())
}

async fn unknown_size() -> Result<()> {
    let server = PluginServer::start().await?;
    let body = flow::pseudo_random(200_000, 4);
    server.route("/p.dll", Route::ok(body.clone()).length(Length::Chunked));
    let cache = fresh_cache("main")?;
    let conf = prefetch_conf(&[plugin_line(
        "p",
        &server.url("/p.dll"),
        &sha256(&body),
        None,
    )]);

    let outcome = prefetch(&conf, trusting(&server, &cache), |_| true).await?;
    outcome.succeeded()?;
    check_contract(&outcome.events, 1, false)?;
    ensure!(
        outcome
            .events
            .iter()
            .all(|e| e.total.is_none() && e.all_total.is_none()),
        "no size was declared or announced, so none should be reported: {:?}",
        outcome.events
    );
    let done = outcome.events.last().unwrap();
    ensure!(
        done.kind == FetchEventKind::Done && done.downloaded == body.len() as u64,
        "{:?}",
        done
    );
    ensure_cached(&cache, &sha256(&body))?;
    Ok(())
}

/// Two names for one digest, used by three proxies, are one file.
async fn one_download_per_digest() -> Result<()> {
    let server = PluginServer::start().await?;
    let body = flow::pseudo_random(50_000, 5);
    let sha = sha256(&body);
    server.route("/p.dll", Route::ok(body));
    let cache = fresh_cache("main")?;
    let conf = format!(
        "[Plugin]\n{}\n{}\n[Proxy]\nA = plugin, plugin=a\nB = plugin, plugin=b\nC = plugin, plugin=a\n",
        plugin_line("a", &server.url("/p.dll"), &sha, None),
        plugin_line("b", &server.url("/p.dll"), &sha.to_ascii_uppercase(), None),
    );

    let outcome = prefetch(&conf, trusting(&server, &cache), |_| true).await?;
    outcome.succeeded()?;
    check_contract(&outcome.events, 1, false)?;
    ensure!(server.requests("/p.dll") == 1, "downloaded more than once");

    let mut config = leaf::config::from_string(&conf).map_err(|e| anyhow!("{:#}", e))?;
    plugin_fetch::resolve_from_cache(&mut config, &cache)?;
    ensure!(
        !plugin_fetch::has_url_plugins(&config)?,
        "every outbound should now have its path"
    );
    ensure!(files_in(&cache).len() == 1, "{:?}", files_in(&cache));
    Ok(())
}

// ---------------------------------------------------------------------------
// Servers that send the wrong thing.

async fn rejects_a_digest_mismatch() -> Result<()> {
    let server = PluginServer::start().await?;
    server.route("/p.dll", Route::ok(b"not what was pinned".to_vec()));
    let cache = fresh_cache("main")?;
    let conf = prefetch_conf(&[plugin_line(
        "p",
        &server.url("/p.dll"),
        &sha256(b"the pinned file"),
        None,
    )]);

    let outcome = prefetch(&conf, trusting(&server, &cache), |_| true).await?;
    check_contract(&outcome.events, 1, false)?;
    let failures = outcome.failures()?;
    ensure!(
        failures.len() == 1 && failures[0].1.contains("sha256 mismatch"),
        "{:?}",
        failures
    );
    ensure_nothing_in(&cache)
}

/// A server that announces a size other than the one the config declared is
/// refused before any of the body is read.
async fn rejects_a_size_the_server_contradicts() -> Result<()> {
    let server = PluginServer::start().await?;
    let body = flow::pseudo_random(10_000, 6);
    server.route(
        "/p.dll",
        Route::ok(body.clone()).length(Length::Claim(20_000)),
    );
    let cache = fresh_cache("main")?;
    let conf = prefetch_conf(&[plugin_line(
        "p",
        &server.url("/p.dll"),
        &sha256(&body),
        Some(10_000),
    )]);

    let outcome = prefetch(&conf, trusting(&server, &cache), |_| true).await?;
    check_contract(&outcome.events, 1, false)?;
    let failures = outcome.failures()?;
    ensure!(
        failures[0]
            .1
            .contains("the server says the file is 20000 bytes"),
        "{:?}",
        failures
    );
    ensure!(
        outcome.kinds(0) == [FetchEventKind::Queued, FetchEventKind::Failed],
        "nothing should have started: {:?}",
        outcome.events
    );
    ensure_nothing_in(&cache)
}

/// A body that keeps coming past the declared size is cut off there, rather
/// than filling the disk.
async fn stops_at_the_declared_size() -> Result<()> {
    let server = PluginServer::start().await?;
    let body = flow::pseudo_random(4 * 1024 * 1024, 7);
    server.route("/p.dll", Route::ok(body).length(Length::Chunked));
    let cache = fresh_cache("main")?;
    let declared = 64 * 1024u64;
    let conf = prefetch_conf(&[plugin_line(
        "p",
        &server.url("/p.dll"),
        &sha256(b"whatever"),
        Some(declared),
    )]);

    let outcome = prefetch(&conf, trusting(&server, &cache), |_| true).await?;
    check_contract(&outcome.events, 1, false)?;
    let failures = outcome.failures()?;
    ensure!(failures[0].1.contains("ran past"), "{:?}", failures);
    ensure!(
        outcome.events.iter().all(|e| e.downloaded <= declared),
        "a download was reported past its declared size: {:?}",
        outcome.events
    );
    ensure_nothing_in(&cache)
}

async fn partial_failure_keeps_the_rest() -> Result<()> {
    let server = PluginServer::start().await?;
    let good = flow::pseudo_random(100_000, 8);
    server.route("/good.dll", Route::ok(good.clone()));
    server.route("/bad.dll", Route::status(500));
    let cache = fresh_cache("main")?;
    let conf = prefetch_conf(&[
        plugin_line("good", &server.url("/good.dll"), &sha256(&good), None),
        plugin_line("bad", &server.url("/bad.dll"), &sha256(b"x"), None),
    ]);

    let outcome = prefetch(&conf, trusting(&server, &cache), |_| true).await?;
    check_contract(&outcome.events, 2, false)?;
    let failures = outcome.failures()?;
    ensure!(
        failures.len() == 1 && failures[0].0 == "bad" && failures[0].1.contains("HTTP 500"),
        "{:?}",
        failures
    );
    ensure_cached(&cache, &sha256(&good))?;
    ensure!(files_in(&cache).len() == 1, "{:?}", files_in(&cache));
    Ok(())
}

// ---------------------------------------------------------------------------
// Stopping: by the app, and by the clock.

/// The app cancels while a download is provably in flight: the prefetch ends
/// at once, says so, reports nothing further, and leaves nothing behind.
async fn cancel_mid_download() -> Result<()> {
    let server = PluginServer::start().await?;
    let body = flow::pseudo_random(1024 * 1024, 9);
    // Held after a quarter, and never let go: the download cannot finish, so
    // it is still running whenever the callback is asked.
    server.route(
        "/p.dll",
        Route::ok(body.clone()).gate(Gate::after(256 * 1024)),
    );
    let cache = fresh_cache("main")?;
    let conf = prefetch_conf(&[plugin_line(
        "p",
        &server.url("/p.dll"),
        &sha256(&body),
        None,
    )]);

    let outcome = prefetch(&conf, trusting(&server, &cache), |event| {
        event.kind != FetchEventKind::Progress
    })
    .await?;
    ensure!(
        matches!(outcome.result, Err(FetchError::Cancelled)),
        "expected a cancel, got {:?}",
        outcome.result
    );
    check_contract(&outcome.events, 1, true)?;
    ensure!(
        outcome.events.last().map(|e| e.kind) == Some(FetchEventKind::Progress),
        "nothing may be reported after the callback cancels: {:?}",
        outcome.events
    );
    ensure_nothing_in(&cache)
}

/// A server that answers and then sends nothing: the heartbeat keeps the
/// callback informed, and the timeout ends it with a failure for that plugin.
async fn times_out_on_a_stalled_server() -> Result<()> {
    let server = PluginServer::start().await?;
    let body = flow::pseudo_random(100_000, 10);
    server.route("/p.dll", Route::ok(body.clone()).gate(Gate::after(0)));
    let cache = fresh_cache("main")?;
    let conf = prefetch_conf(&[plugin_line(
        "p",
        &server.url("/p.dll"),
        &sha256(&body),
        None,
    )]);
    let mut options = trusting(&server, &cache);
    let timeout = Duration::from_millis(2500);
    options.timeout = Some(timeout);

    let outcome = prefetch(&conf, options, |_| true).await?;
    check_contract(&outcome.events, 1, false)?;
    let failures = outcome.failures()?;
    ensure!(failures[0].1.contains("timed out"), "{:?}", failures);
    ensure!(
        outcome.elapsed < timeout + scaled(Duration::from_secs(5)),
        "took {:?} to time out after {:?}",
        outcome.elapsed,
        timeout
    );
    ensure!(
        outcome
            .events
            .iter()
            .any(|e| e.kind == FetchEventKind::Progress && e.downloaded == 0),
        "a stalled download should still be reported, so an app can cancel it: {:?}",
        outcome.events
    );
    ensure_nothing_in(&cache)
}

// ---------------------------------------------------------------------------
// What will not be fetched at all.

async fn refuses_insecure_configs() -> Result<()> {
    let server = PluginServer::start().await?;
    let cache = fresh_cache("main")?;
    let sha = sha256(b"x");
    for (line, expected) in [
        (
            plugin_line(
                "p",
                &server.url("/p.dll").replace("https", "http"),
                &sha,
                None,
            ),
            "is not https",
        ),
        (
            format!("p = url={}", server.url("/p.dll")),
            "pinned with sha256",
        ),
        (
            plugin_line("p", &server.url("/p.dll"), "1234", None),
            "not 64 hex digits",
        ),
    ] {
        let outcome = prefetch(
            &prefetch_conf(std::slice::from_ref(&line)),
            trusting(&server, &cache),
            |_| true,
        )
        .await?;
        match &outcome.result {
            Err(FetchError::Config(err)) if err.to_string().contains(expected) => {}
            other => bail!(
                "[{}]: expected a config error about [{}], got {:?}",
                line,
                expected,
                other
            ),
        }
        ensure!(outcome.events.is_empty(), "[{}] produced events", line);
    }
    ensure!(server.total_requests() == 0, "something was requested");
    ensure_nothing_in(&cache)
}

async fn refuses_a_redirect_to_http() -> Result<()> {
    let server = PluginServer::start().await?;
    let insecure = server.url("/p2.dll").replace("https", "http");
    server.route("/p.dll", Route::redirect(insecure));
    let cache = fresh_cache("main")?;
    let conf = prefetch_conf(&[plugin_line("p", &server.url("/p.dll"), &sha256(b"x"), None)]);

    let outcome = prefetch(&conf, trusting(&server, &cache), |_| true).await?;
    check_contract(&outcome.events, 1, false)?;
    let failures = outcome.failures()?;
    ensure!(
        failures[0].1.contains("which is not https"),
        "{:?}",
        failures
    );
    ensure_nothing_in(&cache)
}

async fn follows_an_https_redirect() -> Result<()> {
    let server = PluginServer::start().await?;
    let body = flow::pseudo_random(20_000, 11);
    server.route("/old.dll", Route::redirect(server.url("/new.dll")));
    server.route("/new.dll", Route::ok(body.clone()));
    let cache = fresh_cache("main")?;
    let conf = prefetch_conf(&[plugin_line(
        "p",
        &server.url("/old.dll"),
        &sha256(&body),
        None,
    )]);

    let outcome = prefetch(&conf, trusting(&server, &cache), |_| true).await?;
    outcome.succeeded()?;
    check_contract(&outcome.events, 1, false)?;
    ensure!(
        server.requests("/new.dll") == 1,
        "the redirect was not followed"
    );
    // Cached under the url the config gave, not the one it was redirected to.
    ensure!(
        cache.join(sha256(&body)).join("old.dll").is_file(),
        "{:?}",
        files_in(&cache)
    );
    Ok(())
}

/// Without being told to trust the server's CA, the client must refuse it --
/// which is what shows that the cases above trust it only because they said so.
async fn refuses_an_untrusted_server() -> Result<()> {
    let server = PluginServer::start().await?;
    server.route("/p.dll", Route::ok(b"x".to_vec()));
    let cache = fresh_cache("main")?;
    let conf = prefetch_conf(&[plugin_line("p", &server.url("/p.dll"), &sha256(b"x"), None)]);
    let mut options = FetchOptions::new(&cache);
    options.timeout = Some(scaled(Duration::from_secs(20)));

    let outcome = prefetch(&conf, options, |_| true).await?;
    check_contract(&outcome.events, 1, false)?;
    let failures = outcome.failures()?;
    ensure!(failures[0].1.contains("TLS handshake"), "{:?}", failures);
    ensure!(server.requests("/p.dll") == 0, "a request got through");
    ensure_nothing_in(&cache)
}

// ---------------------------------------------------------------------------
// Concurrency.

/// Two prefetches into one cache at once -- the app's and a start's, say --
/// both succeed, and leave one whole file.
async fn concurrent_prefetches_share_a_cache() -> Result<()> {
    let server = PluginServer::start().await?;
    let body = flow::pseudo_random(1024 * 1024, 12);
    let gate = Gate::after(0);
    server.route("/p.dll", Route::ok(body.clone()).gate(gate.clone()));
    let cache = fresh_cache("main")?;
    let conf = prefetch_conf(&[plugin_line(
        "p",
        &server.url("/p.dll"),
        &sha256(&body),
        None,
    )]);

    let first = tokio::spawn({
        let (conf, options) = (conf.clone(), trusting(&server, &cache));
        async move { prefetch(&conf, options, |_| true).await }
    });
    let second = tokio::spawn({
        let (conf, options) = (conf.clone(), trusting(&server, &cache));
        async move { prefetch(&conf, options, |_| true).await }
    });
    // Both in flight before either can finish.
    wait_until("both prefetches have asked", || {
        server.requests("/p.dll") == 2
    })
    .await?;
    gate.open();

    for outcome in [first.await??, second.await??] {
        outcome.succeeded()?;
        check_contract(&outcome.events, 1, false)?;
    }
    ensure_cached(&cache, &sha256(&body))?;
    ensure!(files_in(&cache).len() == 1, "{:?}", files_in(&cache));
    Ok(())
}

/// Five plugins through a limit of two: two at a time, never more, and each
/// one let through only once the server has seen the limit reached.
async fn respects_the_concurrency_limit() -> Result<()> {
    let server = PluginServer::start().await?;
    let cache = fresh_cache("main")?;
    let limit = 2;
    let mut lines = Vec::new();
    let mut gates = Vec::new();
    for i in 0..5 {
        let body = flow::pseudo_random(10_000, 100 + i);
        let path = format!("/p{}.dll", i);
        let gate = Gate::after(0);
        server.route(&path, Route::ok(body.clone()).gate(gate.clone()));
        lines.push(plugin_line(
            &format!("p{}", i),
            &server.url(&path),
            &sha256(&body),
            None,
        ));
        gates.push((path, gate, false));
    }
    let mut options = trusting(&server, &cache);
    options.max_concurrent = limit;
    let conf = prefetch_conf(&lines);
    let running = tokio::spawn(async move { prefetch(&conf, options, |_| true).await });

    // Counted from the gates rather than from the server's active requests: a
    // download that was just let through is still active while it finishes,
    // and would stand in for one that has not yet been admitted.
    let held = |gates: &[(String, Gate, bool)]| {
        gates
            .iter()
            .filter(|(path, _, open)| !*open && server.requests(path) == 1)
            .count()
    };
    for released in 0..gates.len() {
        let expected = limit.min(gates.len() - released);
        wait_until(
            &format!("{} downloads are held at their gates", expected),
            || held(&gates) == expected,
        )
        .await?;
        // Let go of one that has been asked for.
        let next = gates
            .iter_mut()
            .find(|(path, _, open)| !*open && server.requests(path) == 1)
            .ok_or_else(|| anyhow!("no download is waiting at a gate"))?;
        next.1.open();
        next.2 = true;
    }

    let outcome = running.await??;
    outcome.succeeded()?;
    check_contract(&outcome.events, 5, false)?;
    ensure!(
        server.max_active() == limit,
        "at most {} downloads should run at once, and that many should; saw {}",
        limit,
        server.max_active()
    );
    Ok(())
}
