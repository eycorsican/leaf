//! A leaf instance under test.
//!
//! Configs are built as JSON -- the same representation a user writes -- and
//! handed to leaf's own parser, so a scenario exercises the real config path
//! rather than a hand-assembled internal structure. Every listener gets an
//! operating-system-assigned port, which is what lets cases run concurrently.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

use crate::net;
use crate::paths;

static NEXT_RUNTIME_ID: AtomicU16 = AtomicU16::new(1);

/// Keeps the config files of concurrently running reloadable nodes apart.
static NEXT_CONFIG_FILE_ID: AtomicU32 = AtomicU32::new(1);

/// Overrides the level nodes log at. A case sets it when its own traffic would
/// otherwise be drowned -- or slowed -- by the log.
pub const ENV_LOG_LEVEL: &str = "LEAF_E2E_LOG_LEVEL";

/// How long a node may take to start listening before the harness gives up.
const START_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Node {
    name: String,
    log_level: String,
    inbounds: Vec<Value>,
    outbounds: Vec<Value>,
    hosts: serde_json::Map<String, Value>,
    socks: Option<SocketAddr>,
}

impl Node {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            // Trace by default, because the captured log is the primary
            // evidence when a case fails and it is kept as an artifact. Cases
            // that move real volume turn it down: leaf traces every frame, and
            // at that rate the log, not the transfer, is what is being measured.
            log_level: std::env::var(ENV_LOG_LEVEL).unwrap_or_else(|_| "trace".to_string()),
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            hosts: serde_json::Map::new(),
            socks: None,
        }
    }

    pub fn log_level(mut self, level: &str) -> Self {
        self.log_level = level.to_string();
        self
    }

    /// Adds a socks inbound on a free port and remembers it as this node's
    /// client entry point.
    pub fn socks_inbound(mut self) -> Result<Self> {
        let port = net::reserve_dual_port()?;
        self.inbounds.push(cfg::socks_inbound("socks-in", port));
        self.socks = Some(net::loopback(port));
        Ok(self)
    }

    /// Maps a name to fixed addresses, so a case that needs a domain
    /// destination resolves it here rather than out on the network.
    pub fn dns_host(mut self, name: &str, addresses: &[&str]) -> Self {
        self.hosts.insert(name.to_string(), json!(addresses));
        self
    }

    pub fn inbound(mut self, inbound: Value) -> Self {
        self.inbounds.push(inbound);
        self
    }

    /// Adds an outbound. The first one added is leaf's default route, so order
    /// matters: put the outbound under test first.
    /// Adds an outbound at the front, which is what makes it the default
    /// route: leaf picks the first outbound when no rule matches.
    pub fn outbound_first(mut self, outbound: Value) -> Self {
        self.outbounds.insert(0, outbound);
        self
    }

    pub fn outbound(mut self, outbound: Value) -> Self {
        self.outbounds.push(outbound);
        self
    }

    /// The socks inbound this node will listen on, known before it starts.
    pub fn socks_addr(&self) -> Result<SocketAddr> {
        self.socks
            .ok_or_else(|| anyhow!("node [{}] has no socks inbound", self.name))
    }

    pub fn config(&self) -> Value {
        let mut config = json!({
            "log": { "level": self.log_level, "output": "console" },
            "inbounds": self.inbounds,
            "outbounds": self.outbounds,
        });
        if !self.hosts.is_empty() {
            config["dns"] = json!({ "hosts": self.hosts });
        }
        config
    }

    pub fn config_string(&self) -> String {
        serde_json::to_string_pretty(&self.config()).expect("config is serialisable")
    }

    /// The address the harness watches to decide the node is up: the first
    /// inbound that names a port.
    fn probe_addr(&self) -> Option<SocketAddr> {
        self.inbounds.iter().find_map(|inbound| {
            let port = u16::try_from(inbound.get("port")?.as_u64()?).ok()?;
            (port != 0).then(|| net::loopback(port))
        })
    }

    /// Whether that port will be a datagram listener rather than a stream one.
    ///
    /// QUIC listens on UDP and accepts no TCP connection at all, so the
    /// readiness probe has to ask a different question of it.
    fn probe_is_datagram(&self) -> bool {
        self.inbounds
            .iter()
            .any(|inbound| inbound.get("protocol").and_then(|p| p.as_str()) == Some("quic"))
    }

    /// Starts the node and waits until it accepts connections.
    pub async fn start(self) -> Result<LeafNode> {
        let config = self.internal_config()?;
        self.start_with(leaf::Config::Internal(config), None).await
    }

    /// Starts the node from a config file, so that it can be reloaded.
    ///
    /// `leaf::reload` re-reads the file the runtime was started with, so a
    /// scenario that exercises reload cannot use the in-memory config every
    /// other start uses. The file lives with the rest of the case artifacts.
    pub async fn start_reloadable(self) -> Result<LeafNode> {
        let path = self.config_file_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&path, self.config_string())
            .with_context(|| format!("writing {}", path.display()))?;
        let config = leaf::Config::File(path.display().to_string());
        self.start_with(config, Some(path)).await
    }

    fn config_file_path(&self) -> Result<PathBuf> {
        // The pid is part of the name because cases run as concurrent child
        // processes, each with a counter of its own starting at one. Without it
        // two cases whose nodes share a name write the same file, and the
        // second one to start reads the first one's config.
        let id = NEXT_CONFIG_FILE_ID.fetch_add(1, Ordering::Relaxed);
        Ok(paths::artifacts_dir()?.join("configs").join(format!(
            "{}-{}-{}.json",
            paths::artifact_slug(&self.name),
            std::process::id(),
            id
        )))
    }

    /// Parses the config here rather than inside `leaf::start`, so that a
    /// malformed one is reported as a harness error and not as a node failure.
    fn internal_config(&self) -> Result<leaf::config::internal::Config> {
        leaf::config::json::from_string(&self.config_string())
            .map_err(|err| anyhow!("node [{}] has an invalid config: {}", self.name, err))
    }

    async fn start_with(
        self,
        config: leaf::Config,
        config_path: Option<PathBuf>,
    ) -> Result<LeafNode> {
        let name = self.name.clone();
        let socks = self.socks;
        let probe = self.probe_addr();
        let datagram_probe = self.probe_is_datagram();
        let (rt_id, mut failure) = self.spawn(config)?;
        let node = LeafNode {
            name: name.clone(),
            rt_id,
            socks,
            config_path,
            stopped: false,
        };

        let Some(probe) = probe else {
            // Nothing listens, so there is nothing to wait for. Give leaf a
            // moment to report a startup failure rather than handing back a
            // node that is already dead.
            return match tokio::time::timeout(Duration::from_millis(250), &mut failure).await {
                Ok(Ok(err)) => Err(anyhow!("node [{}] failed to start: {}", name, err)),
                _ => Ok(node),
            };
        };

        tokio::select! {
            reported = &mut failure => match reported {
                Ok(err) => bail!("node [{}] failed to start: {}", name, err),
                Err(_) => bail!("node [{}] start task vanished", name),
            },
            ready = async {
                if datagram_probe {
                    net::wait_udp_bound(probe.port(), START_TIMEOUT).await
                } else {
                    net::wait_tcp_ready(probe, START_TIMEOUT).await
                }
            } => {
                ready.with_context(|| format!("node [{}] never started listening", name))?;
                Ok(node)
            }
        }
    }

    /// Starts the node expecting it to refuse the config, and returns the error
    /// leaf reported.
    ///
    /// This is how loader and config-validation rejections are observed from
    /// the outside, exactly as an operator would see them.
    pub async fn start_expecting_failure(self) -> Result<String> {
        let name = self.name.clone();
        let config = self.internal_config()?;
        let (rt_id, failure) = self.spawn(leaf::Config::Internal(config))?;
        match tokio::time::timeout(START_TIMEOUT, failure).await {
            Ok(Ok(err)) => Ok(err),
            Ok(Err(_)) => bail!("node [{}] start task vanished", name),
            Err(_) => {
                shutdown_detached(rt_id);
                bail!(
                    "node [{}] started successfully but was expected to fail",
                    name
                )
            }
        }
    }

    fn spawn(&self, config: leaf::Config) -> Result<(u16, tokio::sync::oneshot::Receiver<String>)> {
        let rt_id = NEXT_RUNTIME_ID.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let opts = leaf::StartOptions {
                config,
                auto_reload: false,
                // Multi-threaded on purpose: a plugin that embeds its own
                // runtime wakes the host from a thread the executor does not
                // own, and a single-threaded runtime would not exercise that.
                runtime_opt: leaf::RuntimeOption::MultiThread(2, 2 * 1024 * 1024),
            };
            // `leaf::start` blocks until shutdown, so this only ever reports the
            // startup failures a scenario cares about.
            if let Err(err) = leaf::start(rt_id, opts) {
                let _ = tx.send(err.to_string());
            }
        });
        Ok((rt_id, rx))
    }
}

pub struct LeafNode {
    name: String,
    rt_id: u16,
    socks: Option<SocketAddr>,
    /// Set only for a node started with [`Node::start_reloadable`].
    config_path: Option<PathBuf>,
    stopped: bool,
}

impl LeafNode {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The socks inbound address, for scenarios that drive this node as a
    /// client.
    pub fn socks_addr(&self) -> Result<SocketAddr> {
        self.socks
            .ok_or_else(|| anyhow!("node [{}] has no socks inbound", self.name))
    }

    /// Rewrites this node's config file and makes leaf reload it, the way
    /// `SIGHUP` or the watcher does.
    pub async fn reload_to(&self, config: &Node) -> Result<()> {
        let path = self.config_path.clone().ok_or_else(|| {
            anyhow!(
                "node [{}] was not started from a config file, so it cannot reload",
                self.name
            )
        })?;
        std::fs::write(&path, config.config_string())
            .with_context(|| format!("rewriting {}", path.display()))?;
        let rt_id = self.rt_id;
        tokio::task::spawn_blocking(move || leaf::reload(rt_id))
            .await?
            .map_err(|err| anyhow!("node [{}] failed to reload: {}", self.name, err))
    }

    /// Stops the node and waits for it to go away.
    ///
    /// Scenarios that care whether shutdown actually completes -- notably any
    /// chain holding a plugin that embeds its own runtime -- call this instead
    /// of relying on the drop.
    pub async fn shutdown(mut self) -> Result<()> {
        self.stopped = true;
        let rt_id = self.rt_id;
        tokio::task::spawn_blocking(move || leaf::shutdown(rt_id)).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while leaf::is_running(rt_id) {
            if tokio::time::Instant::now() >= deadline {
                bail!("node [{}] did not shut down", self.name);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }
}

impl Drop for LeafNode {
    fn drop(&mut self) {
        if !self.stopped {
            shutdown_detached(self.rt_id);
        }
    }
}

/// Shuts a runtime down without blocking the caller.
///
/// `leaf::shutdown` sends on a blocking channel, which panics when called from
/// an executor thread, and a node is usually dropped inside a scenario's async
/// body.
fn shutdown_detached(rt_id: u16) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn_blocking(move || leaf::shutdown(rt_id));
        }
        Err(_) => {
            leaf::shutdown(rt_id);
        }
    }
}

/// Config fragments, written as the JSON a user would write.
pub mod cfg {
    use super::*;

    pub fn socks_inbound(tag: &str, port: u16) -> Value {
        json!({
            "protocol": "socks",
            "tag": tag,
            "address": "127.0.0.1",
            "port": port,
        })
    }

    /// A socks inbound that demands a username and a password, which is the
    /// other half of the SOCKS5 handshake a client has to implement.
    pub fn socks_inbound_with_auth(tag: &str, port: u16, username: &str, password: &str) -> Value {
        json!({
            "protocol": "socks",
            "tag": tag,
            "address": "127.0.0.1",
            "port": port,
            "settings": { "username": username, "password": password },
        })
    }

    /// leaf's own SOCKS5 outbound, the oracle the socks5 plugins are measured
    /// against. Empty credentials mean no authentication.
    pub fn socks(tag: &str, server: SocketAddr, username: &str, password: &str) -> Value {
        json!({
            "protocol": "socks",
            "tag": tag,
            "settings": {
                "address": server.ip().to_string(),
                "port": server.port(),
                "username": username,
                "password": password,
            },
        })
    }

    pub fn shadowsocks_inbound(tag: &str, port: u16, method: &str, password: &str) -> Value {
        json!({
            "protocol": "shadowsocks",
            "tag": tag,
            "address": "127.0.0.1",
            "port": port,
            "settings": { "method": method, "password": password },
        })
    }

    pub fn direct(tag: &str) -> Value {
        json!({ "protocol": "direct", "tag": tag })
    }

    pub fn shadowsocks(tag: &str, server: SocketAddr, method: &str, password: &str) -> Value {
        json!({
            "protocol": "shadowsocks",
            "tag": tag,
            "settings": {
                "address": server.ip().to_string(),
                "port": server.port(),
                "method": method,
                "password": password,
            },
        })
    }

    pub fn chain_inbound(tag: &str, port: u16, actors: &[&str]) -> Value {
        json!({
            "protocol": "chain",
            "tag": tag,
            "address": "127.0.0.1",
            "port": port,
            "settings": { "actors": actors },
        })
    }

    /// A TLS terminator. The certificate is inlined rather than written to disk
    /// so that a case leaves nothing behind and depends on no asset directory.
    pub fn tls_inbound(tag: &str, certificate_pem: &str, private_key_pem: &str) -> Value {
        json!({
            "protocol": "tls",
            "tag": tag,
            "settings": {
                "rawCertificate": [certificate_pem],
                "rawCertificateKey": [private_key_pem],
            },
        })
    }

    pub fn ws_inbound(tag: &str, path: &str) -> Value {
        json!({
            "protocol": "ws",
            "tag": tag,
            "settings": { "path": path },
        })
    }

    pub fn trojan_inbound(tag: &str, password: &str) -> Value {
        json!({
            "protocol": "trojan",
            "tag": tag,
            "settings": { "passwords": [password] },
        })
    }

    pub fn tls(tag: &str, server_name: &str, insecure: bool) -> Value {
        json!({
            "protocol": "tls",
            "tag": tag,
            "settings": { "serverName": server_name, "insecure": insecure },
        })
    }

    pub fn ws(tag: &str, path: &str) -> Value {
        json!({
            "protocol": "ws",
            "tag": tag,
            "settings": { "path": path },
        })
    }

    pub fn trojan(tag: &str, server: SocketAddr, password: &str) -> Value {
        json!({
            "protocol": "trojan",
            "tag": tag,
            "settings": {
                "address": server.ip().to_string(),
                "port": server.port(),
                "password": password,
            },
        })
    }

    /// A QUIC transport. The certificate is inlined; leaf takes PEM content
    /// wherever it takes a path.
    pub fn quic(tag: &str, server: SocketAddr, server_name: &str, certificate_pem: &str) -> Value {
        json!({
            "protocol": "quic",
            "tag": tag,
            "settings": {
                "address": server.ip().to_string(),
                "port": server.port(),
                "serverName": server_name,
                "certificate": certificate_pem,
                "alpn": ["http/1.1"],
            },
        })
    }

    pub fn quic_inbound(tag: &str, certificate_pem: &str, private_key_pem: &str) -> Value {
        json!({
            "protocol": "quic",
            "tag": tag,
            "settings": {
                "certificate": certificate_pem,
                "certificateKey": private_key_pem,
                "alpn": ["http/1.1"],
            },
        })
    }

    /// Multiplexing over one connection.
    ///
    /// The endpoint belongs to this actor rather than to the protocol inside
    /// it, and so does the transport underneath: amux names its own actors
    /// rather than sitting beside them in the chain.
    pub fn amux(tag: &str, server: SocketAddr, actors: &[&str]) -> Value {
        json!({
            "protocol": "amux",
            "tag": tag,
            "settings": {
                "address": server.ip().to_string(),
                "port": server.port(),
                "actors": actors,
                "maxAccepts": 16,
                "concurrency": 1,
            },
        })
    }

    pub fn amux_inbound(tag: &str, actors: &[&str]) -> Value {
        json!({
            "protocol": "amux",
            "tag": tag,
            "settings": { "actors": actors },
        })
    }

    /// The same protocols as inbound actors inside a chain, where the chain
    /// owns the listener and an address of their own would bind a second one
    /// on the same port.
    pub fn socks_actor_inbound(tag: &str) -> Value {
        json!({
            "protocol": "socks",
            "tag": tag,
        })
    }

    pub fn shadowsocks_actor_inbound(tag: &str, method: &str, password: &str) -> Value {
        json!({
            "protocol": "shadowsocks",
            "tag": tag,
            "settings": { "method": method, "password": password },
        })
    }

    /// One of leaf's selecting outbounds -- the ones that pick a handler
    /// rather than carry bytes themselves.
    pub fn selector(protocol: &str, tag: &str, actors: &[&str], extra: Value) -> Value {
        let mut settings = json!({ "actors": actors });
        if let (Some(settings), Some(extra)) = (settings.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                settings.insert(key.clone(), value.clone());
            }
        }
        json!({
            "protocol": protocol,
            "tag": tag,
            "settings": settings,
        })
    }

    pub fn chain(tag: &str, actors: &[&str]) -> Value {
        json!({
            "protocol": "chain",
            "tag": tag,
            "settings": { "actors": actors },
        })
    }

    /// A plugin outbound.
    ///
    /// `endpoint` is `Some` only for engines that name their own server
    /// (`connect_type = ProxyTcp`, and every datagram engine); an engine that
    /// layers over the next actor in a chain must leave it unset, and the host
    /// rejects the config if it does not.
    pub fn plugin(tag: &str, path: &Path, endpoint: Option<SocketAddr>, args: &str) -> Value {
        let mut settings = json!({
            "path": path.display().to_string(),
            "args": args,
        });
        if let Some(endpoint) = endpoint {
            settings["host"] = json!(endpoint.ip().to_string());
            settings["port"] = json!(endpoint.port());
        }
        json!({ "protocol": "plugin", "tag": tag, "settings": settings })
    }
}
