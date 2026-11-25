//! Servers from other projects, run as child processes.
//!
//! The interoperability cases point a plugin at the servers people actually
//! deploy -- the protocol's own reference server, sing-box, mihomo -- rather
//! than at a server the same library provides. Each one here is started from a
//! config written into the case's artifact directory, its output goes to a log
//! file beside it, and it is killed when the handle is dropped, so a case that
//! fails leaves behind the config and the log to read and no process to clean
//! up.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::fixtures::Fixture;
use crate::logs;
use crate::net;
use crate::tls;

/// How long a server may take to start listening. sing-box and mihomo start in
/// well under a second; this is for a loaded CI machine.
const START_TIMEOUT: Duration = Duration::from_secs(20);

/// The account every upstream server is configured with.
pub const USER: &str = "e2e";

pub struct UpstreamServer {
    name: String,
    child: Child,
    addr: SocketAddr,
    log: PathBuf,
}

impl UpstreamServer {
    /// Where clients connect.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Starts `fixture` with `args` and waits for it to listen on `addr`.
    async fn spawn(
        fixture: Fixture,
        name: &str,
        args: &[String],
        addr: SocketAddr,
    ) -> Result<Self> {
        let dir = workdir(name)?;
        let log = dir.join(format!("{}.log", name));
        let output =
            std::fs::File::create(&log).with_context(|| format!("creating {}", log.display()))?;
        let child = Command::new(fixture.path()?)
            .args(args)
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(output)
            .spawn()
            .with_context(|| format!("starting {} ({})", name, fixture.id()))?;
        let mut server = Self {
            name: name.to_string(),
            child,
            addr,
            log,
        };
        if let Err(err) = net::wait_tcp_ready(addr, START_TIMEOUT).await {
            let exited = server.child.try_wait().ok().flatten();
            bail!(
                "{} did not start ({}{}):\n{}",
                server.name,
                err,
                exited
                    .map(|status| format!(", exited with {}", status))
                    .unwrap_or_default(),
                server.log_tail()
            );
        }
        Ok(server)
    }

    /// The end of the server's log, for an error message.
    pub fn log_tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(30)..].join("\n")
    }
}

impl Drop for UpstreamServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A directory for one server's config and log: the case's artifact
/// directory when the runner set one, the temp directory otherwise.
fn workdir(name: &str) -> Result<PathBuf> {
    let base = logs::artifact_dir().unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("upstream-{}-{}", name, std::process::id()));
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

fn write(dir: &Path, file: &str, contents: &str) -> Result<String> {
    let path = dir.join(file);
    std::fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))?;
    Ok(path.display().to_string())
}

/// Writes the suite's certificate and key where a server can read them.
fn certificate_files(dir: &Path) -> Result<(String, String)> {
    let certificate = tls::self_signed()?;
    Ok((
        write(dir, "cert.pem", &certificate.certificate_pem)?,
        write(dir, "key.pem", &certificate.private_key_pem)?,
    ))
}

fn loopback_port() -> Result<SocketAddr> {
    Ok(net::loopback(net::reserve_dual_port()?))
}

// ---------------------------------------------------------------------------
// AnyTLS
// ---------------------------------------------------------------------------

/// The AnyTLS servers the suite runs against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnytlsServer {
    /// anytls-go's own server. It makes up a self-signed certificate at every
    /// start, so a client can only reach it with verification off.
    AnytlsGo,
    SingBox,
    SingBoxNext,
    Mihomo,
}

impl AnytlsServer {
    pub const ALL: &'static [AnytlsServer] = &[
        AnytlsServer::AnytlsGo,
        AnytlsServer::SingBox,
        AnytlsServer::SingBoxNext,
        AnytlsServer::Mihomo,
    ];

    pub fn name(self) -> &'static str {
        match self {
            AnytlsServer::AnytlsGo => "anytls-go",
            AnytlsServer::SingBox => "sing-box",
            AnytlsServer::SingBoxNext => "sing-box-next",
            AnytlsServer::Mihomo => "mihomo",
        }
    }

    pub fn fixture(self) -> Fixture {
        match self {
            AnytlsServer::AnytlsGo => Fixture::UpstreamAnytlsGo,
            AnytlsServer::SingBox => Fixture::UpstreamSingBox,
            AnytlsServer::SingBoxNext => Fixture::UpstreamSingBoxNext,
            AnytlsServer::Mihomo => Fixture::UpstreamMihomo,
        }
    }

    /// Whether the server presents the suite's certificate, which a client can
    /// verify; anytls-go presents one of its own making.
    pub fn verifiable(self) -> bool {
        !matches!(self, AnytlsServer::AnytlsGo)
    }

    /// Starts the server with one user, and the padding scheme given or the
    /// protocol's default.
    pub async fn start(
        self,
        password: &str,
        padding_scheme: Option<&str>,
    ) -> Result<UpstreamServer> {
        let addr = loopback_port()?;
        let name = format!("anytls-{}", self.name());
        let dir = workdir(&name)?;
        let args = match self {
            AnytlsServer::AnytlsGo => {
                let mut args = vec![
                    "-l".to_string(),
                    addr.to_string(),
                    "-p".to_string(),
                    password.to_string(),
                ];
                if let Some(scheme) = padding_scheme {
                    args.push("-padding-scheme".to_string());
                    args.push(write(&dir, "padding-scheme.txt", scheme)?);
                }
                args
            }
            AnytlsServer::SingBox | AnytlsServer::SingBoxNext => {
                let (cert, key) = certificate_files(&dir)?;
                let mut inbound = json!({
                    "type": "anytls",
                    "tag": "anytls-in",
                    "listen": addr.ip().to_string(),
                    "listen_port": addr.port(),
                    "users": [{ "name": USER, "password": password }],
                    "tls": { "enabled": true, "certificate_path": cert, "key_path": key },
                });
                if let Some(scheme) = padding_scheme {
                    inbound["padding_scheme"] = json!(scheme.lines().collect::<Vec<_>>());
                }
                sing_box_args(&dir, vec![inbound])?
            }
            AnytlsServer::Mihomo => {
                let (cert, key) = certificate_files(&dir)?;
                let mut listener = json!({
                    "name": "anytls-in",
                    "type": "anytls",
                    "listen": addr.ip().to_string(),
                    "port": addr.port(),
                    "users": { USER: password },
                    "certificate": cert,
                    "private-key": key,
                });
                if let Some(scheme) = padding_scheme {
                    listener["padding-scheme"] = json!(scheme);
                }
                mihomo_args(&dir, vec![listener])?
            }
        };
        UpstreamServer::spawn(self.fixture(), &name, &args, addr).await
    }
}

// ---------------------------------------------------------------------------
// ShadowTLS
// ---------------------------------------------------------------------------

/// The ShadowTLS v3 servers the suite runs against. Each one fronts a
/// Shadowsocks server, which is what ShadowTLS carries in practice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowTlsServer {
    /// ihciah/shadow-tls, the original, relaying to a separate Shadowsocks
    /// server.
    Original,
    /// sing-box, with the ShadowTLS inbound handing over to a Shadowsocks
    /// inbound in the same process.
    SingBox,
    /// mihomo, where ShadowTLS is an option of the Shadowsocks listener.
    Mihomo,
}

/// What a ShadowTLS server needs to be told.
pub struct ShadowTlsSetup<'a> {
    pub password: &'a str,
    /// The site whose handshake is borrowed.
    pub handshake: SocketAddr,
    pub strict: bool,
    pub ss_method: &'a str,
    pub ss_password: &'a str,
    /// Where the original server relays authenticated connections. The other
    /// two carry Shadowsocks themselves and ignore it.
    pub ss_backend: SocketAddr,
}

impl ShadowTlsServer {
    pub const ALL: &'static [ShadowTlsServer] = &[
        ShadowTlsServer::Original,
        ShadowTlsServer::SingBox,
        ShadowTlsServer::Mihomo,
    ];

    pub fn name(self) -> &'static str {
        match self {
            ShadowTlsServer::Original => "shadow-tls",
            ShadowTlsServer::SingBox => "sing-box",
            ShadowTlsServer::Mihomo => "mihomo",
        }
    }

    pub fn fixture(self) -> Fixture {
        match self {
            ShadowTlsServer::Original => Fixture::UpstreamShadowTls,
            ShadowTlsServer::SingBox => Fixture::UpstreamSingBox,
            ShadowTlsServer::Mihomo => Fixture::UpstreamMihomo,
        }
    }

    /// Whether this server needs a separate Shadowsocks server behind it.
    pub fn needs_backend(self) -> bool {
        matches!(self, ShadowTlsServer::Original)
    }

    pub async fn start(self, setup: &ShadowTlsSetup<'_>) -> Result<UpstreamServer> {
        let addr = loopback_port()?;
        let name = format!("shadowtls-{}", self.name());
        let dir = workdir(&name)?;
        let args = match self {
            ShadowTlsServer::Original => {
                let mut args = vec!["--v3".to_string()];
                if setup.strict {
                    args.push("--strict".to_string());
                }
                args.extend([
                    "server".to_string(),
                    "--listen".to_string(),
                    addr.to_string(),
                    "--server".to_string(),
                    setup.ss_backend.to_string(),
                    "--tls".to_string(),
                    setup.handshake.to_string(),
                    "--password".to_string(),
                    setup.password.to_string(),
                ]);
                args
            }
            ShadowTlsServer::SingBox => {
                let ss_port = net::reserve_dual_port()?;
                sing_box_args(
                    &dir,
                    vec![
                        json!({
                            "type": "shadowtls",
                            "tag": "shadowtls-in",
                            "listen": addr.ip().to_string(),
                            "listen_port": addr.port(),
                            "version": 3,
                            "users": [{ "name": USER, "password": setup.password }],
                            "handshake": {
                                "server": setup.handshake.ip().to_string(),
                                "server_port": setup.handshake.port(),
                            },
                            "strict_mode": setup.strict,
                            "detour": "ss-in",
                        }),
                        json!({
                            "type": "shadowsocks",
                            "tag": "ss-in",
                            "listen": "127.0.0.1",
                            "listen_port": ss_port,
                            "method": setup.ss_method,
                            "password": setup.ss_password,
                        }),
                    ],
                )?
            }
            ShadowTlsServer::Mihomo => mihomo_args(
                &dir,
                vec![json!({
                    "name": "ss-in",
                    "type": "shadowsocks",
                    "listen": addr.ip().to_string(),
                    "port": addr.port(),
                    "cipher": setup.ss_method,
                    "password": setup.ss_password,
                    "shadow-tls": {
                        "enable": true,
                        "version": 3,
                        "users": [{ "name": USER, "password": setup.password }],
                        "handshake": { "dest": setup.handshake.to_string() },
                        "strict-mode": setup.strict,
                    },
                })],
            )?,
        };
        UpstreamServer::spawn(self.fixture(), &name, &args, addr).await
    }
}

// ---------------------------------------------------------------------------
// Configs
// ---------------------------------------------------------------------------

/// A sing-box config with these inbounds and a direct outbound, and the
/// arguments that run it.
fn sing_box_args(dir: &Path, inbounds: Vec<Value>) -> Result<Vec<String>> {
    let config = json!({
        "log": { "level": "debug", "timestamp": true },
        "inbounds": inbounds,
        "outbounds": [{ "type": "direct", "tag": "direct" }],
    });
    let path = write(
        dir,
        "sing-box.json",
        &serde_json::to_string_pretty(&config)?,
    )?;
    Ok(vec![
        "run".to_string(),
        "--disable-color".to_string(),
        "-D".to_string(),
        dir.display().to_string(),
        "-c".to_string(),
        path,
    ])
}

/// A mihomo config with these listeners, routing everything direct, and the
/// arguments that run it. Written as JSON, which is YAML too.
fn mihomo_args(dir: &Path, listeners: Vec<Value>) -> Result<Vec<String>> {
    let config = json!({
        "mode": "direct",
        "log-level": "debug",
        "ipv6": true,
        "allow-lan": false,
        "listeners": listeners,
    });
    let path = write(dir, "config.yaml", &serde_json::to_string_pretty(&config)?)?;
    Ok(vec![
        "-d".to_string(),
        dir.display().to_string(),
        "-f".to_string(),
        path,
    ])
}
