//! Build and locate the artifacts a scenario needs.
//!
//! Plugins are `cdylib`s and Go `c-shared` libraries; cargo cannot express
//! "build this and hand my test the path" on stable, so the harness builds them
//! itself. This happens in the *runner* process, at test-run time -- never from
//! a `build.rs`, which runs while cargo holds the build lock and would deadlock
//! on a nested invocation. At run time the lock is free, so the nested build
//! shares the same target directory and rebuilds nothing.
//!
//! Resolved paths are handed to per-case child processes through the
//! environment, so a child never builds anything.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

use crate::paths;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fixture {
    /// The Rust shadowsocks C ABI plugin (`connect_type = ProxyTcp`, unreliable
    /// datagram engine).
    ShadowsocksCabiRs,
    /// The Rust TLS C ABI plugin (`connect_type = Next`).
    TlsCabiRs,
    /// The Go TLS C ABI plugin.
    TlsCabiGo,
    /// The Go Trojan C ABI plugin (stream + reliable datagram engine).
    TrojanCabiGo,
    /// The C SOCKS5 plugin (`connect_type = ProxyTcp`, stream only).
    Socks5CabiC,
    /// The Zig SOCKS5 plugin, the same protocol in another language with no
    /// runtime of its own.
    Socks5CabiZig,
    /// The Go AnyTLS plugin, a thin adapter over the AnyTLS author's library
    /// (`connect_type = ProxyTcp`, stream only).
    AnytlsCabiGo,
    /// The Go ShadowTLS v3 plugin, a thin adapter over sing-shadowtls
    /// (`connect_type = Next`).
    ShadowtlsCabiGo,
    /// The AnyTLS reference server, from the protocol's own repository.
    UpstreamAnytlsGo,
    /// sing-box at its current stable release: AnyTLS and ShadowTLS servers.
    UpstreamSingBox,
    /// sing-box at a pinned commit of its `testing` branch, which replaced the
    /// AnyTLS author's library with an implementation of its own. Kept beside
    /// the stable release so a divergence shows up before it ships.
    UpstreamSingBoxNext,
    /// mihomo at its current release: AnyTLS and ShadowTLS servers.
    UpstreamMihomo,
    /// The original ShadowTLS server, in Rust.
    UpstreamShadowTls,
    /// The suite's own plugin, which misbehaves on request.
    Conformance,
    /// The same, in Go. The SDK's boundary -- which turns a panic or a fault
    /// inside Go into a status code rather than letting it cross into the host
    /// -- and the runtime that boundary belongs to are what no Rust plugin can
    /// stand in for.
    ConformanceGo,
    /// The CLI, for black-box scenarios that drive a real leaf process.
    LeafCli,
}

enum Kind {
    /// A workspace `cdylib` package.
    CargoCdylib {
        package: &'static str,
        stem: &'static str,
    },
    /// A Go `c-shared` build rooted at a workspace-relative directory.
    GoCShared {
        dir: &'static str,
        stem: &'static str,
    },
    /// A single C source file compiled to a shared library by the system
    /// compiler.
    CcShared {
        dir: &'static str,
        source: &'static str,
        stem: &'static str,
    },
    /// A Zig shared library.
    ///
    /// Built with `zig build-lib` rather than `zig build`, because the harness
    /// has to name the output path; the plugin ships a `build.zig` for anyone
    /// building it on its own.
    ZigShared {
        dir: &'static str,
        root: &'static str,
        stem: &'static str,
    },
    /// A server from another project, built from its source at a pinned
    /// revision. These are what the interoperability cases test against: a
    /// plugin is only as compatible as the servers it has actually talked to.
    Upstream {
        /// Clone URL.
        repo: &'static str,
        /// A tag or a full commit id. Pinned, so a run is reproducible and a
        /// new upstream release is a deliberate change here.
        rev: &'static str,
        build: UpstreamBuild,
        /// The executable's name, without an extension.
        exe: &'static str,
    },
    /// A workspace binary.
    CargoBin {
        package: &'static str,
        features: &'static [&'static str],
        bin: &'static str,
    },
}

#[derive(Clone, Copy)]
enum UpstreamBuild {
    /// `go build` of a package path inside the checkout.
    Go { package: &'static str },
    /// `cargo build --release` of the checkout, which is one binary crate.
    Cargo,
}

impl Fixture {
    pub const ALL: &'static [Fixture] = &[
        Fixture::ShadowsocksCabiRs,
        Fixture::TlsCabiRs,
        Fixture::TlsCabiGo,
        Fixture::TrojanCabiGo,
        Fixture::Socks5CabiC,
        Fixture::Socks5CabiZig,
        Fixture::AnytlsCabiGo,
        Fixture::ShadowtlsCabiGo,
        Fixture::UpstreamAnytlsGo,
        Fixture::UpstreamSingBox,
        Fixture::UpstreamSingBoxNext,
        Fixture::UpstreamMihomo,
        Fixture::UpstreamShadowTls,
        Fixture::Conformance,
        Fixture::ConformanceGo,
        Fixture::LeafCli,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Fixture::ShadowsocksCabiRs => "shadowsocks-cabi-rs",
            Fixture::TlsCabiRs => "tls-cabi-rs",
            Fixture::TlsCabiGo => "tls-cabi-go",
            Fixture::TrojanCabiGo => "trojan-cabi-go",
            Fixture::Socks5CabiC => "socks5-cabi-c",
            Fixture::Socks5CabiZig => "socks5-cabi-zig",
            Fixture::AnytlsCabiGo => "anytls-cabi-go",
            Fixture::ShadowtlsCabiGo => "shadowtls-cabi-go",
            Fixture::UpstreamAnytlsGo => "upstream-anytls-go",
            Fixture::UpstreamSingBox => "upstream-sing-box",
            Fixture::UpstreamSingBoxNext => "upstream-sing-box-next",
            Fixture::UpstreamMihomo => "upstream-mihomo",
            Fixture::UpstreamShadowTls => "upstream-shadow-tls",
            Fixture::Conformance => "conformance-cabi",
            Fixture::ConformanceGo => "conformance-cabi-go",
            Fixture::LeafCli => "leaf-cli",
        }
    }

    /// True for fixtures that need a Go toolchain.
    pub fn needs_go(self) -> bool {
        matches!(
            self.kind(),
            Kind::GoCShared { .. }
                | Kind::Upstream {
                    build: UpstreamBuild::Go { .. },
                    ..
                }
        )
    }

    /// True for fixtures that need a C compiler.
    pub fn needs_cc(self) -> bool {
        matches!(self.kind(), Kind::CcShared { .. })
    }

    /// True for fixtures that need a Zig toolchain.
    pub fn needs_zig(self) -> bool {
        matches!(self.kind(), Kind::ZigShared { .. })
    }

    /// True for fixtures that are plugins, as opposed to tooling.
    pub fn is_plugin(self) -> bool {
        !matches!(self.kind(), Kind::CargoBin { .. } | Kind::Upstream { .. })
    }

    /// True for servers from other projects, which a run builds from source
    /// unless it is told where a binary already is.
    pub fn is_upstream(self) -> bool {
        matches!(self.kind(), Kind::Upstream { .. })
    }

    fn kind(self) -> Kind {
        match self {
            Fixture::ShadowsocksCabiRs => Kind::CargoCdylib {
                package: "shadowsocks-cabi-rs",
                stem: "shadowsocks_cabi_rs",
            },
            Fixture::TlsCabiRs => Kind::CargoCdylib {
                package: "tls-cabi-rs",
                stem: "tls_cabi_rs",
            },
            Fixture::TlsCabiGo => Kind::GoCShared {
                dir: "leaf-plugins/tls-cabi-go",
                stem: "tls_cabi_go",
            },
            Fixture::TrojanCabiGo => Kind::GoCShared {
                dir: "leaf-plugins/trojan-cabi-go",
                stem: "trojan_cabi_go",
            },
            Fixture::Socks5CabiC => Kind::CcShared {
                dir: "leaf-plugins/socks5-cabi-c",
                source: "socks5.c",
                stem: "socks5_cabi_c",
            },
            Fixture::Socks5CabiZig => Kind::ZigShared {
                dir: "leaf-plugins/socks5-cabi-zig",
                root: "src/main.zig",
                stem: "socks5_cabi_zig",
            },
            Fixture::AnytlsCabiGo => Kind::GoCShared {
                dir: "leaf-plugins/anytls-cabi-go",
                stem: "anytls_cabi_go",
            },
            Fixture::ShadowtlsCabiGo => Kind::GoCShared {
                dir: "leaf-plugins/shadowtls-cabi-go",
                stem: "shadowtls_cabi_go",
            },
            Fixture::UpstreamAnytlsGo => Kind::Upstream {
                repo: "https://github.com/anytls/anytls-go",
                rev: "v0.0.13",
                build: UpstreamBuild::Go {
                    package: "./cmd/server",
                },
                exe: "anytls-server",
            },
            Fixture::UpstreamSingBox => Kind::Upstream {
                repo: "https://github.com/SagerNet/sing-box",
                rev: "v1.14.4",
                build: UpstreamBuild::Go {
                    package: "./cmd/sing-box",
                },
                exe: "sing-box",
            },
            Fixture::UpstreamSingBoxNext => Kind::Upstream {
                repo: "https://github.com/SagerNet/sing-box",
                // `testing` on 2026-11-10, the day it moved to
                // github.com/sagernet/sing-anytls.
                rev: "a13dbe1f785f66c86acbf3985c33fdafea0cbfd6",
                build: UpstreamBuild::Go {
                    package: "./cmd/sing-box",
                },
                exe: "sing-box",
            },
            Fixture::UpstreamMihomo => Kind::Upstream {
                repo: "https://github.com/MetaCubeX/mihomo",
                rev: "v1.19.34",
                build: UpstreamBuild::Go { package: "." },
                exe: "mihomo",
            },
            Fixture::UpstreamShadowTls => Kind::Upstream {
                repo: "https://github.com/ihciah/shadow-tls",
                rev: "v0.2.25",
                build: UpstreamBuild::Cargo,
                exe: "shadow-tls",
            },
            Fixture::Conformance => Kind::CargoCdylib {
                package: "conformance-cabi",
                stem: "conformance_cabi",
            },
            Fixture::ConformanceGo => Kind::GoCShared {
                dir: "leaf-e2e/plugins/conformance-cabi-go",
                stem: "conformance_cabi_go",
            },
            Fixture::LeafCli => Kind::CargoBin {
                package: "leaf-cli",
                features: &["leaf/plugin"],
                bin: "leaf",
            },
        }
    }

    /// The environment variable the runner uses to hand this fixture's path to
    /// a case child process.
    pub fn env_key(self) -> String {
        format!(
            "LEAF_E2E_FIXTURE_{}",
            self.id().to_ascii_uppercase().replace('-', "_")
        )
    }

    /// Resolves the fixture inside a case child process.
    pub fn path(self) -> Result<PathBuf> {
        let key = self.env_key();
        let value = std::env::var(&key).map_err(|_| {
            anyhow!(
                "fixture [{}] is not available to this case; the scenario must \
                 declare it in `needs`",
                self.id()
            )
        })?;
        Ok(PathBuf::from(value))
    }

    /// Where a fixture the harness builds itself is written.
    ///
    /// Only the Go, C and Zig plugins go through here: they are built by their
    /// own toolchain with an explicit output path, and next to cargo's output
    /// is where they belong, so that `cargo clean` takes them too. What cargo
    /// builds, cargo is asked about instead.
    fn artifact_path(self) -> Result<PathBuf> {
        let dir = paths::profile_dir()?;
        Ok(match self.kind() {
            Kind::GoCShared { stem, .. }
            | Kind::CcShared { stem, .. }
            | Kind::ZigShared { stem, .. } => dir.join(dylib_file_name(stem)),
            Kind::CargoCdylib { stem, .. } => dir.join(dylib_file_name(stem)),
            Kind::CargoBin { bin, .. } => dir.join(exe_file_name(bin)),
            Kind::Upstream { .. } => upstream_dir(self)?.join("bin"),
        })
    }

    /// The environment variable that names an already-built upstream server,
    /// so a machine without network access -- or a CI cache -- can skip the
    /// clone and the build.
    pub fn upstream_env_key(self) -> String {
        format!(
            "LEAF_E2E_UPSTREAM_{}",
            self.id()
                .trim_start_matches("upstream-")
                .to_ascii_uppercase()
                .replace('-', "_")
        )
    }

    fn build(self) -> Result<PathBuf> {
        let root = paths::workspace_root();
        let profile = paths::cargo_profile_arg()?;
        // Only the fixtures built by another toolchain need a path decided for
        // them; the cargo ones report where they went.
        let out = match self.kind() {
            Kind::CargoCdylib { .. } | Kind::CargoBin { .. } | Kind::Upstream { .. } => {
                PathBuf::new()
            }
            _ => self.artifact_path()?,
        };
        match self.kind() {
            Kind::Upstream {
                repo,
                rev,
                build,
                exe,
            } => return build_upstream(self, repo, rev, build, exe),
            Kind::CargoCdylib { package, stem } => {
                let mut cmd = cargo();
                cmd.current_dir(&root)
                    .args(["build", "--profile", &profile, "-p", package]);
                add_target(&mut cmd)?;
                return cargo_artifact(cmd, package, "cdylib", stem);
            }
            Kind::CargoBin {
                package,
                features,
                bin,
            } => {
                let mut cmd = cargo();
                cmd.current_dir(&root)
                    .args(["build", "--profile", &profile, "-p", package]);
                add_target(&mut cmd)?;
                if !features.is_empty() {
                    cmd.arg("--features").arg(features.join(","));
                }
                return cargo_artifact(cmd, package, "bin", bin);
            }
            Kind::GoCShared { dir, .. } => {
                ensure_go()?;
                let mut cmd = Command::new("go");
                cmd.current_dir(root.join(dir))
                    // cgo reads `CC`, and on Windows it has to be a GNU
                    // toolchain: the runtime of a `c-shared` library is
                    // started from a constructor the GNU CRT runs, and a
                    // library linked against the MSVC one builds, loads, and
                    // then hangs on the first call into it, waiting for an
                    // initialisation that never began. Handing the child what
                    // `cc_command` resolved keeps that choice in one place
                    // instead of depending on what the shell happened to
                    // export.
                    .env("CC", cc_command().join(" "))
                    .env("CGO_ENABLED", "1")
                    .arg("build")
                    .arg("-buildmode=c-shared")
                    .arg("-o")
                    .arg(&out)
                    .arg(".");
                run(cmd, &format!("go build {}", dir))?;
            }
            Kind::CcShared { dir, source, .. } => {
                let compiler = cc_command();
                ensure_compiler(&compiler, "--version", "C compiler")?;
                let (program, leading) = compiler
                    .split_first()
                    .expect("cc_command never returns an empty command");
                let mut cmd = Command::new(program);
                cmd.current_dir(root.join(dir))
                    .args(leading)
                    .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-shared"])
                    // The C plugin parses what a proxy server sends it, in a
                    // language that will not stop it from getting that wrong.
                    // This costs nothing measurable and turns a mistake into a
                    // crash instead of a foothold.
                    .arg("-fstack-protector-strong")
                    .arg("-I")
                    .arg(root.join("leaf-plugin-abi/include"))
                    .arg("-o")
                    .arg(&out)
                    .arg(source);
                if !cfg!(target_os = "windows") {
                    // Every shared object is position-independent on Windows,
                    // where the flag is a warning rather than a setting, and
                    // fortified libc calls depend on a libc that offers them.
                    cmd.args(["-fPIC", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2"]);
                }
                if !cfg!(any(target_os = "macos", target_os = "windows")) {
                    // Both are ELF link-editor options. Mach-O binds lazily by
                    // design and has no relro section; PE has neither.
                    cmd.args(["-Wl,-z,relro", "-Wl,-z,now"]);
                }
                run(cmd, &format!("{} {}/{}", compiler.join(" "), dir, source))?;
            }
            Kind::ZigShared {
                dir, root: source, ..
            } => {
                ensure_toolchain("zig", &["version"], "Zig toolchain")?;
                let mut cmd = Command::new("zig");
                cmd.current_dir(root.join(dir)).args([
                    "build-lib",
                    "-dynamic",
                    "-lc",
                    "-OReleaseSafe",
                ]);
                if cfg!(target_os = "windows") {
                    // Zig's native target on Windows is the MSVC ABI, whose
                    // libc it can only find if Visual Studio is installed.
                    // The GNU target uses the mingw-w64 Zig ships with, so a
                    // Zig download is the whole toolchain. What comes out is a
                    // plain C ABI DLL either way.
                    cmd.arg("-target").arg(if cfg!(target_arch = "aarch64") {
                        "aarch64-windows-gnu"
                    } else {
                        "x86_64-windows-gnu"
                    });
                }
                cmd.arg("-I")
                    .arg(root.join("leaf-plugin-abi/include"))
                    .arg(format!("-femit-bin={}", out.display()))
                    .arg(source);
                run(cmd, &format!("zig build-lib {}/{}", dir, source))?;
            }
        }
        if !out.exists() {
            bail!("built [{}] but {} is missing", self.id(), out.display());
        }
        Ok(out)
    }
}

/// The set of fixtures the selected scenarios need, resolved once per run.
pub struct FixtureSet {
    resolved: BTreeMap<Fixture, Result<PathBuf, String>>,
}

impl FixtureSet {
    /// Builds every requested fixture, recording why any of them could not be
    /// produced instead of failing the whole run: a missing Go toolchain must
    /// show up as skipped cases, not as a broken harness.
    pub fn build(wanted: &BTreeSet<Fixture>) -> Self {
        let mut resolved = BTreeMap::new();
        for fixture in wanted {
            let outcome = fixture.build().map_err(|err| format!("{:#}", err));
            resolved.insert(*fixture, outcome);
        }
        Self { resolved }
    }

    /// Returns the reason the given requirements cannot be met, if any.
    pub fn unmet(&self, needs: &[Fixture]) -> Option<String> {
        for fixture in needs {
            match self.resolved.get(fixture) {
                Some(Ok(_)) => {}
                Some(Err(reason)) => {
                    return Some(format!(
                        "fixture [{}] unavailable: {}",
                        fixture.id(),
                        reason
                    ))
                }
                None => return Some(format!("fixture [{}] was not built", fixture.id())),
            }
        }
        None
    }

    /// The environment a case child process needs to find its fixtures.
    pub fn env(&self) -> Vec<(String, String)> {
        self.resolved
            .iter()
            .filter_map(|(fixture, outcome)| {
                outcome
                    .as_ref()
                    .ok()
                    .map(|path| (fixture.env_key(), path.display().to_string()))
            })
            .collect()
    }
}

/// Builds for the same target this harness was built for.
///
/// Without this a sanitizer or cross lane, which cargo nests under the triple,
/// would build plugins for the host and then look for them where they are not.
fn add_target(cmd: &mut Command) -> Result<()> {
    if let Some(triple) = paths::target_triple()? {
        cmd.arg("--target").arg(triple);
    }
    Ok(())
}

/// Where one upstream server's checkout and binary live.
///
/// Under the workspace's `target/`, beside cargo's own output but outside any
/// profile: the same server serves a debug run and a release one, and `cargo
/// clean` takes it with everything else. The revision is in the name, so a
/// changed pin builds afresh instead of reusing the wrong binary.
fn upstream_dir(fixture: Fixture) -> Result<PathBuf> {
    let Kind::Upstream { rev, .. } = fixture.kind() else {
        bail!("[{}] is not an upstream server", fixture.id());
    };
    let short = &rev[..rev.len().min(12)];
    Ok(paths::workspace_root()
        .join("target")
        .join("e2e-upstream")
        .join(format!("{}-{}", fixture.id(), short)))
}

fn build_upstream(
    fixture: Fixture,
    repo: &str,
    rev: &str,
    build: UpstreamBuild,
    exe: &str,
) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(fixture.upstream_env_key()) {
        let path = PathBuf::from(path);
        if !path.is_file() {
            bail!(
                "{} names {}, which is not a file",
                fixture.upstream_env_key(),
                path.display()
            );
        }
        return Ok(path);
    }

    let dir = upstream_dir(fixture)?;
    let bin = dir.join("bin").join(exe_file_name(exe));
    if bin.is_file() {
        return Ok(bin);
    }
    let src = dir.join("src");
    if !src.join(".git").is_dir() {
        ensure_toolchain("git", &["--version"], "git")?;
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(&src)?;
        // A fetch of one revision rather than a clone: it works the same for a
        // tag and for a bare commit id, and brings no history along.
        for args in [
            vec!["init", "--quiet"],
            vec!["remote", "add", "origin", repo],
            vec!["fetch", "--quiet", "--depth", "1", "origin", rev],
            vec!["checkout", "--quiet", "FETCH_HEAD"],
        ] {
            let mut cmd = Command::new("git");
            cmd.current_dir(&src).args(&args);
            run(cmd, &format!("git {} ({})", args.join(" "), fixture.id()))?;
        }
    }

    std::fs::create_dir_all(dir.join("bin"))?;
    match build {
        UpstreamBuild::Go { package } => {
            ensure_go()?;
            let mut cmd = Command::new("go");
            cmd.current_dir(&src)
                .env("CGO_ENABLED", "0")
                .args(["build", "-trimpath", "-o"])
                .arg(&bin)
                .arg(package);
            run(cmd, &format!("go build {} ({})", package, fixture.id()))?;
        }
        UpstreamBuild::Cargo => {
            // Through rustup's `cargo`, not the one running this harness, and
            // with none of this run's settings: the server is a separate
            // project with its own lockfile and its own `rust-toolchain`
            // (shadow-tls pins a nightly), and the toolchain cargo exports to
            // a test would override it. A sanitizer flag meant for the harness
            // has no business in it either.
            ensure_toolchain("cargo", &["--version"], "cargo")?;
            let mut cmd = Command::new("cargo");
            cmd.current_dir(&src)
                .env("CARGO_TARGET_DIR", dir.join("target"))
                .env_remove("CARGO")
                .env_remove("RUSTC")
                .env_remove("RUSTDOC")
                .env_remove("RUSTUP_TOOLCHAIN")
                .env_remove("RUSTFLAGS")
                .env_remove("CARGO_BUILD_TARGET")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .args(["build", "--release", "--locked"]);
            run(cmd, &format!("cargo build ({})", fixture.id()))?;
            let built = dir.join("target").join("release").join(exe_file_name(exe));
            std::fs::copy(&built, &bin)
                .with_context(|| format!("copying {} to {}", built.display(), bin.display()))?;
        }
    }
    if !bin.is_file() {
        bail!("built [{}] but {} is missing", fixture.id(), bin.display());
    }
    Ok(bin)
}

fn cargo() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
}

/// Builds a cargo fixture and returns the file cargo says it produced.
///
/// The alternative is to work out where cargo puts things, which is a moving
/// target: the layout under `target/` has changed once already under this
/// harness. Asking for `--message-format=json` costs one flag and a few lines
/// of parsing, and what comes back is not a guess.
fn cargo_artifact(mut cmd: Command, package: &str, kind: &str, stem: &str) -> Result<PathBuf> {
    let what = format!("cargo build -p {}", package);
    // Diagnostics stay human-readable on stderr; only the artifact records go
    // to stdout as JSON.
    cmd.arg("--message-format=json-render-diagnostics");
    let output = capture(cmd, &what)?;

    // Matched by the file cargo produced rather than by the target it records,
    // because a target is not named after its package: leaf-cli's binary is
    // `leaf`. On Windows a cdylib is reported next to its import library, and
    // the loadable half is the one to keep.
    let wanted = [stem.to_string(), format!("lib{}", stem)];
    let found = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|record| record["reason"] == "compiler-artifact")
        .filter(|record| {
            record["target"]["kind"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|k| k == kind))
        })
        .filter_map(|record| {
            record["filenames"].as_array().and_then(|names| {
                names
                    .iter()
                    .filter_map(|name| name.as_str())
                    .find(|name| {
                        Path::new(name)
                            .file_stem()
                            .and_then(|found| found.to_str())
                            .is_some_and(|found| wanted.iter().any(|want| want == found))
                    })
                    .map(PathBuf::from)
            })
        })
        .next_back();
    found.ok_or_else(|| {
        anyhow!(
            "{} reported no {} named [{}]; cargo's own output is the only record of where \
             it puts things, so this is either the wrong name or a cargo that stopped \
             saying",
            what,
            kind,
            stem
        )
    })
}

/// Runs a command, failing with whatever it said when it fails.
fn capture(mut cmd: Command, what: &str) -> Result<std::process::Output> {
    // Cargo exports these for the crate being tested; leaving them set confuses
    // a nested build that is about a different package.
    cmd.env_remove("CARGO_MANIFEST_DIR")
        .env_remove("CARGO_MANIFEST_PATH")
        .env_remove("CARGO_PKG_NAME")
        .env_remove("CARGO_CRATE_NAME");
    let output = cmd
        .output()
        .with_context(|| format!("failed to spawn: {}", what))?;
    if !output.status.success() {
        bail!(
            "{} failed with {}\n--- stderr ---\n{}",
            what,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim_end()
        );
    }
    Ok(output)
}

fn run(cmd: Command, what: &str) -> Result<()> {
    capture(cmd, what).map(|_| ())
}

fn ensure_go() -> Result<()> {
    ensure_toolchain("go", &["version"], "Go toolchain")
}

/// The C compiler to build the C plugin with, and the arguments it carries.
///
/// `cc` everywhere it exists, which is everywhere but Windows; there the
/// plugin needs the GCC-style driver a MinGW or Clang install provides, and
/// `gcc` is the one that comes with MSYS2 and with the toolchain cgo already
/// requires. `CC` overrides both, so a cross or sanitized lane -- or a host
/// whose `gcc` is for the wrong architecture -- can point at the compiler
/// cargo is using.
///
/// It is split on whitespace, the way every other build system reads `CC`,
/// because a driver sometimes needs an argument to be the right compiler at
/// all: `zig cc -target aarch64-windows-gnu` is how one Zig install serves as
/// the GNU toolchain both this plugin and cgo want.
///
/// `LEAF_E2E_CC` comes first because `CC` cannot always be the answer for both
/// halves of a run. Cargo's own C dependencies -- `aws-lc-sys` above all --
/// read `CC` too, and must be built for the Rust target; the plugins and cgo
/// may need a different toolchain entirely. On a host where those disagree,
/// leave `CC` to cargo and put the plugins' compiler here.
fn cc_command() -> Vec<String> {
    let raw = std::env::var("LEAF_E2E_CC")
        .or_else(|_| std::env::var("CC"))
        .unwrap_or_else(|_| {
            if cfg!(target_os = "windows") {
                "gcc".to_string()
            } else {
                "cc".to_string()
            }
        });
    let parts: Vec<String> = raw.split_whitespace().map(str::to_string).collect();
    if parts.is_empty() {
        vec!["cc".to_string()]
    } else {
        parts
    }
}

/// Reports a missing toolchain as an error the runner turns into a skipped
/// case, rather than letting it fail the whole run.
fn ensure_toolchain(program: &str, args: &[&str], what: &str) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("no {} on PATH", what))?;
    if !output.status.success() {
        bail!(
            "`{} {}` failed with {}",
            program,
            args.join(" "),
            output.status
        );
    }
    Ok(())
}

/// The same, for a compiler that comes with arguments of its own.
fn ensure_compiler(compiler: &[String], probe: &str, what: &str) -> Result<()> {
    let (program, leading) = compiler
        .split_first()
        .expect("cc_command never returns an empty command");
    let args: Vec<&str> = leading
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(probe))
        .collect();
    ensure_toolchain(program, &args, what)
}

fn dylib_file_name(stem: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{}.dll", stem)
    } else if cfg!(target_os = "macos") {
        format!("lib{}.dylib", stem)
    } else {
        format!("lib{}.so", stem)
    }
}

fn exe_file_name(stem: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{}.exe", stem)
    } else {
        stem.to_string()
    }
}
