//! The shipped binary, driven as an operator would.
//!
//! Everything else in this suite runs leaf in-process. These cases run the
//! binary, because some things live only there: whether a config that ships in
//! the repository still parses, what an operator is told about a plugin they
//! have not deployed yet, and whether the process actually exits once a plugin
//! has pulled a language runtime of its own into it.

use std::time::Duration;

use anyhow::{ensure, Result};

use crate::client::Socks5;
use crate::fixtures::Fixture;
use crate::flow;
use crate::node::{cfg, Node};
use crate::paths;
use crate::process::{self, CliNode};
use crate::scenario::{boxed, Scenario, Tag};
use crate::servers::Origin;

/// Generous: a shutdown that takes this long is a hang, and a hang is what this
/// is looking for.
const EXIT_TIMEOUT: Duration = Duration::from_secs(15);

pub fn scenarios() -> Vec<Scenario> {
    let mut scenarios =
        vec![
            Scenario::new("blackbox/example-configs-are-valid", "blackbox", || {
                boxed(example_configs_are_valid())
            })
            .tags([Tag::Cli])
            .needs([Fixture::LeafCli])
            .timeout(Duration::from_secs(60)),
            Scenario::new(
                "blackbox/verify-plugin-reports-what-the-loader-sees",
                "blackbox",
                || boxed(verify_plugin_reports_what_the_loader_sees()),
            )
            .tags([Tag::Cli, Tag::Plugin])
            .needs([
                Fixture::LeafCli,
                Fixture::ShadowsocksCabiRs,
                Fixture::TlsCabiRs,
            ])
            .timeout(Duration::from_secs(60)),
        ];

    // The two cases below end by asking the process to shut itself down, which
    // means sending the interrupt leaf listens for. There is no equivalent to
    // send on Windows without leaf and this harness agreeing on a console
    // control event, so they are not registered there rather than registered
    // and failed -- `--strict` cannot tell a case that could not run from one
    // that ran badly, and everything else in the suite runs on Windows.
    if cfg!(unix) {
        scenarios.push(
            Scenario::new(
                "blackbox/carries-traffic-through-a-plugin",
                "blackbox",
                || boxed(carries_traffic()),
            )
            .tags([Tag::Cli, Tag::Plugin])
            .needs([Fixture::LeafCli, Fixture::Conformance])
            .timeout(Duration::from_secs(60)),
        );
        scenarios.push(
            Scenario::new(
                "blackbox/exits-with-a-go-runtime-loaded",
                "blackbox",
                || boxed(exits_with_a_go_runtime_loaded()),
            )
            .tags([Tag::Cli, Tag::Plugin, Tag::Go])
            .needs([Fixture::LeafCli, Fixture::TlsCabiGo])
            .timeout(Duration::from_secs(60)),
        );
    }
    scenarios
}

/// The configs in `examples/` are documentation, and documentation rots. `-T`
/// parses one and exits, which is exactly the check nothing else performs.
async fn example_configs_are_valid() -> Result<()> {
    let root = paths::workspace_root().join("examples");
    let mut configs = Vec::new();
    collect_json(&root, &mut configs)?;
    configs.sort();
    ensure!(
        !configs.is_empty(),
        "no example configs found under {}",
        root.display()
    );

    for config in &configs {
        process::test_config(config)?;
    }
    Ok(())
}

/// `--verify-plugin` is the answer to "will this load, and what will its
/// outbound have to say?", asked before the plugin is anywhere near traffic.
/// It is worth having only if it agrees with the loader, so this checks it
/// against two plugins whose shapes the rest of the suite already relies on:
/// one that dials a server of its own, one that layers on what precedes it.
async fn verify_plugin_reports_what_the_loader_sees() -> Result<()> {
    let shadowsocks = Fixture::ShadowsocksCabiRs.path()?;
    let (ok, report) = process::verify_plugin(&shadowsocks, None)?;
    ensure!(ok, "the shadowsocks plugin was rejected: {report}");
    for expected in [
        "connect_type=proxy-tcp",
        "the outbound must set host and port",
        "transport_type=unreliable",
    ] {
        ensure!(
            report.contains(expected),
            "the report does not mention [{expected}]: {report}"
        );
    }

    let tls = Fixture::TlsCabiRs.path()?;
    let (ok, report) = process::verify_plugin(&tls, None)?;
    ensure!(ok, "the TLS plugin was rejected: {report}");
    for expected in [
        "connect_type=next",
        "the outbound must not set host and port",
        "datagram:  none",
    ] {
        ensure!(
            report.contains(expected),
            "the report does not mention [{expected}]: {report}"
        );
    }

    // The digest the report gives is the value an operator puts in `sha256`,
    // so it has to be the one the pin check accepts. Reading it back out of
    // the report and handing it straight back is that round trip.
    let digest = report
        .lines()
        .find_map(|line| line.strip_prefix("sha256:"))
        .map(str::trim)
        .filter(|digest| digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow::anyhow!("the report carries no sha256: {report}"))?
        .to_string();
    let (ok, output) = process::verify_plugin(&tls, Some(&digest))?;
    ensure!(ok, "the digest the report gave was refused: {output}");

    let (ok, output) = process::verify_plugin(&tls, Some(&"0".repeat(64)))?;
    ensure!(!ok, "a plugin was accepted against a digest it does not have");
    ensure!(
        output.contains("sha256 pin"),
        "a refused pin did not say so: {output}"
    );

    // The rule that a bare name is never looked up along the library search
    // path is the loader's, and it holds here for the same reason.
    let (ok, output) = process::verify_plugin(std::path::Path::new("libtls_cabi_rs.so"), None)?;
    ensure!(!ok, "a bare library name was accepted: {output}");
    ensure!(
        output.contains("bare library name"),
        "a refused bare name did not say why: {output}"
    );

    Ok(())
}

fn collect_json(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_json(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "json") {
            out.push(path);
        }
    }
    Ok(())
}

/// A real process, a config file on disk, a plugin loaded from a path in it,
/// and traffic through the result.
async fn carries_traffic() -> Result<()> {
    let origin = Origin::tcp_echo().await?;
    let node = Node::new("client").socks_inbound()?.outbound(cfg::plugin(
        "conformance",
        &Fixture::Conformance.path()?,
        Some(origin.addr()),
        "",
    ));
    let cli = CliNode::start("carries-traffic", &node).await?;

    let mut stream = Socks5::new(cli.socks_addr()).connect(origin.addr()).await?;
    flow::echo_roundtrip(&mut stream, b"hello").await?;
    drop(stream);

    cli.interrupt_and_wait(EXIT_TIMEOUT).await
}

/// The hazard the ABI warns about: a Go `c-shared` build leaves a thread that
/// has called into it unable to exit cleanly. Long-lived executor threads
/// satisfy that in practice -- but only a real process can show whether the
/// whole thing still shuts down.
async fn exits_with_a_go_runtime_loaded() -> Result<()> {
    let node = Node::new("client").socks_inbound()?.outbound(cfg::plugin(
        "go-tls",
        &Fixture::TlsCabiGo.path()?,
        None,
        r#"{"server_name":"localhost","insecure":true}"#,
    ));
    let cli = CliNode::start("go-runtime", &node).await?;
    cli.interrupt_and_wait(EXIT_TIMEOUT).await
}
