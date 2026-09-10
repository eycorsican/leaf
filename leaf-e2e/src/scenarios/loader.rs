//! What the host refuses to load, observed from the outside.
//!
//! These rules live in the plugin host and decide whether a deployment starts
//! at all, so they are checked the way an operator meets them: a config, a
//! start, and the message leaf prints. None of them is reachable from a test
//! that constructs handlers directly.

use std::time::Duration;

use anyhow::{ensure, Result};
use serde_json::json;

use crate::fixtures::Fixture;
use crate::net;
use crate::node::{cfg, Node};
use crate::scenario::{boxed, Scenario, Tag};

pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario::new("loader/rejects-missing-library", "loader", || {
            boxed(rejects_missing_library())
        })
        .tags([Tag::Native])
        .timeout(Duration::from_secs(20)),
        Scenario::new("loader/rejects-empty-path", "loader", || {
            boxed(rejects_empty_path())
        })
        .tags([Tag::Native])
        .timeout(Duration::from_secs(20)),
        Scenario::new(
            "loader/proxy-tcp-engine-requires-endpoint",
            "loader",
            || boxed(proxy_tcp_engine_requires_endpoint()),
        )
        .tags([Tag::Plugin])
        .needs([Fixture::ShadowsocksCabiRs])
        .timeout(Duration::from_secs(20)),
        Scenario::new(
            "loader/proxy-tcp-engine-rejects-half-an-endpoint",
            "loader",
            || boxed(proxy_tcp_engine_rejects_half_an_endpoint()),
        )
        .tags([Tag::Plugin])
        .needs([Fixture::ShadowsocksCabiRs])
        .timeout(Duration::from_secs(20)),
        Scenario::new(
            "loader/next-engine-rejects-explicit-endpoint",
            "loader",
            || boxed(next_engine_rejects_explicit_endpoint()),
        )
        .tags([Tag::Plugin])
        .needs([Fixture::TlsCabiRs])
        .timeout(Duration::from_secs(20)),
        Scenario::new("loader/go-tls-plugin-loads", "loader", || {
            boxed(go_tls_plugin_loads())
        })
        .tags([Tag::Plugin, Tag::Go])
        .needs([Fixture::TlsCabiGo])
        .timeout(Duration::from_secs(30)),
        Scenario::new("loader/go-trojan-plugin-loads", "loader", || {
            boxed(go_trojan_plugin_loads())
        })
        .tags([Tag::Plugin, Tag::Go])
        .needs([Fixture::TrojanCabiGo])
        .timeout(Duration::from_secs(30)),
        Scenario::new("loader/c-socks5-plugin-loads", "loader", || {
            boxed(proxy_tcp_plugin_loads(Fixture::Socks5CabiC))
        })
        .tags([Tag::Plugin, Tag::Cc])
        .needs([Fixture::Socks5CabiC])
        .timeout(Duration::from_secs(30)),
        Scenario::new("loader/zig-socks5-plugin-loads", "loader", || {
            boxed(proxy_tcp_plugin_loads(Fixture::Socks5CabiZig))
        })
        .tags([Tag::Plugin, Tag::Zig])
        .needs([Fixture::Socks5CabiZig])
        .timeout(Duration::from_secs(30)),
    ]
}

/// A plugin with `connect_type = ProxyTcp` loads, is registered, and lets the
/// node start. Nothing is sent through it: what is under test is the path from
/// a config file to a mapped library and a handler.
async fn proxy_tcp_plugin_loads(fixture: Fixture) -> Result<()> {
    let endpoint = net::loopback(net::reserve_dual_port()?);
    let node = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "socks5-out",
            &fixture.path()?,
            Some(endpoint),
            "",
        ))
        .start()
        .await?;
    node.shutdown().await
}

/// A path that does not resolve must fail the start, naming the tag.
async fn rejects_missing_library() -> Result<()> {
    let missing = std::env::temp_dir().join("leaf-e2e-there-is-no-such-plugin.dylib");
    let error = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin("broken", &missing, None, ""))
        .start_expecting_failure()
        .await?;
    ensure!(
        error.contains("failed to load plugin outbound") && error.contains("broken"),
        "unexpected error: {}",
        error
    );
    Ok(())
}

/// An omitted path is a config mistake, and must be reported as one rather than
/// reaching the loader.
async fn rejects_empty_path() -> Result<()> {
    let error = Node::new("client")
        .socks_inbound()?
        .outbound(json!({
            "protocol": "plugin",
            "tag": "no-path",
            "settings": { "path": "", "args": "" },
        }))
        .start_expecting_failure()
        .await?;
    ensure!(
        error.contains("plugin path is empty"),
        "unexpected error: {}",
        error
    );
    Ok(())
}

/// An engine that connects to its own server cannot be told where that is only
/// by omission.
async fn proxy_tcp_engine_requires_endpoint() -> Result<()> {
    let error = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "ss-plugin",
            &Fixture::ShadowsocksCabiRs.path()?,
            None,
            "aes-128-gcm;password",
        ))
        .start_expecting_failure()
        .await?;
    ensure!(
        error.contains("requires explicit host and port"),
        "unexpected error: {}",
        error
    );
    Ok(())
}

/// Half an endpoint is worse than none: it looks configured but is not.
async fn proxy_tcp_engine_rejects_half_an_endpoint() -> Result<()> {
    let error = Node::new("client")
        .socks_inbound()?
        .outbound(json!({
            "protocol": "plugin",
            "tag": "ss-plugin",
            "settings": {
                "path": Fixture::ShadowsocksCabiRs.path()?.display().to_string(),
                "args": "aes-128-gcm;password",
                "host": "127.0.0.1",
            },
        }))
        .start_expecting_failure()
        .await?;
    ensure!(
        error.contains("requires both host and port"),
        "unexpected error: {}",
        error
    );
    Ok(())
}

/// An engine that layers over the next actor in a chain names no endpoint, and
/// a config that gives it one is a misunderstanding worth refusing.
async fn next_engine_rejects_explicit_endpoint() -> Result<()> {
    let error = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "tls-plugin",
            &Fixture::TlsCabiRs.path()?,
            Some(net::loopback(443)),
            r#"{"server_name":"example.com"}"#,
        ))
        .start_expecting_failure()
        .await?;
    ensure!(
        error.contains("must not set host/port"),
        "unexpected error: {}",
        error
    );
    Ok(())
}

/// Loading a plugin that embeds a Go runtime, and then shutting the node down.
///
/// Both halves matter. The load proves the descriptor a `c-shared` build
/// exports is one the host accepts; the shutdown proves the node still stops,
/// which is the failure mode the ABI warns about -- a Go runtime makes a host
/// thread that has called into it unable to exit cleanly.
async fn go_tls_plugin_loads() -> Result<()> {
    // `connect_type = Next`: this engine layers over whatever the chain hands
    // it, so it names no endpoint.
    let node = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "go-tls",
            &Fixture::TlsCabiGo.path()?,
            None,
            r#"{"server_name":"localhost","insecure":true}"#,
        ))
        .start()
        .await?;
    node.shutdown().await
}

/// The Go Trojan plugin exports a stream engine and a reliable datagram engine,
/// so a successful start means both vtables passed validation and both handlers
/// were registered.
async fn go_trojan_plugin_loads() -> Result<()> {
    let node = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "go-trojan",
            &Fixture::TrojanCabiGo.path()?,
            Some(net::loopback(net::reserve_dual_port()?)),
            "password",
        ))
        .start()
        .await?;
    node.shutdown().await
}
