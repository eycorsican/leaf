//! Whether the end of a request reaches the far end.
//!
//! A client that has finished sending says so by closing its write side, and
//! keeps reading. Plenty of protocols end a request that way and nothing else:
//! an HTTP body with no length, a `cat file | nc`, an upload to something that
//! answers only once it has everything. If the end of the request stops at any
//! stage of a proxy chain, the far end waits for more that will never come,
//! and what the client sees is not an error but a delay -- until leaf's own
//! idle timeout ends the session ten seconds later.
//!
//! Each case here is one transport carrying one half-close, so a failure names
//! the stage rather than the chain. They are leaf against leaf: no plugin is
//! involved, and the plugin chains are covered by `differential/*/half-close`.
//!
//! This is how the websocket transport was caught: everything else propagated
//! the end of a request and the two websocket paths did not. WebSocket has no
//! half close of its own, so leaf sends a Close frame for it -- which its own
//! read side has always understood as the end of the peer's side alone, but
//! which a stricter peer may answer by hanging up. That is why it is behind
//! `WS_HALF_CLOSE`, and why the websocket cases here set it: they are about
//! what the transport can carry, not about what is safe to assume of an
//! unknown server.
//!
//! The deadline is short on purpose. leaf's uplink and downlink idle timeouts
//! default to ten seconds, and a session that ends on one of those *does*
//! deliver the end of stream in the end -- so a case that waited that long
//! would pass whether or not anything propagated. Three seconds separates "it
//! travelled" from "it timed out".

use std::time::Duration;

use anyhow::{ensure, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::client::Socks5;
use crate::differential::{Deployment, DeploymentFuture, Net};
use crate::net;
use crate::node::{cfg, Node};
use crate::scenario::{boxed, Scenario, Tag};
use crate::servers::{self, Origin};
use crate::tls;

const SS_METHOD: &str = "aes-128-gcm";
const PASSWORD: &str = "e2e-password";
const WS_PATH: &str = "/leaf";

/// How long the end of a request may take to cross the chain.
///
/// Everything here is loopback and a handful of frames; the only thing that
/// takes longer than a millisecond is a timeout.
const VERDICT: Duration = Duration::from_secs(3);

/// One transport, carrying one half-close.
#[derive(Clone, Copy)]
enum Path {
    /// No proxy protocol at all: leaf's socks inbound straight to a direct
    /// outbound. The baseline -- if this fails, nothing else means anything.
    Direct,
    Shadowsocks,
    Socks5,
    /// `chain[trojan]`, and then the same with each transport layered over it,
    /// so a failure names the layer that swallowed the end of the request.
    Trojan,
    WsTrojan,
    TlsTrojan,
    TlsWsTrojan,
}

impl Path {
    fn name(self) -> &'static str {
        match self {
            Path::Direct => "direct",
            Path::Shadowsocks => "shadowsocks",
            Path::Socks5 => "socks5",
            Path::Trojan => "trojan",
            Path::WsTrojan => "ws-trojan",
            Path::TlsTrojan => "tls-trojan",
            Path::TlsWsTrojan => "tls-ws-trojan",
        }
    }

    /// The actors the client chains together, outermost first.
    fn layers(self) -> &'static [&'static str] {
        match self {
            Path::Trojan => &["trojan"],
            Path::WsTrojan => &["ws", "trojan"],
            Path::TlsTrojan => &["tls", "trojan"],
            Path::TlsWsTrojan => &["tls", "ws", "trojan"],
            _ => &[],
        }
    }

    /// Whether this path needs leaf told to signal a half close at all.
    ///
    /// Only the websocket transport does: it has nothing of its own to say it
    /// with, and what leaf sends instead is off by default.
    fn needs_ws_half_close(self) -> bool {
        self.layers().contains(&"ws")
    }

    fn deploy(self) -> DeploymentFuture {
        match self {
            Path::Direct => Box::pin(deploy_direct()),
            Path::Shadowsocks => Box::pin(deploy_shadowsocks()),
            Path::Socks5 => Box::pin(deploy_socks5()),
            other => Box::pin(deploy_chain(other)),
        }
    }
}

pub fn scenarios() -> Vec<Scenario> {
    [
        Path::Direct,
        Path::Shadowsocks,
        Path::Socks5,
        Path::Trojan,
        Path::WsTrojan,
        Path::TlsTrojan,
        Path::TlsWsTrojan,
    ]
    .into_iter()
    .map(|path| {
        let mut scenario = Scenario::new(
            format!("half-close/{}", path.name()),
            "half-close",
            move || boxed(request_end_reaches_the_far_end(path)),
        )
        .tags([Tag::Native])
        .timeout(Duration::from_secs(45));
        if path.needs_ws_half_close() {
            // "true", not "1": leaf parses its boolean options with
            // `bool::from_str`, which takes only the words.
            scenario = scenario.env("WS_HALF_CLOSE", "true");
        }
        scenario
    })
    .collect()
}

/// The client finishes its request and closes its write side. The far end has
/// to see the end of stream.
async fn request_end_reaches_the_far_end(path: Path) -> Result<()> {
    let probe = Origin::tcp_eof_reporter().await?;
    let deployment = path.deploy().await?;
    let net: Net = deployment.net();

    let mut stream = net
        .socks
        .connect(probe.addr())
        .await
        .context("opening the connection")?;
    stream
        .write_all(b"the whole request")
        .await
        .context("writing the request")?;
    stream.flush().await?;
    stream
        .shutdown()
        .await
        .context("closing the write side of the connection")?;

    let mut marker = [0u8; 1];
    tokio::time::timeout(VERDICT, stream.read_exact(&mut marker))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "the far end had not seen the end of the request after {:?}: it stopped \
                 somewhere in [{}]",
                VERDICT,
                path.name()
            )
        })?
        .context("reading the far end's answer")?;
    ensure!(
        marker[0] == servers::EOF_SEEN,
        "the far end answered {:#04x} rather than the end-of-request marker",
        marker[0]
    );

    deployment.shutdown().await
}

/// `socks -> direct -> origin`, in one node.
async fn deploy_direct() -> Result<Deployment> {
    let client = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::direct("direct"))
        .start()
        .await?;
    Ok(Deployment::new(
        probe_net(client.socks_addr()?),
        vec![client],
        Vec::new(),
    ))
}

/// `socks -> shadowsocks -> leaf shadowsocks -> direct -> origin`.
async fn deploy_shadowsocks() -> Result<Deployment> {
    let port = net::reserve_dual_port()?;
    let server = Node::new("server")
        .inbound(cfg::shadowsocks_inbound("ss-in", port, SS_METHOD, PASSWORD))
        .outbound(cfg::direct("direct"))
        .start()
        .await?;
    let client = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::shadowsocks(
            "ss-out",
            net::loopback(port),
            SS_METHOD,
            PASSWORD,
        ))
        .start()
        .await?;
    Ok(Deployment::new(
        probe_net(client.socks_addr()?),
        vec![client, server],
        Vec::new(),
    ))
}

/// `socks -> socks5 -> leaf socks -> direct -> origin`.
async fn deploy_socks5() -> Result<Deployment> {
    let port = net::reserve_dual_port()?;
    let server = Node::new("server")
        .inbound(cfg::socks_inbound("socks-in", port))
        .outbound(cfg::direct("direct"))
        .start()
        .await?;
    let client = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::socks("socks-out", net::loopback(port), "", ""))
        .start()
        .await?;
    Ok(Deployment::new(
        probe_net(client.socks_addr()?),
        vec![client, server],
        Vec::new(),
    ))
}

/// `socks -> chain[...] -> leaf chain[...] -> direct -> origin`, with the
/// layers the path names.
async fn deploy_chain(path: Path) -> Result<Deployment> {
    let certificate = tls::self_signed()?;
    let port = net::reserve_dual_port()?;

    let inbound_actors: Vec<String> = path
        .layers()
        .iter()
        .map(|layer| format!("{}-in", layer))
        .collect();
    let inbound_refs: Vec<&str> = inbound_actors.iter().map(String::as_str).collect();
    let mut server = Node::new("server")
        .inbound(cfg::chain_inbound("chain-in", port, &inbound_refs))
        .outbound(cfg::direct("direct"));
    for layer in path.layers() {
        server = server.inbound(match *layer {
            "tls" => cfg::tls_inbound(
                "tls-in",
                &certificate.certificate_pem,
                &certificate.private_key_pem,
            ),
            "ws" => cfg::ws_inbound("ws-in", WS_PATH),
            "trojan" => cfg::trojan_inbound("trojan-in", PASSWORD),
            other => unreachable!("unknown layer {}", other),
        });
    }
    let server = server.start().await?;

    let outbound_actors: Vec<String> = path
        .layers()
        .iter()
        .map(|layer| format!("{}-out", layer))
        .collect();
    let outbound_refs: Vec<&str> = outbound_actors.iter().map(String::as_str).collect();
    let mut client = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::chain("chain-out", &outbound_refs));
    for layer in path.layers() {
        client = client.outbound(match *layer {
            "tls" => cfg::tls("tls-out", tls::SERVER_NAME, true),
            "ws" => cfg::ws("ws-out", WS_PATH),
            // The innermost actor is the one that names the server.
            "trojan" => cfg::trojan("trojan-out", net::loopback(port), PASSWORD),
            other => unreachable!("unknown layer {}", other),
        });
    }
    let client = client.start().await?;

    Ok(Deployment::new(
        probe_net(client.socks_addr()?),
        vec![client, server],
        Vec::new(),
    ))
}

/// A `Net` for a case that names its own destination.
///
/// The probe origin is created by the case rather than by the topology, so the
/// addresses a topology usually carries are the client's own socks inbound.
fn probe_net(socks: std::net::SocketAddr) -> Net {
    let unused = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    Net {
        socks: Socks5::new(socks),
        tcp_origin: unused,
        tcp_sink: unused,
        tcp_source: unused,
        tcp_discard: unused,
        udp_origin: unused,
    }
}
