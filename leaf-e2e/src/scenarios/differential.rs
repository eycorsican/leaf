//! Plugins measured against the implementation they stand in for.
//!
//! Each case runs one behaviour twice: once over a topology built entirely from
//! leaf's own protocols, once with a plugin substituted for one stage of it,
//! and requires the two to agree. Everything else stays fixed, so a
//! disagreement can only come from the substitution.
//!
//! The server is always stock leaf. That is what makes these interoperability
//! tests and not round-trips: the bytes a plugin puts on the wire have to be
//! the protocol, not merely something the same plugin can read back.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde_json::Value;

use crate::behaviours;
use crate::client::Socks5;
use crate::differential::{
    compare, compare_cost, Behaviour, Deployment, DeploymentFuture, Meter, Net, Topology,
};
use crate::fixtures::Fixture;
use crate::meters;
use crate::net;
use crate::node::{cfg, Node, ENV_LOG_LEVEL};
use crate::scenario::{boxed, Scenario, Tag};
use crate::servers::Origin;
use crate::tls;

const SS_METHOD: &str = "aes-128-gcm";
const SS_PASSWORD: &str = "e2e-password";
const TROJAN_PASSWORD: &str = "e2e-password";
const SOCKS_USERNAME: &str = "leaf";
const SOCKS_PASSWORD: &str = "e2e-password";
const WS_PATH: &str = "/leaf";
/// What the sink origin reads before closing; the `peer-closes-first`
/// behaviour writes exactly this much.
const SINK_BYTES: usize = 32;

/// Which implementation fills one stage of a topology.
#[derive(Clone, Copy)]
pub(crate) enum Stage {
    Native,
    Plugin(Fixture),
}

impl Stage {
    fn fixture(self) -> Option<Fixture> {
        match self {
            Stage::Native => None,
            Stage::Plugin(fixture) => Some(fixture),
        }
    }
}

/// One column of the matrix: a set of substitutions with a name.
///
/// Shared with the stress registry, which runs its loads over the same
/// topologies: a plugin that is correct on one connection and wrong on sixty is
/// the same substitution seen under a different light.
pub(crate) struct Candidate {
    /// Appears in the case id.
    pub(crate) name: &'static str,
    pub(crate) group: Group,
    pub(crate) suite: Suite,
}

/// Which behaviours a candidate is run through.
#[derive(Clone, Copy)]
pub(crate) enum Suite {
    /// Every stream behaviour, and the datagram one.
    Full,
    /// Every stream behaviour. For a plugin with no datagram engine, which is a
    /// shape the ABI allows and the host registers for TCP only.
    StreamOnly,
    /// One exchange. Enough for a variation that differs only in how the
    /// handshake is authenticated, where the rest of the suite would re-test
    /// the same data path.
    Handshake,
}

impl Suite {
    /// Whether this candidate's plugin registers a datagram engine at all.
    pub(crate) fn carries_datagrams(self) -> bool {
        matches!(self, Suite::Full)
    }

    fn behaviours(self) -> Vec<(Behaviour, Vec<Tag>)> {
        match self {
            Suite::Full => behaviours::stream_suite()
                .into_iter()
                .chain([(behaviours::UDP, vec![])])
                .collect(),
            Suite::StreamOnly => behaviours::stream_suite(),
            Suite::Handshake => vec![(behaviours::ECHO, vec![])],
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Group {
    /// Client routes straight through a shadowsocks outbound.
    Shadowsocks { outbound: Stage },
    /// Client routes through `chain[tls, ws, trojan]`.
    TlsChain { tls: Stage, trojan: Stage },
    /// Client routes straight through a SOCKS5 outbound to a leaf socks
    /// inbound, with or without credentials.
    Socks5 { outbound: Stage, auth: bool },
}

impl Group {
    pub(crate) fn native(self) -> Group {
        match self {
            Group::Shadowsocks { .. } => Group::Shadowsocks {
                outbound: Stage::Native,
            },
            Group::TlsChain { .. } => Group::TlsChain {
                tls: Stage::Native,
                trojan: Stage::Native,
            },
            Group::Socks5 { auth, .. } => Group::Socks5 {
                outbound: Stage::Native,
                auth,
            },
        }
    }

    pub(crate) fn fixtures(self) -> Vec<Fixture> {
        match self {
            Group::Shadowsocks { outbound } | Group::Socks5 { outbound, .. } => {
                outbound.fixture().into_iter().collect()
            }
            Group::TlsChain { tls, trojan } => [tls.fixture(), trojan.fixture()]
                .into_iter()
                .flatten()
                .collect(),
        }
    }

    pub(crate) fn deploy(self) -> DeploymentFuture {
        match self {
            Group::Shadowsocks { outbound } => Box::pin(deploy_shadowsocks(outbound)),
            Group::TlsChain { tls, trojan } => Box::pin(deploy_tls_chain(tls, trojan)),
            Group::Socks5 { outbound, auth } => Box::pin(deploy_socks5(outbound, auth)),
        }
    }
}

/// The tags that say which toolchains a set of fixtures needs, so a lane
/// without one skips the cases rather than failing them.
pub(crate) fn toolchain_tags(fixtures: &[Fixture]) -> Vec<Tag> {
    [
        (Tag::Go, Fixture::needs_go as fn(Fixture) -> bool),
        (Tag::Cc, Fixture::needs_cc as fn(Fixture) -> bool),
        (Tag::Zig, Fixture::needs_zig as fn(Fixture) -> bool),
    ]
    .into_iter()
    .filter(|(_, needed)| fixtures.iter().copied().any(needed))
    .map(|(tag, _)| tag)
    .collect()
}

/// The matrix both this registry and the stress one are generated from.
pub(crate) fn candidates() -> Vec<Candidate> {
    vec![
        Candidate {
            name: "shadowsocks",
            group: Group::Shadowsocks {
                outbound: Stage::Plugin(Fixture::ShadowsocksCabiRs),
            },
            suite: Suite::Full,
        },
        Candidate {
            name: "tls-chain/tls-cabi-rs",
            group: Group::TlsChain {
                tls: Stage::Plugin(Fixture::TlsCabiRs),
                trojan: Stage::Native,
            },
            suite: Suite::Full,
        },
        Candidate {
            name: "tls-chain/tls-cabi-go",
            group: Group::TlsChain {
                tls: Stage::Plugin(Fixture::TlsCabiGo),
                trojan: Stage::Native,
            },
            suite: Suite::Full,
        },
        Candidate {
            name: "tls-chain/all-go",
            group: Group::TlsChain {
                tls: Stage::Plugin(Fixture::TlsCabiGo),
                trojan: Stage::Plugin(Fixture::TrojanCabiGo),
            },
            suite: Suite::Full,
        },
        // The same protocol in two languages with no runtime of their own,
        // measured against leaf's own SOCKS5 outbound. Neither exports a
        // datagram engine, so neither carries the UDP behaviour: an outbound
        // registered for TCP only is a shape the ABI allows.
        Candidate {
            name: "socks5/c",
            group: Group::Socks5 {
                outbound: Stage::Plugin(Fixture::Socks5CabiC),
                auth: false,
            },
            suite: Suite::StreamOnly,
        },
        Candidate {
            name: "socks5/zig",
            group: Group::Socks5 {
                outbound: Stage::Plugin(Fixture::Socks5CabiZig),
                auth: false,
            },
            suite: Suite::StreamOnly,
        },
        // The username and password exchange is a second handshake before the
        // request, and the only part of the protocol these add.
        Candidate {
            name: "socks5/c-auth",
            group: Group::Socks5 {
                outbound: Stage::Plugin(Fixture::Socks5CabiC),
                auth: true,
            },
            suite: Suite::Handshake,
        },
        Candidate {
            name: "socks5/zig-auth",
            group: Group::Socks5 {
                outbound: Stage::Plugin(Fixture::Socks5CabiZig),
                auth: true,
            },
            suite: Suite::Handshake,
        },
    ]
}

pub fn scenarios() -> Vec<Scenario> {
    let mut scenarios = Vec::new();
    for candidate in candidates() {
        let fixtures = candidate.group.fixtures();
        let toolchains = toolchain_tags(&fixtures);

        for (behaviour, extra_tags) in candidate.suite.behaviours() {
            let group = candidate.group;
            let mut tags = vec![Tag::Plugin, Tag::Differential];
            tags.extend(toolchains.iter().copied());
            tags.extend(extra_tags.iter().copied());
            let slow = extra_tags.contains(&Tag::Slow);

            let mut scenario = Scenario::new(
                format!("differential/{}/{}", candidate.name, behaviour.name),
                "differential",
                move || boxed(run(group, behaviour)),
            )
            .tags(tags)
            .needs(fixtures.clone())
            // Two full deployments per case, and the bulk one moves megabytes
            // through both.
            .timeout(if slow {
                Duration::from_secs(120)
            } else {
                Duration::from_secs(60)
            });
            // `debug` rather than `trace`: trace on a case that moves
            // megabytes is mostly the transfer logging itself. It is not
            // `info`, which is what this was, because the line that says how
            // the relay ended -- `transfer end` or `transfer err=...` -- is a
            // `debug` one, and a bulk case that fails without it in the
            // artifact cannot be diagnosed from CI at all. The difference is
            // about a tenth of the log; the stress lane below, where it is
            // eight times, keeps `info`.
            if slow {
                scenario = scenario.env(ENV_LOG_LEVEL, "debug");
            }
            scenarios.push(scenario);
        }

        // What the boundary costs, measured against the same native topology.
        // Only the primary candidates carry these: a third opinion on the same
        // question is not worth the wall clock.
        if !is_primary(candidate.name) {
            continue;
        }
        for entry in meters::all() {
            // A candidate whose plugin registers no datagram engine has no UDP
            // path to measure; the host registers it for TCP only.
            if entry.datagram && !candidate.suite.carries_datagrams() {
                continue;
            }
            let group = candidate.group;
            let meter = entry.meter;
            let mut tags = vec![Tag::Plugin, Tag::Perf, Tag::Slow];
            tags.extend(toolchains.iter().copied());
            tags.extend(entry.extra_tags.iter().copied());
            scenarios.push(
                Scenario::new(
                    format!("perf/{}/{}", candidate.name, meter.name),
                    "perf",
                    move || boxed(measure(group, meter)),
                )
                .tags(tags)
                .needs(fixtures.clone())
                // Both topologies, measured three times each. `info` here is
                // not the bulk cases' oversight above: this case exists to
                // produce numbers, and logging is work the numbers would
                // include.
                .env(ENV_LOG_LEVEL, "info")
                .timeout(Duration::from_secs(180)),
            );
        }
    }
    scenarios
}

/// Which candidates carry the expensive lanes: the cost meters and the loads.
///
/// A third opinion on the same question is not worth the wall clock, so this is
/// one protocol plugin, one transport plugin, and one plugin in a language with
/// no runtime of its own. The host under all of them is the same host.
pub(crate) fn is_primary(candidate: &str) -> bool {
    matches!(
        candidate,
        "shadowsocks" | "tls-chain/tls-cabi-rs" | "socks5/c"
    )
}

async fn measure(group: Group, meter: Meter) -> Result<()> {
    let native = group.native();
    let oracle: Topology = Arc::new(move || native.deploy());
    let candidate: Topology = Arc::new(move || group.deploy());
    compare_cost(&oracle, &candidate, meter).await
}

async fn run(group: Group, behaviour: Behaviour) -> Result<()> {
    let native = group.native();
    let oracle: Topology = Arc::new(move || native.deploy());
    let candidate: Topology = Arc::new(move || group.deploy());
    compare(&oracle, &candidate, behaviour).await
}

/// `socks -> shadowsocks -> leaf shadowsocks server -> direct -> origin`
async fn deploy_shadowsocks(outbound: Stage) -> Result<Deployment> {
    let tcp_origin = Origin::tcp_echo().await?;
    let udp_origin = Origin::udp_echo().await?;
    let tcp_sink = Origin::tcp_sink(SINK_BYTES).await?;
    let tcp_source = Origin::tcp_source().await?;
    let tcp_discard = Origin::tcp_discard(meters::STREAM_BYTES).await?;

    let server_port = net::reserve_dual_port()?;
    let server = Node::new("server")
        .dns_host(behaviours::TEST_DOMAIN, &["127.0.0.1"])
        .inbound(cfg::shadowsocks_inbound(
            "ss-in",
            server_port,
            SS_METHOD,
            SS_PASSWORD,
        ))
        .outbound(cfg::direct("direct"))
        .start()
        .await?;

    let server_addr = net::loopback(server_port);
    let client = Node::new("client")
        .socks_inbound()?
        .outbound(match outbound {
            Stage::Native => cfg::shadowsocks("ss-out", server_addr, SS_METHOD, SS_PASSWORD),
            Stage::Plugin(fixture) => cfg::plugin(
                "ss-out",
                &fixture.path()?,
                Some(server_addr),
                &format!("{};{}", SS_METHOD, SS_PASSWORD),
            ),
        })
        .start()
        .await?;

    let net = Net {
        socks: Socks5::new(client.socks_addr()?),
        tcp_origin: tcp_origin.addr(),
        tcp_sink: tcp_sink.addr(),
        tcp_source: tcp_source.addr(),
        tcp_discard: tcp_discard.addr(),
        udp_origin: udp_origin.addr(),
    };
    // Client first: it has to stop before the server it talks to.
    Ok(Deployment::new(
        net,
        vec![client, server],
        vec![tcp_origin, udp_origin, tcp_sink, tcp_source, tcp_discard],
    ))
}

/// `socks -> socks5 -> leaf socks inbound -> direct -> origin`
///
/// The server is a stock leaf socks inbound, so what the plugin puts on the
/// wire has to be SOCKS5 rather than merely something it can read back.
async fn deploy_socks5(outbound: Stage, auth: bool) -> Result<Deployment> {
    let tcp_origin = Origin::tcp_echo().await?;
    let udp_origin = Origin::udp_echo().await?;
    let tcp_sink = Origin::tcp_sink(SINK_BYTES).await?;
    let tcp_source = Origin::tcp_source().await?;
    let tcp_discard = Origin::tcp_discard(meters::STREAM_BYTES).await?;

    let server_port = net::reserve_dual_port()?;
    let server_inbound = if auth {
        cfg::socks_inbound_with_auth("socks-in", server_port, SOCKS_USERNAME, SOCKS_PASSWORD)
    } else {
        cfg::socks_inbound("socks-in", server_port)
    };
    let server = Node::new("server")
        .dns_host(behaviours::TEST_DOMAIN, &["127.0.0.1"])
        .inbound(server_inbound)
        .outbound(cfg::direct("direct"))
        .start()
        .await?;

    let server_addr = net::loopback(server_port);
    let (username, password) = if auth {
        (SOCKS_USERNAME, SOCKS_PASSWORD)
    } else {
        ("", "")
    };
    let client = Node::new("client")
        .socks_inbound()?
        .outbound(match outbound {
            Stage::Native => cfg::socks("socks-out", server_addr, username, password),
            // The plugin reads the same credentials as `username:password`,
            // and an empty string as no authentication.
            Stage::Plugin(fixture) => cfg::plugin(
                "socks-out",
                &fixture.path()?,
                Some(server_addr),
                &if auth {
                    format!("{}:{}", username, password)
                } else {
                    String::new()
                },
            ),
        })
        .start()
        .await?;

    let net = Net {
        socks: Socks5::new(client.socks_addr()?),
        tcp_origin: tcp_origin.addr(),
        tcp_sink: tcp_sink.addr(),
        tcp_source: tcp_source.addr(),
        tcp_discard: tcp_discard.addr(),
        udp_origin: udp_origin.addr(),
    };
    Ok(Deployment::new(
        net,
        vec![client, server],
        vec![tcp_origin, udp_origin, tcp_sink, tcp_source, tcp_discard],
    ))
}

/// `socks -> chain[tls, ws, trojan] -> leaf chain[tls, ws, trojan] -> direct -> origin`
async fn deploy_tls_chain(tls_stage: Stage, trojan_stage: Stage) -> Result<Deployment> {
    let tcp_origin = Origin::tcp_echo().await?;
    let udp_origin = Origin::udp_echo().await?;
    let tcp_sink = Origin::tcp_sink(SINK_BYTES).await?;
    let tcp_source = Origin::tcp_source().await?;
    let tcp_discard = Origin::tcp_discard(meters::STREAM_BYTES).await?;
    let certificate = tls::self_signed()?;

    let server_port = net::reserve_dual_port()?;
    let server = Node::new("server")
        .dns_host(behaviours::TEST_DOMAIN, &["127.0.0.1"])
        .inbound(cfg::chain_inbound(
            "chain-in",
            server_port,
            &["tls-in", "ws-in", "trojan-in"],
        ))
        .inbound(cfg::tls_inbound(
            "tls-in",
            &certificate.certificate_pem,
            &certificate.private_key_pem,
        ))
        .inbound(cfg::ws_inbound("ws-in", WS_PATH))
        .inbound(cfg::trojan_inbound("trojan-in", TROJAN_PASSWORD))
        .outbound(cfg::direct("direct"))
        .start()
        .await?;

    let server_addr = net::loopback(server_port);
    let client = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::chain(
            "chain-out",
            &["tls-out", "ws-out", "trojan-out"],
        ))
        .outbound(tls_actor(tls_stage)?)
        .outbound(cfg::ws("ws-out", WS_PATH))
        .outbound(trojan_actor(trojan_stage, server_addr)?)
        .start()
        .await?;

    let net = Net {
        socks: Socks5::new(client.socks_addr()?),
        tcp_origin: tcp_origin.addr(),
        tcp_sink: tcp_sink.addr(),
        tcp_source: tcp_source.addr(),
        tcp_discard: tcp_discard.addr(),
        udp_origin: udp_origin.addr(),
    };
    Ok(Deployment::new(
        net,
        vec![client, server],
        vec![tcp_origin, udp_origin, tcp_sink, tcp_source, tcp_discard],
    ))
}

/// The TLS stage layers over the next actor, so it names no endpoint whichever
/// implementation fills it.
fn tls_actor(stage: Stage) -> Result<Value> {
    Ok(match stage {
        Stage::Native => cfg::tls("tls-out", tls::SERVER_NAME, true),
        Stage::Plugin(fixture) => cfg::plugin(
            "tls-out",
            &fixture.path()?,
            None,
            &serde_json::json!({ "server_name": tls::SERVER_NAME, "insecure": true }).to_string(),
        ),
    })
}

/// The trojan stage is the one that names the server, so it carries the
/// endpoint in both forms.
fn trojan_actor(stage: Stage, server: SocketAddr) -> Result<Value> {
    Ok(match stage {
        Stage::Native => cfg::trojan("trojan-out", server, TROJAN_PASSWORD),
        Stage::Plugin(fixture) => cfg::plugin(
            "trojan-out",
            &fixture.path()?,
            Some(server),
            TROJAN_PASSWORD,
        ),
    })
}
