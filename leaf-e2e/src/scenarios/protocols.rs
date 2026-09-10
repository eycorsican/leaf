//! Every stack leaf can speak to itself with, carrying every behaviour.
//!
//! `leaf/tests` covers this ground one hand-written config file at a time: a
//! test per combination, each with its own ports, its own copy of a socks
//! client and its own idea of what "worked" means. This is the same coverage
//! as a matrix -- stack times behaviour -- so a combination costs a line, the
//! behaviours are the ones every other suite here uses, and a failure names
//! the stack and the behaviour rather than a file.
//!
//! A stack is what the client speaks and the server accepts, listed from the
//! outermost transport inwards: `chain[ws, trojan]` is trojan carried over a
//! websocket. Both ends are leaf, so this asks whether an implementation
//! agrees with itself; whether it agrees with anyone else is what
//! `differential/` asks of the plugins.
//!
//! What is not here: the outbounds with no inbound to talk to (vmess, vless,
//! obfs, reality), the inbounds that need privileges or a device (tun, nf),
//! and the routing outbounds (failover, tryall, select, static), which are
//! about picking a handler rather than carrying bytes.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::behaviours;
use crate::client::Socks5;
use crate::differential::{Behaviour, Deployment, DeploymentFuture, Net};
use crate::net;
use crate::node::{cfg, Node, ENV_LOG_LEVEL};
use crate::scenario::{boxed, Scenario, Tag};
use crate::servers::Origin;
use crate::tls;

const SS_METHOD: &str = "aes-128-gcm";
const PASSWORD: &str = "e2e-password";
const WS_PATH: &str = "/leaf";
/// What the sink origin reads before closing; `peer-closes-first` writes
/// exactly this much.
const SINK_BYTES: usize = 32;

/// One layer of a stack.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Layer {
    /// Transports, outermost first.
    Tls,
    Ws,
    Quic,
    Amux,
    /// amux carrying its own websocket transport, which is how leaf composes
    /// the two: the transport is named inside the amux settings rather than
    /// beside it in the chain.
    AmuxOverWs,
    /// Protocols, innermost. These carry the destination.
    Trojan,
    Shadowsocks,
    Socks,
}

impl Layer {
    fn tag(self) -> &'static str {
        match self {
            Layer::Tls => "tls",
            Layer::Ws => "ws",
            Layer::Quic => "quic",
            Layer::Amux => "amux",
            Layer::AmuxOverWs => "amux-over-ws",
            Layer::Trojan => "trojan",
            Layer::Shadowsocks => "shadowsocks",
            Layer::Socks => "socks",
        }
    }

    /// Whether this layer can be an inbound of its own, with an address and a
    /// port. The rest are actors: they need a chain around them to be
    /// listened on, even when there is only one of them.
    fn listens(self) -> bool {
        matches!(self, Layer::Socks | Layer::Shadowsocks)
    }

    /// Whether this layer is the one that names the server endpoint.
    ///
    /// Exactly one layer in a stack does, and it is the outermost layer that
    /// has an address of its own: quic and amux dial for themselves, and
    /// everything else leaves it to the protocol inside.
    fn dials(self) -> bool {
        matches!(
            self,
            Layer::Quic
                | Layer::Amux
                | Layer::AmuxOverWs
                | Layer::Trojan
                | Layer::Shadowsocks
                | Layer::Socks
        )
    }
}

/// A stack, and what it is expected to carry.
struct Stack {
    /// Appears in the case id.
    name: &'static str,
    layers: &'static [Layer],
    /// Whether the stack carries datagrams as well as streams.
    datagrams: bool,
}

fn stacks() -> Vec<Stack> {
    vec![
        Stack {
            name: "socks",
            layers: &[Layer::Socks],
            datagrams: true,
        },
        Stack {
            name: "shadowsocks",
            layers: &[Layer::Shadowsocks],
            datagrams: true,
        },
        Stack {
            name: "trojan",
            layers: &[Layer::Trojan],
            datagrams: true,
        },
        Stack {
            name: "ws-trojan",
            layers: &[Layer::Ws, Layer::Trojan],
            datagrams: true,
        },
        Stack {
            name: "tls-trojan",
            layers: &[Layer::Tls, Layer::Trojan],
            datagrams: true,
        },
        Stack {
            name: "tls-ws-trojan",
            layers: &[Layer::Tls, Layer::Ws, Layer::Trojan],
            datagrams: true,
        },
        Stack {
            name: "quic-trojan",
            layers: &[Layer::Quic, Layer::Trojan],
            datagrams: true,
        },
        Stack {
            name: "amux-trojan",
            layers: &[Layer::Amux, Layer::Trojan],
            datagrams: true,
        },
        Stack {
            name: "amux-over-ws-trojan",
            layers: &[Layer::AmuxOverWs, Layer::Trojan],
            datagrams: true,
        },
        // Streams only. Shadowsocks carries datagrams as datagrams -- its UDP
        // side is its own protocol over a UDP association -- and a websocket
        // is a stream. There is nothing for the chain to put the association
        // in, which is why trojan-based stacks carry UDP here and this one
        // does not: trojan tunnels its datagrams over the stream it already
        // has.
        Stack {
            name: "ws-shadowsocks",
            layers: &[Layer::Ws, Layer::Shadowsocks],
            datagrams: false,
        },
    ]
}

/// Several proxies in a row, each reached through the one before it.
///
/// A different question from a stack: there the layers wrap one connection to
/// one server, here each hop is a whole proxy with a server of its own, and
/// what the chain outbound has to get right is that every hop dials the next
/// one from inside the tunnel the previous one built. This is the shape
/// `leaf/tests/test_out_chain_*` covered a file at a time.
struct Relay {
    name: &'static str,
    hops: &'static [&'static [Layer]],
    datagrams: bool,
}

fn relays() -> Vec<Relay> {
    vec![
        Relay {
            name: "shadowsocks+shadowsocks",
            hops: &[&[Layer::Shadowsocks], &[Layer::Shadowsocks]],
            datagrams: true,
        },
        Relay {
            name: "ws-trojan+shadowsocks",
            hops: &[&[Layer::Ws, Layer::Trojan], &[Layer::Shadowsocks]],
            datagrams: true,
        },
        Relay {
            name: "ws-trojan+ws-trojan",
            hops: &[&[Layer::Ws, Layer::Trojan], &[Layer::Ws, Layer::Trojan]],
            datagrams: true,
        },
        Relay {
            name: "quic-trojan+shadowsocks",
            hops: &[&[Layer::Quic, Layer::Trojan], &[Layer::Shadowsocks]],
            datagrams: true,
        },
        Relay {
            name: "shadowsocks+quic-trojan",
            hops: &[&[Layer::Shadowsocks], &[Layer::Quic, Layer::Trojan]],
            datagrams: true,
        },
        Relay {
            name: "ws-trojan+shadowsocks+ws-trojan",
            hops: &[
                &[Layer::Ws, Layer::Trojan],
                &[Layer::Shadowsocks],
                &[Layer::Ws, Layer::Trojan],
            ],
            datagrams: true,
        },
    ]
}

pub fn scenarios() -> Vec<Scenario> {
    let mut scenarios = Vec::new();
    for stack in stacks() {
        let mut behaviours = behaviours::stream_suite();
        if stack.datagrams {
            behaviours.push((behaviours::UDP, vec![]));
        }
        for (behaviour, extra_tags) in behaviours {
            let layers = stack.layers;
            let slow = extra_tags.contains(&Tag::Slow);
            let mut tags = vec![Tag::Native];
            tags.extend(extra_tags);
            let mut scenario = Scenario::new(
                format!("protocol/{}/{}", stack.name, behaviour.name),
                "protocol",
                move || boxed(carries(layers, behaviour)),
            )
            .tags(tags)
            .timeout(if slow {
                Duration::from_secs(120)
            } else {
                Duration::from_secs(60)
            });
            // See the note in `differential.rs`: `debug` is what records how
            // the relay ended, and a bulk case that fails needs it.
            if slow {
                scenario = scenario.env(ENV_LOG_LEVEL, "debug");
            }
            if layers.contains(&Layer::Ws) || layers.contains(&Layer::AmuxOverWs) {
                // A websocket has nothing of its own to say "the request has
                // ended" with; leaf sends an empty frame for it, and both ends
                // here are leaf. See `half-close/`.
                scenario = scenario.env("WS_HALF_CLOSE", "true");
            }
            scenarios.push(scenario);
        }
    }

    for selector in selectors() {
        for behaviour in [
            behaviours::ECHO,
            behaviours::CONCURRENT,
            behaviours::CONNECTION_CHURN,
            behaviours::UDP,
        ] {
            let protocol = selector.protocol;
            let extra = selector.extra;
            // See `survives_a_dead_actor`: a datagram case cannot see a dead
            // actor, so it is run against the working one alone.
            let dead = selector.survives_a_dead_actor && behaviour.name != behaviours::UDP.name;
            scenarios.push(
                Scenario::new(
                    format!("selector/{}/{}", selector.name, behaviour.name),
                    "selector",
                    move || boxed(selects(protocol, extra, dead, behaviour)),
                )
                .tags([Tag::Native])
                .timeout(Duration::from_secs(60)),
            );
        }
    }

    for relay in relays() {
        let mut behaviours = behaviours::stream_suite();
        if relay.datagrams {
            behaviours.push((behaviours::UDP, vec![]));
        }
        for (behaviour, extra_tags) in behaviours {
            let hops = relay.hops;
            let slow = extra_tags.contains(&Tag::Slow);
            let mut tags = vec![Tag::Native];
            tags.extend(extra_tags);
            let mut scenario = Scenario::new(
                format!("relay/{}/{}", relay.name, behaviour.name),
                "relay",
                move || boxed(relays_carry(hops, behaviour)),
            )
            .tags(tags)
            .timeout(if slow {
                Duration::from_secs(180)
            } else {
                Duration::from_secs(90)
            });
            if slow {
                scenario = scenario.env(ENV_LOG_LEVEL, "debug");
            }
            if hops
                .iter()
                .any(|hop| hop.contains(&Layer::Ws) || hop.contains(&Layer::AmuxOverWs))
            {
                scenario = scenario.env("WS_HALF_CLOSE", "true");
            }
            scenarios.push(scenario);
        }
    }
    scenarios
}

/// Runs one behaviour over a relay.
async fn relays_carry(hops: &'static [&'static [Layer]], behaviour: Behaviour) -> Result<()> {
    let name = hops
        .iter()
        .map(|hop| describe(hop))
        .collect::<Vec<_>>()
        .join(" => ");
    let deployment = deploy_relay(hops)
        .await
        .with_context(|| format!("starting the [{}] relay", name))?;
    (behaviour.run)(deployment.net())
        .await
        .with_context(|| format!("behaviour [{}] over [{}]", behaviour.name, name))?;
    deployment.shutdown().await
}

/// `socks -> hop1 -> hop2 -> ... -> direct -> origin`.
///
/// Every hop is a leaf node that terminates its own stack and relays onwards;
/// the client stacks all of them, so the connection to the last hop is built
/// inside the tunnel to the one before it.
fn deploy_relay(hops: &'static [&'static [Layer]]) -> DeploymentFuture {
    Box::pin(async move {
        let tcp_origin = Origin::tcp_echo().await?;
        let udp_origin = Origin::udp_echo().await?;
        let tcp_sink = Origin::tcp_sink(SINK_BYTES).await?;
        let tcp_source = Origin::tcp_source().await?;
        let tcp_discard = Origin::tcp_discard(crate::meters::STREAM_BYTES).await?;
        let certificate = tls::self_signed()?;

        let mut ports = Vec::with_capacity(hops.len());
        for _ in hops {
            ports.push(net::reserve_dual_port()?);
        }

        // One node per hop, each terminating its own stack and going direct
        // from there: the next hop is just another destination to it.
        let mut nodes = Vec::with_capacity(hops.len() + 1);
        for (index, hop) in hops.iter().enumerate() {
            let prefix = format!("h{}-", index);
            let chained = hop.len() > 1 || !hop[0].listens();
            let mut node = Node::new(&format!("hop{}", index))
                .dns_host(behaviours::TEST_DOMAIN, &["127.0.0.1"])
                .outbound(cfg::direct("direct"));
            if !chained {
                node = node.inbound(inbound(hop[0], &prefix, ports[index], false, certificate));
            } else {
                let actors: Vec<String> = hop
                    .iter()
                    .map(|l| format!("{}{}-in", prefix, l.tag()))
                    .collect();
                let refs: Vec<&str> = actors.iter().map(String::as_str).collect();
                node = node.inbound(cfg::chain_inbound(
                    &format!("{}chain-in", prefix),
                    ports[index],
                    &refs,
                ));
                for layer in *hop {
                    node = node.inbound(inbound(*layer, &prefix, ports[index], true, certificate));
                    if *layer == Layer::AmuxOverWs {
                        node = node
                            .inbound(cfg::ws_inbound(&format!("{}amux-ws-in", prefix), WS_PATH));
                    }
                }
            }
            nodes.push(node.start().await?);
        }

        // The client stacks every hop: the outermost entry of its chain is the
        // first hop, and each later one is dialled from inside the previous.
        let mut client = Node::new("client").socks_inbound()?;
        let mut entries = Vec::new();
        for (index, hop) in hops.iter().enumerate() {
            let prefix = format!("h{}-", index);
            let server = net::loopback(ports[index]);
            if hop.len() == 1 {
                entries.push(format!("{}{}-out", prefix, hop[0].tag()));
            } else {
                let actors: Vec<String> = hop
                    .iter()
                    .map(|l| format!("{}{}-out", prefix, l.tag()))
                    .collect();
                let refs: Vec<&str> = actors.iter().map(String::as_str).collect();
                let tag = format!("{}chain-out", prefix);
                client = client.outbound(cfg::chain(&tag, &refs));
                entries.push(tag);
            }
            for layer in *hop {
                client = client.outbound(outbound(*layer, &prefix, server, certificate));
                if *layer == Layer::AmuxOverWs {
                    client = client.outbound(cfg::ws(&format!("{}amux-ws-out", prefix), WS_PATH));
                }
            }
        }
        let entry_refs: Vec<&str> = entries.iter().map(String::as_str).collect();
        // The relay itself, listed first so it is the default route.
        let client = client
            .outbound_first(cfg::chain("relay-out", &entry_refs))
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
        // The client stops first, then the hops in the order they are reached.
        let mut all = vec![client];
        all.extend(nodes);
        Ok(Deployment::new(
            net,
            all,
            vec![tcp_origin, udp_origin, tcp_sink, tcp_source, tcp_discard],
        ))
    })
}

/// A selecting outbound: one that picks among handlers rather than carrying
/// bytes itself.
///
/// Health checking is off in all of them. leaf probes a public resolver to
/// decide whether an actor is alive, and a suite that reaches the internet to
/// answer a question about leaf is not a suite -- it fails where there is no
/// network and passes for reasons of its own where there is. What is left is
/// what these outbounds do without it: pick, and for the two that can, fail
/// over when a connection is refused.
///
/// `select` is not here: it is not in leaf's default feature set, so in this
/// build there is nothing to test.
struct Selector {
    name: &'static str,
    protocol: &'static str,
    /// Settings beyond the actor list.
    extra: fn() -> Value,
    /// Whether a dead actor goes in front of the working one.
    ///
    /// Only for the stream behaviours, and only where the outbound claims to
    /// survive it: a refused connection is something an outbound can see. A
    /// datagram sent into a socket nobody is listening on is not, so putting a
    /// dead actor in front of a UDP case would test the health checker that is
    /// deliberately turned off here.
    survives_a_dead_actor: bool,
}

fn selectors() -> Vec<Selector> {
    vec![
        Selector {
            name: "failover",
            protocol: "failover",
            extra: || serde_json::json!({ "healthCheck": false, "failTimeout": 2 }),
            survives_a_dead_actor: true,
        },
        Selector {
            name: "tryall",
            protocol: "tryall",
            extra: || serde_json::json!({ "delayBase": 0 }),
            survives_a_dead_actor: true,
        },
        Selector {
            name: "static",
            protocol: "static",
            extra: || serde_json::json!({ "method": "rr" }),
            survives_a_dead_actor: false,
        },
    ]
}

/// Runs one behaviour through a selecting outbound over a shadowsocks hop.
async fn selects(
    protocol: &'static str,
    extra: fn() -> Value,
    with_a_dead_actor: bool,
    behaviour: Behaviour,
) -> Result<()> {
    let tcp_origin = Origin::tcp_echo().await?;
    let udp_origin = Origin::udp_echo().await?;
    let tcp_sink = Origin::tcp_sink(SINK_BYTES).await?;
    let tcp_source = Origin::tcp_source().await?;
    let tcp_discard = Origin::tcp_discard(crate::meters::STREAM_BYTES).await?;

    let port = net::reserve_dual_port()?;
    let server = Node::new("server")
        .dns_host(behaviours::TEST_DOMAIN, &["127.0.0.1"])
        .inbound(cfg::shadowsocks_inbound("ss-in", port, SS_METHOD, PASSWORD))
        .outbound(cfg::direct("direct"))
        .start()
        .await?;

    // A port nobody is listening on, reserved so that nothing else takes it
    // while the case runs.
    let dead_port = net::reserve_dual_port()?;
    let mut actors = Vec::new();
    if with_a_dead_actor {
        actors.push("dead-out");
    }
    actors.push("ss-out");

    let mut client = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::selector(protocol, "selector-out", &actors, extra()))
        .outbound(cfg::shadowsocks(
            "ss-out",
            net::loopback(port),
            SS_METHOD,
            PASSWORD,
        ));
    if with_a_dead_actor {
        client = client.outbound(cfg::shadowsocks(
            "dead-out",
            net::loopback(dead_port),
            SS_METHOD,
            PASSWORD,
        ));
    }
    let client = client.start().await?;

    let net = Net {
        socks: Socks5::new(client.socks_addr()?),
        tcp_origin: tcp_origin.addr(),
        tcp_sink: tcp_sink.addr(),
        tcp_source: tcp_source.addr(),
        tcp_discard: tcp_discard.addr(),
        udp_origin: udp_origin.addr(),
    };
    let deployment = Deployment::new(
        net,
        vec![client, server],
        vec![tcp_origin, udp_origin, tcp_sink, tcp_source, tcp_discard],
    );
    (behaviour.run)(deployment.net()).await.with_context(|| {
        format!(
            "behaviour [{}] through a {} outbound",
            behaviour.name, protocol
        )
    })?;
    deployment.shutdown().await
}

/// Runs one behaviour over one stack.
async fn carries(layers: &'static [Layer], behaviour: Behaviour) -> Result<()> {
    let deployment = deploy(layers)
        .await
        .with_context(|| format!("starting the [{}] topology", describe(layers)))?;
    (behaviour.run)(deployment.net())
        .await
        .with_context(|| format!("behaviour [{}] over [{}]", behaviour.name, describe(layers)))?;
    deployment.shutdown().await
}

fn describe(layers: &[Layer]) -> String {
    layers
        .iter()
        .map(|layer| layer.tag())
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// `socks -> <stack> -> leaf <stack> -> direct -> origin`.
///
/// A single-layer stack is the protocol on its own -- a shadowsocks outbound
/// against a shadowsocks inbound. Anything longer is a chain on both sides,
/// which is how leaf composes a transport with the protocol inside it.
fn deploy(layers: &'static [Layer]) -> DeploymentFuture {
    Box::pin(async move {
        let tcp_origin = Origin::tcp_echo().await?;
        let udp_origin = Origin::udp_echo().await?;
        let tcp_sink = Origin::tcp_sink(SINK_BYTES).await?;
        let tcp_source = Origin::tcp_source().await?;
        let tcp_discard = Origin::tcp_discard(crate::meters::STREAM_BYTES).await?;
        let certificate = tls::self_signed()?;
        let port = net::reserve_dual_port()?;
        let server_addr = net::loopback(port);

        // A protocol that cannot listen on its own is wrapped in a chain even
        // when it is the only thing in it, which is a configuration in its own
        // right and one nothing else here covers.
        let chained = layers.len() > 1 || !layers[0].listens();

        let mut server = Node::new("server")
            .dns_host(behaviours::TEST_DOMAIN, &["127.0.0.1"])
            .outbound(cfg::direct("direct"));
        if !chained {
            server = server.inbound(inbound(layers[0], "", port, false, &certificate));
        } else {
            let actors: Vec<String> = layers.iter().map(|l| format!("{}-in", l.tag())).collect();
            let refs: Vec<&str> = actors.iter().map(String::as_str).collect();
            server = server.inbound(cfg::chain_inbound("chain-in", port, &refs));
            for layer in layers {
                server = server.inbound(inbound(*layer, "", port, true, &certificate));
                // A layer that carries a transport of its own declares it too.
                if *layer == Layer::AmuxOverWs {
                    server = server.inbound(cfg::ws_inbound("amux-ws-in", WS_PATH));
                }
            }
        }
        let server = server.start().await?;

        let mut client = Node::new("client").socks_inbound()?;
        if !chained {
            client = client.outbound(outbound(layers[0], "", server_addr, &certificate));
        } else {
            let actors: Vec<String> = layers.iter().map(|l| format!("{}-out", l.tag())).collect();
            let refs: Vec<&str> = actors.iter().map(String::as_str).collect();
            client = client.outbound(cfg::chain("chain-out", &refs));
            for layer in layers {
                client = client.outbound(outbound(*layer, "", server_addr, &certificate));
                if *layer == Layer::AmuxOverWs {
                    client = client.outbound(cfg::ws("amux-ws-out", WS_PATH));
                }
            }
        }
        let client = client.start().await?;

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
    })
}

/// The client's side of one layer.
///
/// Only the layer that dials names the endpoint; the ones above it wrap
/// whatever the layer below produced.
fn outbound(
    layer: Layer,
    prefix: &str,
    server: SocketAddr,
    certificate: &tls::SelfSigned,
) -> Value {
    let tag = format!("{}{}-out", prefix, layer.tag());
    match layer {
        Layer::Tls => cfg::tls(&tag, tls::SERVER_NAME, true),
        Layer::Ws => cfg::ws(&tag, WS_PATH),
        Layer::Quic => cfg::quic(&tag, server, tls::SERVER_NAME, &certificate.certificate_pem),
        Layer::Amux => cfg::amux(&tag, server, &[]),
        Layer::AmuxOverWs => cfg::amux(&tag, server, &[&format!("{}amux-ws-out", prefix)]),
        Layer::Trojan => cfg::trojan(&tag, server, PASSWORD),
        Layer::Shadowsocks => cfg::shadowsocks(&tag, server, SS_METHOD, PASSWORD),
        Layer::Socks => cfg::socks(&tag, server, "", ""),
    }
}

/// The server's side of one layer. `port` is used only by a single-layer
/// stack, where the protocol is the listener rather than an actor in a chain.
fn inbound(
    layer: Layer,
    prefix: &str,
    port: u16,
    chained: bool,
    certificate: &tls::SelfSigned,
) -> Value {
    let tag = format!("{}{}-in", prefix, layer.tag());
    match layer {
        Layer::Tls => cfg::tls_inbound(
            &tag,
            &certificate.certificate_pem,
            &certificate.private_key_pem,
        ),
        Layer::Ws => cfg::ws_inbound(&tag, WS_PATH),
        Layer::Quic => cfg::quic_inbound(
            &tag,
            &certificate.certificate_pem,
            &certificate.private_key_pem,
        ),
        Layer::Amux => cfg::amux_inbound(&tag, &[]),
        Layer::AmuxOverWs => cfg::amux_inbound(&tag, &[&format!("{}amux-ws-in", prefix)]),
        Layer::Trojan => cfg::trojan_inbound(&tag, PASSWORD),
        Layer::Shadowsocks if chained => cfg::shadowsocks_actor_inbound(&tag, SS_METHOD, PASSWORD),
        Layer::Shadowsocks => cfg::shadowsocks_inbound(&tag, port, SS_METHOD, PASSWORD),
        Layer::Socks if chained => cfg::socks_actor_inbound(&tag),
        Layer::Socks => cfg::socks_inbound(&tag, port),
    }
}

/// Kept so the `dials` rule stays checked rather than assumed.
#[allow(dead_code)]
fn dialing_layer(layers: &[Layer]) -> Option<Layer> {
    layers.iter().copied().find(|layer| layer.dials())
}
