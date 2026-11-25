//! The reference plugins against the servers people deploy.
//!
//! `differential/` compares a plugin with leaf's own implementation of the same
//! protocol. The protocols here have none: AnyTLS and ShadowTLS exist in leaf
//! only as plugins. What a plugin for them has to agree with instead is
//! everyone else, so every case here puts a real leaf, with the plugin loaded
//! across the ABI, in front of a server from another project, built from its
//! source at a pinned revision:
//!
//! | protocol  | servers                                                      |
//! |-----------|--------------------------------------------------------------|
//! | AnyTLS    | anytls-go (the reference), sing-box stable, sing-box testing, mihomo |
//! | ShadowTLS | shadow-tls (the original), sing-box stable, mihomo           |
//!
//! Each pair runs the stream behaviours every other suite here runs, and the
//! cases that are about the protocol rather than the plumbing: the padding
//! scheme a server hands out, the fingerprint, and the ways a connection has to
//! fail -- a wrong password, a connection hijacked to the real site, a site
//! that offers only TLS 1.2.

use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::behaviours;
use crate::client::{Socks5, Target};
use crate::differential::{Behaviour, Deployment, Net, Observation};
use crate::fixtures::Fixture;
use crate::flow;
use crate::meters;
use crate::net;
use crate::node::{cfg, LeafNode, Node};
use crate::scenario::{boxed, Scenario, Tag};
use crate::servers::{Origin, RecordRelay, TlsSite};
use crate::tls;
use crate::upstream::{AnytlsServer, ShadowTlsServer, ShadowTlsSetup, UpstreamServer};

const PASSWORD: &str = "e2e-interop-password";
const SS_METHOD: &str = "aes-128-gcm";
const SS_PASSWORD: &str = "e2e-interop-ss-password";
/// What the sink origin reads before closing; `peer-closes-first` writes
/// exactly this much.
const SINK_BYTES: usize = 32;
/// How long a connection that must fail may take to do so.
const REFUSAL: Duration = Duration::from_secs(10);

/// A padding scheme no server uses by default, with fixed sizes so the records
/// it produces can be checked exactly.
const CUSTOM_SCHEME: &str = "stop=3\n0=50-50\n1=150-150\n2=300-300";
/// What TLS 1.3 adds to a record's length field: the inner content type and a
/// 16-byte AEAD tag. Every server here is Go, and Go negotiates only AEAD
/// suites with 16-byte tags.
const TLS13_OVERHEAD: usize = 17;

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// The stream behaviours, with the domain case resolving `localhost` rather
/// than the suite's own test domain: these servers resolve names themselves,
/// and none of them can be told about a name only the suite knows.
fn stream_suite() -> Vec<(Behaviour, Vec<Tag>)> {
    behaviours::stream_suite()
        .into_iter()
        .map(|(behaviour, tags)| {
            if behaviour.name == behaviours::DOMAIN_DESTINATION.name {
                (LOCALHOST_DESTINATION, tags)
            } else {
                (behaviour, tags)
            }
        })
        .collect()
}

const LOCALHOST_DESTINATION: Behaviour = Behaviour {
    name: "domain-destination",
    run: |net| Box::pin(localhost_destination(net)),
};

async fn localhost_destination(net: Net) -> Result<Observation> {
    let mut observed = Observation::default();
    let target = Target::domain("localhost", net.tcp_origin.port());
    let mut stream = net.socks.connect(target).await?;
    tokio::time::timeout(
        Duration::from_secs(10),
        flow::echo_roundtrip(&mut stream, b"named"),
    )
    .await??;
    observed.record("exchange", 5);
    Ok(observed)
}

pub fn scenarios() -> Vec<Scenario> {
    let mut scenarios = Vec::new();

    for &server in AnytlsServer::ALL {
        let needs = vec![Fixture::AnytlsCabiGo, server.fixture()];
        let id = |case: &str| format!("interop/anytls/{}/{}", server.name(), case);
        for (behaviour, extra) in stream_suite() {
            // AnyTLS has no half close: FIN ends a stream in both directions,
            // and every server here drops the stream when it arrives. A reply
            // still on its way when the client ends its side is lost by
            // design -- sing-box's own client loses it the same way. What the
            // protocol does promise, that ending one side ends the connection
            // promptly, is `half-close`, which runs.
            if behaviour.name == behaviours::HALF_CLOSE_TAIL.name {
                continue;
            }
            let topology = Anytls {
                server,
                fingerprint: None,
                scheme: None,
            };
            scenarios.push(case(id(behaviour.name), &needs, &extra, move || {
                boxed(run_behaviour(Topology::Anytls(topology), behaviour))
            }));
        }
        scenarios.push(case(id("fingerprint-chrome"), &needs, &[], move || {
            boxed(run_behaviour(
                Topology::Anytls(Anytls {
                    server,
                    fingerprint: Some("chrome"),
                    scheme: None,
                }),
                behaviours::ECHO,
            ))
        }));
        scenarios.push(case(id("server-padding-scheme"), &needs, &[], move || {
            boxed(anytls_server_padding_scheme(server))
        }));
        scenarios.push(case(id("wrong-password"), &needs, &[], move || {
            boxed(anytls_wrong_password(server))
        }));
    }

    for &server in ShadowTlsServer::ALL {
        let needs = vec![Fixture::ShadowtlsCabiGo, server.fixture()];
        let id = |case: &str| format!("interop/shadowtls/{}/{}", server.name(), case);
        for (behaviour, extra) in stream_suite() {
            let mut scenario = case(id(behaviour.name), &needs, &extra, move || {
                boxed(run_behaviour(
                    Topology::ShadowTls(ShadowTls::new(server, Some("chrome"))),
                    behaviour,
                ))
            });
            if behaviour.name == behaviours::HALF_CLOSE_TAIL.name {
                scenario = scenario.known_defect(
                    "the host shuts down the socket's sending side as soon as the application \
                     half-closes, even while the engine is still handshaking or still has \
                     application input it has not encoded yet. ShadowTLS's handshake is a \
                     round trip through the real site, so a request written and half-closed \
                     at once is lost with the rest of the handshake (`transfer err=Broken \
                     pipe`). An engine has no way to tell the host it is not finished yet",
                );
            }
            scenarios.push(scenario);
        }
        scenarios.push(case(id("fingerprint-none"), &needs, &[], move || {
            boxed(run_behaviour(
                Topology::ShadowTls(ShadowTls::new(server, None)),
                behaviours::ECHO,
            ))
        }));
        scenarios.push(case(id("wrong-password"), &needs, &[], move || {
            boxed(shadowtls_refused(server, Refusal::WrongPassword))
        }));
        scenarios.push(case(id("hijacked-to-site"), &needs, &[], move || {
            boxed(shadowtls_refused(server, Refusal::Hijacked))
        }));
        scenarios.push(case(id("tls12-site-strict"), &needs, &[], move || {
            boxed(shadowtls_refused(server, Refusal::Tls12Site))
        }));
    }
    scenarios
}

fn case<F>(id: String, needs: &[Fixture], extra: &[Tag], run: F) -> Scenario
where
    F: Fn() -> crate::scenario::CaseFuture + Send + Sync + 'static,
{
    let mut needs = needs.to_vec();
    needs.sort();
    needs.dedup();
    let mut tags = vec![Tag::Plugin, Tag::Interop, Tag::Go];
    tags.extend(extra.iter().copied());
    let slow = extra.contains(&Tag::Slow);
    Scenario::new(id, "interop", run)
        .tags(tags)
        .needs(needs)
        .timeout(if slow {
            Duration::from_secs(120)
        } else {
            Duration::from_secs(60)
        })
}

// ---------------------------------------------------------------------------
// Topologies
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Anytls {
    server: AnytlsServer,
    fingerprint: Option<&'static str>,
    scheme: Option<&'static str>,
}

#[derive(Clone, Copy)]
struct ShadowTls {
    server: ShadowTlsServer,
    fingerprint: Option<&'static str>,
    /// The password the client has; the server always has [`PASSWORD`].
    client_password: &'static str,
    /// Point the client at the handshake site itself rather than at the
    /// shadow server -- a hijacked connection.
    hijacked: bool,
    tls12_site: bool,
}

impl ShadowTls {
    fn new(server: ShadowTlsServer, fingerprint: Option<&'static str>) -> Self {
        Self {
            server,
            fingerprint,
            client_password: PASSWORD,
            hijacked: false,
            tls12_site: false,
        }
    }
}

#[derive(Clone, Copy)]
enum Topology {
    Anytls(Anytls),
    ShadowTls(ShadowTls),
}

/// A deployment, and everything outside leaf it depends on.
struct Running {
    deployment: Deployment,
    servers: Vec<UpstreamServer>,
    _site: Option<TlsSite>,
    _relay: Option<RecordRelay>,
}

impl Running {
    fn net(&self) -> Net {
        self.deployment.net()
    }

    /// What the servers said, for an error that needs it.
    fn server_logs(&self) -> String {
        self.servers
            .iter()
            .map(|server| server.log_tail())
            .collect::<Vec<_>>()
            .join("\n---\n")
    }

    async fn shutdown(self) -> Result<()> {
        self.deployment.shutdown().await
    }
}

struct Origins {
    tcp: Origin,
    udp: Origin,
    sink: Origin,
    source: Origin,
    discard: Origin,
}

impl Origins {
    async fn start() -> Result<Self> {
        Ok(Self {
            tcp: Origin::tcp_echo().await?,
            udp: Origin::udp_echo().await?,
            sink: Origin::tcp_sink(SINK_BYTES).await?,
            source: Origin::tcp_source().await?,
            discard: Origin::tcp_discard(meters::STREAM_BYTES).await?,
        })
    }

    fn into_deployment(self, client: LeafNode, mut others: Vec<LeafNode>) -> Result<Deployment> {
        let net = Net {
            socks: Socks5::new(client.socks_addr()?),
            tcp_origin: self.tcp.addr(),
            tcp_sink: self.sink.addr(),
            tcp_source: self.source.addr(),
            tcp_discard: self.discard.addr(),
            udp_origin: self.udp.addr(),
        };
        // Client first: it has to stop before anything it talks to.
        let mut nodes = vec![client];
        nodes.append(&mut others);
        Ok(Deployment::new(
            net,
            nodes,
            vec![self.tcp, self.udp, self.sink, self.source, self.discard],
        ))
    }
}

/// The args the AnyTLS plugin gets for `server`.
fn anytls_args(server: AnytlsServer, fingerprint: Option<&str>) -> Result<String> {
    let mut args = json!({ "password": PASSWORD });
    if server.verifiable() {
        args["server_name"] = json!(tls::SERVER_NAME);
        args["certificate"] = json!(tls::self_signed()?.certificate_pem);
    } else {
        args["insecure"] = json!(true);
    }
    if let Some(fingerprint) = fingerprint {
        args["fingerprint"] = json!(fingerprint);
    }
    Ok(args.to_string())
}

/// `socks -> anytls plugin -> [relay ->] upstream AnyTLS server -> origin`
async fn deploy_anytls(topology: Anytls, password: &str, relay: bool) -> Result<Running> {
    let origins = Origins::start().await?;
    let server = topology.server.start(PASSWORD, topology.scheme).await?;
    let relay = if relay {
        Some(RecordRelay::start(server.addr()).await?)
    } else {
        None
    };
    let endpoint = relay.as_ref().map_or(server.addr(), |relay| relay.addr());
    let mut args: serde_json::Value =
        serde_json::from_str(&anytls_args(topology.server, topology.fingerprint)?)?;
    args["password"] = json!(password);
    let client = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "anytls-out",
            &Fixture::AnytlsCabiGo.path()?,
            Some(endpoint),
            &args.to_string(),
        ))
        .start()
        .await?;
    Ok(Running {
        deployment: origins.into_deployment(client, vec![])?,
        servers: vec![server],
        _site: None,
        _relay: relay,
    })
}

/// `socks -> chain[shadowtls plugin, shadowsocks] -> upstream ShadowTLS server
/// [-> leaf shadowsocks server] -> origin`, with a TLS site on the side for the
/// handshake.
async fn deploy_shadowtls(topology: ShadowTls) -> Result<Running> {
    let origins = Origins::start().await?;
    let site = TlsSite::start(topology.tls12_site).await?;

    let mut others = Vec::new();
    let backend_port = net::reserve_dual_port()?;
    if topology.server.needs_backend() {
        others.push(
            Node::new("ss-backend")
                // The domain case asks for `localhost`, and this node resolves
                // it, not the ShadowTLS server in front of it.
                .dns_host("localhost", &["127.0.0.1"])
                .inbound(cfg::shadowsocks_inbound(
                    "ss-in",
                    backend_port,
                    SS_METHOD,
                    SS_PASSWORD,
                ))
                .outbound(cfg::direct("direct"))
                .start()
                .await?,
        );
    }
    let server = topology
        .server
        .start(&ShadowTlsSetup {
            password: PASSWORD,
            handshake: site.addr(),
            strict: true,
            ss_method: SS_METHOD,
            ss_password: SS_PASSWORD,
            ss_backend: net::loopback(backend_port),
        })
        .await?;

    let mut args = json!({
        "password": topology.client_password,
        "server_name": tls::SERVER_NAME,
        "certificate": tls::self_signed()?.certificate_pem,
    });
    if let Some(fingerprint) = topology.fingerprint {
        args["fingerprint"] = json!(fingerprint);
    }
    let endpoint = if topology.hijacked {
        site.addr()
    } else {
        server.addr()
    };
    let client = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::chain("shadowtls-chain", &["shadowtls-out", "ss-out"]))
        .outbound(cfg::plugin(
            "shadowtls-out",
            &Fixture::ShadowtlsCabiGo.path()?,
            None,
            &args.to_string(),
        ))
        .outbound(cfg::shadowsocks("ss-out", endpoint, SS_METHOD, SS_PASSWORD))
        .start()
        .await?;
    Ok(Running {
        deployment: origins.into_deployment(client, others)?,
        servers: vec![server],
        _site: Some(site),
        _relay: None,
    })
}

async fn deploy(topology: Topology) -> Result<Running> {
    match topology {
        Topology::Anytls(topology) => deploy_anytls(topology, PASSWORD, false).await,
        Topology::ShadowTls(topology) => deploy_shadowtls(topology).await,
    }
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

async fn run_behaviour(topology: Topology, behaviour: Behaviour) -> Result<()> {
    let running = deploy(topology).await?;
    let outcome = (behaviour.run)(running.net()).await;
    if let Err(err) = outcome {
        let logs = running.server_logs();
        let _ = running.shutdown().await;
        return Err(err).with_context(|| format!("the upstream server said:\n{}", logs));
    }
    running.shutdown().await
}

/// One echo through a fresh connection.
async fn echo_once(net: Net, payload: &[u8]) -> Result<()> {
    let mut stream = net.socks.connect(net.tcp_origin).await?;
    tokio::time::timeout(
        Duration::from_secs(10),
        flow::echo_roundtrip(&mut stream, payload),
    )
    .await??;
    Ok(())
}

/// A server with a padding scheme of its own hands it to the client on the
/// first session, and the client has to use it from the next session on. The
/// records of the second connection, read off the wire between leaf and the
/// server, have to have the sizes that scheme dictates:
///
/// ```text
/// 0=50-50     authentication: 32 + 2 + 50
/// 1=150-150   settings, SYN and the destination
/// 2=300-300   the first application write
/// ```
async fn anytls_server_padding_scheme(server: AnytlsServer) -> Result<()> {
    let running = deploy_anytls(
        Anytls {
            server,
            fingerprint: None,
            scheme: Some(CUSTOM_SCHEME),
        },
        PASSWORD,
        true,
    )
    .await?;
    let relay = running._relay.as_ref().expect("deployed with a relay");
    let net = running.net();

    echo_once(net, b"learns the scheme").await?;
    echo_once(net, b"uses it").await?;

    let records = relay.records(1);
    // The first is the client's TLS 1.3 Finished; the scheme governs what
    // comes after it.
    ensure!(
        records.len() >= 4,
        "only {} application data records on the second connection",
        records.len()
    );
    let sizes: Vec<usize> = records[1..4].iter().map(|r| r - TLS13_OVERHEAD).collect();
    let first: Vec<usize> = relay
        .records(0)
        .iter()
        .skip(1)
        .take(3)
        .map(|r| r - TLS13_OVERHEAD)
        .collect();
    if sizes != [32 + 2 + 50, 150, 300] {
        let logs = running.server_logs();
        let _ = running.shutdown().await;
        bail!(
            "the second connection's records carry {:?} bytes, want [84, 150, 300] from the \
             server's scheme (the first connection's were {:?}).\nserver:\n{}",
            sizes,
            first,
            logs
        );
    }
    running.shutdown().await
}

async fn anytls_wrong_password(server: AnytlsServer) -> Result<()> {
    let running = deploy_anytls(
        Anytls {
            server,
            fingerprint: None,
            scheme: None,
        },
        "not-the-servers-password",
        false,
    )
    .await?;
    let outcome = expect_refused(running.net()).await;
    running.shutdown().await?;
    outcome.context("a client with the wrong password")
}

#[derive(Clone, Copy)]
enum Refusal {
    WrongPassword,
    Hijacked,
    Tls12Site,
}

async fn shadowtls_refused(server: ShadowTlsServer, refusal: Refusal) -> Result<()> {
    let mut topology = ShadowTls::new(server, Some("chrome"));
    let what = match refusal {
        Refusal::WrongPassword => {
            topology.client_password = "not-the-servers-password";
            "a client with the wrong password"
        }
        Refusal::Hijacked => {
            topology.hijacked = true;
            "a connection hijacked to the real site"
        }
        Refusal::Tls12Site => {
            topology.tls12_site = true;
            "strict mode, with a site that offers only TLS 1.2"
        }
    };
    let running = deploy_shadowtls(topology).await?;
    let outcome = expect_refused(running.net()).await;
    running.shutdown().await?;
    outcome.context(what)
}

/// The connection must end without carrying anything: either the proxy
/// refuses it outright, or it closes without echoing. Hanging counts as a
/// failure too -- an application left waiting on a dead connection is the
/// thing this exists to rule out.
async fn expect_refused(net: Net) -> Result<()> {
    let mut stream = match net.socks.connect(net.tcp_origin).await {
        Err(_) => return Ok(()),
        Ok(stream) => stream,
    };
    let payload = b"this must not come back";
    let _ = stream.write_all(payload).await;
    let mut received = Vec::new();
    match tokio::time::timeout(REFUSAL, stream.read_to_end(&mut received)).await {
        Err(_) => bail!(
            "the connection neither carried data nor ended within {:?}",
            REFUSAL
        ),
        Ok(_) if received.windows(payload.len()).any(|w| w == payload) => {
            bail!("the payload was echoed: the connection was not refused")
        }
        Ok(_) => Ok(()),
    }
}
