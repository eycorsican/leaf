//! Plugins that lie, and what the host does about it.
//!
//! The host runs plugins in its own process with its own privileges, so nothing
//! here makes a hostile plugin safe. What it does make is the difference
//! between an accidentally wrong plugin and a corrupted host: a `consumed`
//! larger than the input, a `produced` larger than the buffer, a size hint no
//! one should honour, an engine that will never make progress. Each of those
//! has to become a failed connection with something to say, never a crash and
//! never a hang.
//!
//! Run this lane under a sanitizer as well as plainly; that is what the
//! `hostile` tag is for.

use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::client::Socks5;
use crate::conformance;
use crate::fixtures::Fixture;
use crate::flow;
use crate::logs;
use crate::node::{cfg, LeafNode, Node};
use crate::scenario::{boxed, Scenario, Tag};
use crate::servers::Origin;

/// Long enough that a working connection has certainly answered, short enough
/// that a hang is reported as one.
const VERDICT: Duration = Duration::from_secs(10);

struct Case {
    id: &'static str,
    fault: &'static str,
    outcome: Outcome,
    /// What the host has to say about it, in its own log. Asserting on this is
    /// the difference between "the connection broke" and "the host caught
    /// exactly this and named it".
    reported: Option<&'static str>,
}

#[derive(Clone, Copy)]
enum Outcome {
    /// The connection has to fail rather than carry data.
    ConnectionFails,
    /// The fault is one the host absorbs; traffic still has to work.
    TrafficStillWorks,
}

pub fn scenarios() -> Vec<Scenario> {
    let cases = [
        Case {
            id: "hostile/over-reported-consumed",
            fault: "overreport-consumed",
            outcome: Outcome::ConnectionFails,
            reported: Some("stream engine push(app) consumed"),
        },
        Case {
            id: "hostile/over-reported-produced",
            fault: "overreport-produced",
            outcome: Outcome::ConnectionFails,
            reported: Some("bytes into a"),
        },
        Case {
            id: "hostile/engine-that-never-progresses",
            fault: "stall",
            outcome: Outcome::ConnectionFails,
            reported: Some("made no progress and is not waiting for input"),
        },
        Case {
            id: "hostile/engine-that-refuses-to-be-created",
            fault: "create-null",
            outcome: Outcome::ConnectionFails,
            // The plugin's own words, which only arrive if the host asked it
            // for them and copied the answer out correctly.
            reported: Some("refused to create an instance on purpose"),
        },
        Case {
            id: "hostile/engine-that-goes-fatal",
            fault: "fatal-after-write",
            outcome: Outcome::ConnectionFails,
            reported: Some("entered fatal state"),
        },
        // Not a failure to report: an absurd hint has to be clamped and the
        // connection carry on.
        Case {
            id: "hostile/absurd-output-size-hints",
            fault: "huge-size-hints",
            outcome: Outcome::TrafficStillWorks,
            reported: None,
        },
        // Nor is a stingy engine: it takes as many rounds as it takes.
        Case {
            id: "hostile/engine-that-takes-one-byte-at-a-time",
            fault: "one-byte-consumer",
            outcome: Outcome::TrafficStillWorks,
            reported: None,
        },
        // A log target longer than any cap, cut inside a character, and one
        // with no terminator at all. Truncating the first by slicing a `str`
        // at a byte index panics, and a panic in a callback the plugin invoked
        // is an abort -- so this case passing at all is most of the point.
        // The message still has to arrive, under a target the host trimmed.
        Case {
            id: "hostile/absurd-log-targets",
            fault: "bad-log-target",
            outcome: Outcome::TrafficStillWorks,
            reported: Some("logged under a target cut inside a character"),
        },
        // The host asks how long the explanation is before allocating room for
        // it. An engine that answers `usize::MAX` must not be believed.
        Case {
            id: "hostile/made-up-error-length",
            fault: "huge-error-length",
            outcome: Outcome::ConnectionFails,
            reported: Some("error length it made up"),
        },
    ];

    let mut scenarios: Vec<Scenario> = cases
        .into_iter()
        .map(|case| {
            Scenario::new(case.id, "hostile", move || {
                boxed(run(case.fault, case.outcome, case.reported))
            })
            .tags([Tag::Plugin, Tag::Hostile])
            .needs([Fixture::Conformance])
            .timeout(Duration::from_secs(45))
        })
        .collect();

    // The same questions asked of a plugin that carries a language runtime,
    // where the answer comes from somewhere else entirely: the Go SDK's
    // boundary, which has to turn a panic -- and a hardware fault, which Go
    // makes into a panic -- into a status code rather than letting it cross
    // into the host. A Rust plugin cannot stand in for this: it has no runtime
    // to catch anything, and a fault in it is simply a crash.
    let go_cases = [
        Case {
            id: "hostile/go/panic-in-push",
            fault: "panic-in-push",
            outcome: Outcome::ConnectionFails,
            reported: Some("panic across the ABI boundary"),
        },
        Case {
            id: "hostile/go/panic-in-pull",
            fault: "panic-in-pull",
            outcome: Outcome::ConnectionFails,
            reported: Some("panic across the ABI boundary"),
        },
        Case {
            id: "hostile/go/panic-before-the-instance-exists",
            fault: "panic-in-create",
            outcome: Outcome::ConnectionFails,
            reported: Some("panic across the ABI boundary"),
        },
        // Not a panic but an access violation, which the Go runtime has to
        // claim through its own exception handler and turn into a panic before
        // the SDK can catch anything. Asserting on the runtime's own words is
        // what tells the two apart.
        Case {
            id: "hostile/go/a-fault-becomes-a-failed-connection",
            fault: "fault-in-push",
            outcome: Outcome::ConnectionFails,
            reported: Some("nil pointer dereference"),
        },
    ];
    scenarios.extend(go_cases.into_iter().map(|case| {
        Scenario::new(case.id, "hostile", move || {
            boxed(run_go(case.fault, case.outcome, case.reported))
        })
        .tags([Tag::Plugin, Tag::Hostile, Tag::Go])
        .needs([Fixture::ConformanceGo])
        .timeout(Duration::from_secs(60))
    }));
    scenarios.push(
        Scenario::new(
            "hostile/go/a-fault-with-another-runtime-live",
            "hostile",
            || boxed(a_fault_with_another_runtime_live()),
        )
        .tags([Tag::Plugin, Tag::Hostile, Tag::Go])
        .needs([Fixture::ConformanceGo, Fixture::TlsCabiGo])
        .timeout(Duration::from_secs(90)),
    );

    scenarios.push(
        Scenario::new(
            "hostile/engine-that-never-reads-the-peer",
            "hostile",
            || boxed(never_reads_the_peer()),
        )
        .tags([Tag::Plugin, Tag::Hostile])
        .needs([Fixture::Conformance])
        .timeout(Duration::from_secs(60)),
    );
    scenarios.push(
        Scenario::new("hostile/wake-from-a-plugin-thread", "hostile", || {
            boxed(wake_from_a_plugin_thread())
        })
        .tags([Tag::Plugin, Tag::Hostile])
        .needs([Fixture::Conformance])
        .timeout(Duration::from_secs(60)),
    );
    scenarios.push(
        Scenario::new("hostile/instances-are-destroyed", "hostile", || {
            boxed(instances_are_destroyed())
        })
        .tags([Tag::Plugin, Tag::Hostile])
        .needs([Fixture::Conformance])
        .timeout(Duration::from_secs(45)),
    );
    scenarios.push(
        Scenario::new("hostile/one-library-serves-many-tags", "hostile", || {
            boxed(one_library_serves_many_tags())
        })
        .tags([Tag::Plugin, Tag::Hostile])
        .needs([Fixture::Conformance])
        .timeout(Duration::from_secs(45)),
    );
    scenarios.push(
        Scenario::new(
            "hostile/reload-drops-a-live-stream-plugin",
            "hostile",
            || boxed(reload_drops_a_live_stream_plugin()),
        )
        .tags([Tag::Plugin, Tag::Hostile])
        .needs([Fixture::Conformance])
        .timeout(Duration::from_secs(60)),
    );
    scenarios.push(
        Scenario::new(
            "hostile/reload-drops-a-live-datagram-plugin",
            "hostile",
            || boxed(reload_drops_a_live_datagram_plugin()),
        )
        .tags([Tag::Plugin, Tag::Hostile])
        .needs([Fixture::Conformance])
        .env(conformance::ENV_DESCRIPTOR, "datagram-unreliable")
        .timeout(Duration::from_secs(60)),
    );
    scenarios
}

/// A reload that takes the plugin outbound away while a stream through it is
/// still open.
///
/// The handler that holds the loaded library goes with the old configuration;
/// the connection does not. What the stream wrapper holds is the vtable, which
/// is nothing but function pointers into that library, so unless it keeps the
/// library mapped itself the reload unmaps the code the live stream is about to
/// call -- on its next read, and again when its instance is destroyed.
///
/// How loudly that fails is a property of the platform: on Linux `dlclose`
/// unmaps and the case crashes, under a sanitizer with a diagnosis. macOS
/// dyld usually declines to unmap, so there the case only says the reload
/// itself works. It is worth running on both for that reason.
async fn reload_drops_a_live_stream_plugin() -> Result<()> {
    let origin = Origin::tcp_echo().await?;
    let node = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "conformance",
            &Fixture::Conformance.path()?,
            Some(origin.addr()),
            "",
        ))
        .start_reloadable()
        .await?;
    let socks_addr = node.socks_addr()?;

    let mut stream = Socks5::new(socks_addr).connect(origin.addr()).await?;
    flow::echo_roundtrip(&mut stream, b"before-reload").await?;

    // The new configuration keeps the inbound -- reload leaves listeners alone
    // -- and names no plugin at all, which is what drops the last handler
    // holding the library.
    node.reload_to(
        &Node::new("client")
            .inbound(cfg::socks_inbound("socks-in", socks_addr.port()))
            .outbound(cfg::direct("direct")),
    )
    .await?;

    flow::echo_roundtrip(&mut stream, b"after-reload").await?;
    // The instance is destroyed here, through the same vtable.
    drop(stream);
    conformance::wait_for_balanced_instances(Duration::from_secs(15)).await?;

    // The node is still serving, now over the outbound that replaced the
    // plugin, which is what says the reload itself worked.
    let mut direct = Socks5::new(socks_addr).connect(origin.addr()).await?;
    flow::echo_roundtrip(&mut direct, b"after-the-plugin-is-gone").await?;
    drop(direct);

    node.shutdown().await
}

/// The same reload, against a UDP session.
///
/// This is the harder half: a datagram session outlives its handler by design.
/// `dispatch_datagram` hands the wrapper back and drops the handler, and the
/// NAT session holds the wrapper from a task of its own for as long as the
/// session lasts.
async fn reload_drops_a_live_datagram_plugin() -> Result<()> {
    let origin = Origin::udp_echo().await?;
    let node = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "conformance",
            &Fixture::Conformance.path()?,
            Some(origin.addr()),
            "",
        ))
        .start_reloadable()
        .await?;
    let socks_addr = node.socks_addr()?;

    let session = Socks5::new(socks_addr).udp_associate().await?;
    session.send_to(b"before-reload", origin.addr()).await?;
    let mut buf = [0u8; 128];
    let (n, _) = tokio::time::timeout(VERDICT, session.recv_from(&mut buf)).await??;
    ensure!(&buf[..n] == b"before-reload", "udp echo before the reload");

    node.reload_to(
        &Node::new("client")
            .inbound(cfg::socks_inbound("socks-in", socks_addr.port()))
            .outbound(cfg::direct("direct")),
    )
    .await?;

    // The session was established through the plugin and is still routed
    // through it, so this goes through the engine of an outbound that no
    // configuration names any more.
    session.send_to(b"after-reload", origin.addr()).await?;
    let (n, _) = tokio::time::timeout(VERDICT, session.recv_from(&mut buf)).await??;
    ensure!(&buf[..n] == b"after-reload", "udp echo after the reload");

    drop(session);
    node.shutdown().await
}

/// A client whose only route is the conformance plugin, relaying to `origin`.
async fn start_node(origin: std::net::SocketAddr, args: &str) -> Result<LeafNode> {
    start_node_with(Fixture::Conformance, origin, args).await
}

/// The same, for whichever conformance plugin the case is about.
async fn start_node_with(
    fixture: Fixture,
    origin: std::net::SocketAddr,
    args: &str,
) -> Result<LeafNode> {
    Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "conformance",
            &fixture.path()?,
            Some(origin),
            args,
        ))
        .start()
        .await
}

async fn run(fault: &'static str, outcome: Outcome, reported: Option<&'static str>) -> Result<()> {
    let origin = Origin::tcp_echo().await?;
    let node = start_node(origin.addr(), &format!("fault={}", fault)).await?;
    let socks = Socks5::new(node.socks_addr()?);

    match outcome {
        Outcome::TrafficStillWorks => {
            let mut stream = socks.connect(origin.addr()).await?;
            flow::echo_roundtrip(&mut stream, b"hello").await?;
            // A second, larger exchange, because a clamp that is wrong by a
            // little only shows up once a buffer has to be reused.
            let payload = flow::pseudo_random(96 * 1024, 0xc1a3);
            flow::echo_roundtrip(&mut stream, &payload).await?;
        }
        Outcome::ConnectionFails => expect_failure(&socks, origin.addr(), fault).await?,
    }

    if let Some(needle) = reported {
        logs::wait_for(needle, VERDICT).await?;
    }

    node.shutdown().await
}

/// The same, through the Go conformance plugin.
///
/// What is under test here is not the host's arithmetic but the SDK's
/// boundary: whatever the engine does to itself has to come back as a status
/// code, so that the host sees a failing plugin rather than a failing process.
async fn run_go(
    fault: &'static str,
    outcome: Outcome,
    reported: Option<&'static str>,
) -> Result<()> {
    let origin = Origin::tcp_echo().await?;
    let node = start_node_with(
        Fixture::ConformanceGo,
        origin.addr(),
        &format!("fault={}", fault),
    )
    .await?;
    let socks = Socks5::new(node.socks_addr()?);

    match outcome {
        Outcome::TrafficStillWorks => {
            let mut stream = socks.connect(origin.addr()).await?;
            flow::echo_roundtrip(&mut stream, b"hello").await?;
        }
        Outcome::ConnectionFails => expect_failure(&socks, origin.addr(), fault).await?,
    }

    if let Some(needle) = reported {
        logs::wait_for(needle, VERDICT).await?;
    }

    node.shutdown().await
}

/// A Go plugin faults while a second Go runtime is loaded and working.
///
/// This is the one thing two Go `c-shared` libraries in one process actually
/// have to arbitrate. Each runtime registers a vectored exception handler, and
/// each claims an exception only when the faulting instruction is inside its
/// own module -- so a fault in one must be turned into that one's panic, and
/// must not be taken, mishandled or dropped by the other. Get it wrong and the
/// process dies instead of the connection.
///
/// The second runtime is asked to work again afterwards, because the failure
/// worth catching is not the fault being mishandled at the moment it happens
/// but the other runtime being left in a state it cannot continue from.
async fn a_fault_with_another_runtime_live() -> Result<()> {
    // A whole working topology whose TLS stage is a different Go library, and
    // therefore a different Go runtime, live for as long as this case is.
    let bystander = crate::scenarios::differential::Group::TlsChain {
        tls: crate::scenarios::differential::Stage::Plugin(Fixture::TlsCabiGo),
        trojan: crate::scenarios::differential::Stage::Native,
    };
    let bystander = bystander.deploy().await?;
    (crate::behaviours::ECHO.run)(bystander.net())
        .await
        .context("the second runtime was not working before the fault, so this proves nothing")?;

    let origin = Origin::tcp_echo().await?;
    let node =
        start_node_with(Fixture::ConformanceGo, origin.addr(), "fault=fault-in-push").await?;
    let socks = Socks5::new(node.socks_addr()?);
    expect_failure(&socks, origin.addr(), "fault-in-push").await?;
    logs::wait_for("nil pointer dereference", VERDICT).await?;
    node.shutdown().await?;

    (crate::behaviours::ECHO.run)(bystander.net())
        .await
        .context("the second runtime stopped working after the first one faulted")?;
    bystander.shutdown().await
}

/// Requires the connection to fail -- at setup or on the first exchange -- and
/// specifically not to hang.
async fn expect_failure(socks: &Socks5, origin: std::net::SocketAddr, fault: &str) -> Result<()> {
    let connected = tokio::time::timeout(VERDICT, socks.connect(origin))
        .await
        .map_err(|_| anyhow::anyhow!("fault [{}]: the connection attempt hung", fault))?;
    // Failing here is a perfectly good outcome: the host refused to build the
    // stream at all.
    let Ok(mut stream) = connected else {
        return Ok(());
    };

    let exchange = tokio::time::timeout(VERDICT, async {
        stream.write_all(b"hello").await?;
        stream.flush().await?;
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await?;
        Ok::<[u8; 5], std::io::Error>(echoed)
    })
    .await;

    match exchange {
        Err(_) => bail!(
            "fault [{}]: the connection neither answered nor failed within {:?}",
            fault,
            VERDICT
        ),
        Ok(Ok(echoed)) => bail!(
            "fault [{}]: the connection echoed {:?} instead of failing",
            fault,
            echoed
        ),
        Ok(Err(_)) => Ok(()),
    }
}

/// An engine that takes nothing from the network leaves the host holding
/// whatever the peer sends. That has to stop somewhere, and be reported, rather
/// than grow until the process dies.
async fn never_reads_the_peer() -> Result<()> {
    // Comfortably more than the host is willing to hold undelivered.
    const PUSHED: usize = 512 * 1024;

    let origin = Origin::tcp_echo().await?;
    let node = start_node(origin.addr(), "fault=refuse-net-input").await?;
    let socks = Socks5::new(node.socks_addr()?);

    let mut stream = socks.connect(origin.addr()).await?;
    let payload = flow::pseudo_random(PUSHED, 0xfeed);
    // The write direction still works, so the echo comes back and piles up on
    // the side the engine refuses to touch. Failing here is fine: the host is
    // expected to tear the connection down partway through.
    let _ = tokio::time::timeout(VERDICT, async {
        stream.write_all(&payload).await?;
        stream.flush().await
    })
    .await;

    logs::wait_for("buffered bytes of network input", VERDICT).await?;
    node.shutdown().await
}

/// A plugin calling the host's readiness callback from a thread of its own,
/// continuously, while connections come and go.
///
/// The callback stays valid only until `destroy_instance` returns, so this is
/// where a host that lets an instance's context go early, or a plugin that
/// fails to join its threads, turns into a use-after-free. Run it under a
/// sanitizer; that is what the `hostile` tag is for.
async fn wake_from_a_plugin_thread() -> Result<()> {
    const ROUNDS: u64 = 12;

    let before = conformance::stats()?;
    let origin = Origin::tcp_echo().await?;
    let node = start_node(origin.addr(), "fault=wake-from-thread").await?;
    let socks = Socks5::new(node.socks_addr()?);

    for round in 0..ROUNDS {
        let payload = flow::pseudo_random(4096, 0x3a3e + round);
        let mut stream = socks.connect(origin.addr()).await?;
        flow::echo_roundtrip(&mut stream, &payload).await?;
        // Dropped while its thread is still waking the host, which is the
        // moment that matters.
        drop(stream);
    }

    let after = conformance::wait_for_balanced_instances(Duration::from_secs(20)).await?;
    ensure!(
        after.instances_created - before.instances_created == ROUNDS,
        "expected {} instances, saw {}",
        ROUNDS,
        after.instances_created - before.instances_created
    );

    node.shutdown().await
}

/// Every connection creates an engine instance; every one of them has to be
/// destroyed once its stream is gone.
async fn instances_are_destroyed() -> Result<()> {
    const CONNECTIONS: u64 = 8;

    let before = conformance::stats()?;
    let origin = Origin::tcp_echo().await?;
    let node = start_node(origin.addr(), "").await?;
    let socks = Socks5::new(node.socks_addr()?);

    for _ in 0..CONNECTIONS {
        let mut stream = socks.connect(origin.addr()).await?;
        flow::echo_roundtrip(&mut stream, b"hello").await?;
        drop(stream);
    }

    let after = conformance::wait_for_balanced_instances(Duration::from_secs(15)).await?;
    ensure!(
        after.instances_created - before.instances_created == CONNECTIONS,
        "expected {} instances, saw {}",
        CONNECTIONS,
        after.instances_created - before.instances_created
    );

    node.shutdown().await?;
    conformance::wait_for_balanced_instances(Duration::from_secs(15)).await?;
    Ok(())
}

/// Two outbounds naming the same file share one mapping, and the host reads the
/// descriptor once.
async fn one_library_serves_many_tags() -> Result<()> {
    let origin = Origin::tcp_echo().await?;
    let path = Fixture::Conformance.path()?;
    let before = conformance::stats()?;

    let node = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin("conformance-a", &path, Some(origin.addr()), ""))
        .outbound(cfg::plugin("conformance-b", &path, Some(origin.addr()), ""))
        .start()
        .await?;

    let reads = conformance::stats()?.descriptor_reads - before.descriptor_reads;
    ensure!(
        reads == 1,
        "two tags on one file should read the descriptor once, but it was read {} times",
        reads
    );

    // The first outbound is the default route, so this proves the shared
    // library is actually usable and not merely cached.
    let mut stream = Socks5::new(node.socks_addr()?)
        .connect(origin.addr())
        .await?;
    flow::echo_roundtrip(&mut stream, b"hello").await?;

    node.shutdown().await
}
