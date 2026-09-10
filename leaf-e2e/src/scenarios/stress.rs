//! What the host does when there is a lot of it at once.
//!
//! The differential suite asks whether a plugin behaves like the native
//! implementation on one connection; the cost meters ask what the boundary
//! costs on one connection. Neither reaches the parts of the host that only
//! exist because there are many: an engine instance per connection, two wakers
//! per stream that a split hands to different tasks, a mutex in front of a
//! datagram instance, and buffer caps that only matter once someone stops
//! reading.
//!
//! A case here asserts invariants, never timings: every iteration completed,
//! every byte came back the way it went out, every instance that was created
//! was destroyed, and the process was not holding more at the end than at the
//! start. What a load costs is a question for `meters.rs`, where it is asked
//! against native rather than against a number someone picked.
//!
//! Every load runs over the native topology first. A machine that cannot carry
//! sixty-four connections says nothing about a plugin, and the case says so
//! before it ever starts the plugin one.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use tokio::io::AsyncReadExt;

use crate::alloc;
use crate::client::{Socks5, Target};
use crate::conformance;
use crate::differential::Net;
use crate::fixtures::Fixture;
use crate::load::{Churn, Load, Payload};
use crate::node::{cfg, Node, ENV_LOG_LEVEL};
use crate::scenario::{boxed, Scenario, Tag};
use crate::scenarios::differential as matrix;
use crate::servers::{self, Origin};

type LoadFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// What fraction of a load that opens a connection per iteration has to
/// complete. See [`crate::load::Outcome::require_completion`] for why this is
/// not one.
const RELIABLE: f64 = 0.99;

/// One load, and where it belongs.
#[derive(Clone, Copy)]
struct Drive {
    /// First segment of the case id, after `stress/`.
    name: &'static str,
    run: fn(Net) -> LoadFuture,
    /// Only runs where the candidate's plugin registers a datagram engine.
    datagram: bool,
    /// Restricts the load to one candidate, for the ones too long to run three
    /// times over.
    only: Option<&'static str>,
    extra_tags: &'static [Tag],
    timeout: Duration,
}

const CONCURRENCY: Drive = Drive {
    name: "concurrency",
    run: |net| Box::pin(concurrency(net)) as LoadFuture,
    datagram: false,
    only: None,
    extra_tags: &[],
    timeout: Duration::from_secs(120),
};

const CHURN: Drive = Drive {
    name: "churn",
    run: |net| Box::pin(churn(net)) as LoadFuture,
    datagram: false,
    only: None,
    extra_tags: &[],
    timeout: Duration::from_secs(120),
};

const BACKPRESSURE: Drive = Drive {
    name: "backpressure",
    run: |net| Box::pin(backpressure(net)) as LoadFuture,
    datagram: false,
    only: None,
    extra_tags: &[],
    timeout: Duration::from_secs(120),
};

const DATAGRAM_STORM: Drive = Drive {
    name: "datagram",
    run: |net| Box::pin(datagram_storm(net)) as LoadFuture,
    datagram: true,
    only: None,
    extra_tags: &[],
    timeout: Duration::from_secs(120),
};

const SOAK: Drive = Drive {
    name: "soak",
    run: |net| Box::pin(soak(net)) as LoadFuture,
    datagram: false,
    // One candidate: this is minutes of wall clock to answer a question about
    // the host, and the host is the same underneath all of them.
    only: Some("shadowsocks"),
    extra_tags: &[Tag::Soak],
    timeout: Duration::from_secs(1800),
};

pub fn scenarios() -> Vec<Scenario> {
    let drives = [CONCURRENCY, CHURN, BACKPRESSURE, DATAGRAM_STORM, SOAK];

    let mut scenarios = Vec::new();
    for candidate in matrix::candidates() {
        if !matrix::is_primary(candidate.name) {
            continue;
        }
        let fixtures = candidate.group.fixtures();
        let toolchains = matrix::toolchain_tags(&fixtures);

        for drive in drives {
            if drive.datagram && !candidate.suite.carries_datagrams() {
                continue;
            }
            if drive.only.is_some_and(|only| only != candidate.name) {
                continue;
            }
            let group = candidate.group;
            let mut tags = vec![Tag::Plugin, Tag::Stress, Tag::Slow];
            tags.extend(toolchains.iter().copied());
            tags.extend(drive.extra_tags.iter().copied());
            scenarios.push(
                Scenario::new(
                    format!("stress/{}/{}", drive.name, candidate.name),
                    "stress",
                    move || boxed(run(group, drive)),
                )
                .tags(tags)
                .needs(fixtures.clone())
                // Logging under a thousand connections is most of the work
                // the process does, and none of what is being tested. Measured
                // at `debug` this lane's artifact is eight times the size,
                // which is why it stays here and the bulk cases elsewhere do
                // not.
                .env(ENV_LOG_LEVEL, "info")
                .timeout(drive.timeout),
            );
        }
    }
    scenarios.extend(hostile_under_load());
    scenarios
}

/// Runs a load over the native topology and then over the plugin one.
///
/// Both have to pass. The native run is the control: it separates "this
/// machine cannot do this" from "this plugin cannot do this", and a case that
/// cannot tell those apart is worse than no case.
async fn run(group: matrix::Group, drive: Drive) -> Result<()> {
    let native = group.native();
    let deployment = native
        .deploy()
        .await
        .context("starting the native topology")?;
    (drive.run)(deployment.net())
        .await
        .context("the native topology failed this load, so it says nothing about the plugin")?;
    deployment.shutdown().await?;

    let deployment = group
        .deploy()
        .await
        .context("starting the plugin topology")?;
    (drive.run)(deployment.net())
        .await
        .context("the plugin topology failed this load")?;
    deployment.shutdown().await
}

/// Many connections, all busy, all at once.
///
/// Engine instances are per connection and their state is the engine's own, so
/// this is where a plugin keeping state in a global, or a host handing two
/// streams one instance, stops being invisible.
async fn concurrency(net: Net) -> Result<()> {
    const CONNECTIONS: usize = 64;
    const HOLD: Duration = Duration::from_secs(10);

    let outcome = Load::new(Payload::Echo { size: 8 * 1024 })
        .concurrency(CONNECTIONS)
        .for_duration(HOLD)
        .scaled()
        .run(net.socks, net.tcp_origin)
        .await?;
    eprintln!("leaf-e2e: stress/concurrency: {}", outcome);
    outcome.require_clean()?;
    // A load that ran for ten seconds and completed one exchange per
    // connection would be "clean" and would have tested nothing.
    ensure!(
        outcome.completed >= outcome.concurrency * 2,
        "only {} exchanges completed across {} connections",
        outcome.completed,
        outcome.concurrency
    );
    Ok(())
}

/// Connections arriving faster than they finish, while transfers run
/// underneath them.
///
/// Creating and destroying instances while others are mid-transfer is the
/// shape that turns a context released too early into a use-after-free, and
/// the one a deployment actually sees.
async fn churn(net: Net) -> Result<()> {
    const RATE: f64 = 50.0;
    const FOR: Duration = Duration::from_secs(10);

    let storm = Churn::new(RATE, FOR)
        .scaled()
        .run(net.socks, net.tcp_origin);
    let background = Load::new(Payload::Bulk {
        size: 4 * 1024 * 1024,
    })
    .concurrency(2)
    .for_duration(FOR)
    .scaled()
    .run(net.socks, net.tcp_origin);

    let (storm, background) = tokio::join!(storm, background);
    let storm = storm?;
    let background = background?;
    eprintln!("leaf-e2e: stress/churn: storm {}", storm);
    eprintln!("leaf-e2e: stress/churn: background {}", background);

    // A storm opens a connection per arrival, so it is judged on completion
    // rather than on perfection; the transfers underneath it are few and hold
    // their connections, so they are judged on every byte.
    storm
        .require_completion(RELIABLE)
        .context("the connection storm")?;
    background
        .require_completion(RELIABLE)
        .context("the transfers running underneath the storm")?;
    Ok(())
}

/// A reader that stops reading while the far end keeps sending.
///
/// What has to happen is that the pause becomes backpressure on the wire: the
/// host is poll-driven, so an application that stops reading stops the engine,
/// the socket fills, and the far end is throttled. What must not happen is any
/// stage draining the socket into memory to keep itself busy -- a plugin with
/// a runtime and a reader goroutine of its own is exactly how that arrives --
/// or the pause tearing the connection down.
///
/// So this asserts two things: the process holds no more while nobody is
/// reading, and the stream picks up exactly where it left off, in order, when
/// someone does.
async fn backpressure(net: Net) -> Result<()> {
    /// Read before pausing, so the connection is established and flowing.
    const WARM: usize = 512 * 1024;
    const PAUSE: Duration = Duration::from_secs(5);
    /// Read after resuming, to prove the stream survived and stayed in order.
    const AFTER: usize = 2 * 1024 * 1024;
    /// What the whole path may hold while nobody is reading: socket buffers at
    /// both ends of three hops, and whatever each stage had in hand when the
    /// reader stopped. Generous -- and far below what a stage that kept
    /// draining into memory would reach in five seconds at loopback speed,
    /// which is hundreds of megabytes.
    const HELD: u64 = 32 * 1024 * 1024;

    let mut stream = net
        .socks
        .connect(net.tcp_source)
        .await
        .context("opening the connection to the source")?;
    let block = servers::source_block();
    let mut offset = 0usize;
    read_verified(&mut stream, &block, &mut offset, WARM)
        .await
        .context("before the pause")?;

    let growth = alloc::Growth::start();
    tokio::time::sleep(PAUSE).await;
    let growth = growth.finish();
    ensure!(
        growth.bytes() <= HELD,
        "a reader that stopped for {:?} left the process holding {}",
        PAUSE,
        growth
    );

    read_verified(&mut stream, &block, &mut offset, AFTER)
        .await
        .context("after the pause")?;
    eprintln!(
        "leaf-e2e: stress/backpressure: {} held while paused for {:?}",
        growth, PAUSE
    );
    Ok(())
}

/// Reads `count` bytes and checks them against the source's repeating block.
///
/// Position matters as much as content: a byte dropped or duplicated anywhere
/// in the path shifts everything after it, and the mismatch says where.
async fn read_verified(
    stream: &mut tokio::net::TcpStream,
    block: &[u8],
    offset: &mut usize,
    count: usize,
) -> Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut read = 0usize;
    while read < count {
        let want = buf.len().min(count - read);
        let n = stream
            .read(&mut buf[..want])
            .await
            .with_context(|| format!("reading after {} of {} bytes", read, count))?;
        ensure!(n > 0, "the source closed after {} of {} bytes", read, count);
        for byte in &buf[..n] {
            ensure!(
                *byte == block[*offset % block.len()],
                "the stream diverged from the source pattern at byte {}",
                offset
            );
            *offset += 1;
        }
        read += n;
    }
    Ok(())
}

/// Several datagram sessions at once, each pushing packets of every shape.
///
/// One instance per session, all of them behind the host's mutex, and every
/// packet a whole frame the engine has to encode and decode on its own.
async fn datagram_storm(net: Net) -> Result<()> {
    const SESSIONS: usize = 8;
    const PACKETS: usize = 150;
    const SIZES: [usize; 3] = [1, 512, 1400];
    /// Loopback UDP can drop, and a proxied datagram crosses it three times.
    /// A packet in a hundred is noise; more than that is a defect.
    const TOLERATED_LOSS: usize = PACKETS * SESSIONS / 100;
    const REPLY: Duration = Duration::from_secs(5);

    let mut sessions = Vec::with_capacity(SESSIONS);
    for index in 0..SESSIONS {
        let socks = net.socks;
        let origin = net.udp_origin;
        sessions.push(tokio::spawn(async move {
            let session = socks.udp_associate().await?;
            let mut lost = 0usize;
            let mut buf = vec![0u8; 64 * 1024];
            for packet in 0..PACKETS {
                let size = SIZES[packet % SIZES.len()];
                let payload = crate::flow::pseudo_random(size, (index * PACKETS + packet) as u64);
                session.send_to(&payload, origin).await?;
                match tokio::time::timeout(REPLY, session.recv_from(&mut buf)).await {
                    Ok(Ok((n, source))) => {
                        ensure!(
                            buf[..n] == payload[..],
                            "session {}: a datagram of {} bytes came back as {}",
                            index,
                            size,
                            n
                        );
                        ensure!(
                            source == Target::Ip(origin),
                            "session {}: a datagram came back from {:?}",
                            index,
                            source
                        );
                    }
                    Ok(Err(err)) => return Err(err).context("receiving a datagram"),
                    Err(_) => lost += 1,
                }
            }
            Ok::<usize, anyhow::Error>(lost)
        }));
    }

    let mut lost = 0usize;
    for (index, session) in sessions.into_iter().enumerate() {
        lost += session
            .await?
            .with_context(|| format!("datagram session {}", index))?;
    }
    eprintln!(
        "leaf-e2e: stress/datagram: {} sessions x {} packets, {} lost",
        SESSIONS, PACKETS, lost
    );
    ensure!(
        lost <= TOLERATED_LOSS,
        "{} of {} datagrams never came back",
        lost,
        SESSIONS * PACKETS
    );
    Ok(())
}

/// Minutes of mixed traffic, watching what the process is holding.
///
/// A leak of a few kilobytes per connection is invisible in a ten-second case
/// and fatal in a week of running. The measurement is the second half against
/// the first: whatever a deployment allocates once -- caches, pools, a
/// language runtime's heap -- is there by then, so what grows afterwards is
/// what grows forever.
async fn soak(net: Net) -> Result<()> {
    const HALF: Duration = Duration::from_secs(150);
    /// What a steady state is allowed to drift by over the second half.
    const DRIFT: u64 = 32 * 1024 * 1024;

    // Duration is scaled here rather than by `Load::scaled`, because the
    // sampler has to turn round at the same moment the loads do; scaling the
    // concurrency as well would change what a soak is rather than how long it
    // takes.
    let half = HALF
        .mul_f64(crate::load::scale())
        .max(Duration::from_secs(5));
    let mut before = None;
    let watch = async {
        tokio::time::sleep(half).await;
        before = Some(alloc::live_bytes());
        tokio::time::sleep(half).await;
    };

    let exchanges = Load::new(Payload::Echo { size: 16 * 1024 })
        .concurrency(16)
        .for_duration(half * 2)
        .run(net.socks, net.tcp_origin);
    let transfers = Load::new(Payload::Bulk {
        size: 4 * 1024 * 1024,
    })
    .concurrency(2)
    .for_duration(half * 2)
    .run(net.socks, net.tcp_origin);

    let (exchanges, transfers, ()) = tokio::join!(exchanges, transfers, watch);
    let exchanges = exchanges?;
    let transfers = transfers?;
    eprintln!("leaf-e2e: soak: exchanges {}", exchanges);
    eprintln!("leaf-e2e: soak: transfers {}", transfers);
    exchanges.require_clean().context("the exchanges")?;
    transfers
        .require_completion(RELIABLE)
        .context("the transfers")?;

    let before = before.context("the soak ended before it was half over")?;
    let after = alloc::live_bytes();
    let growth = after.saturating_sub(before);
    eprintln!(
        "leaf-e2e: soak: holding {:.1} MiB at the halfway point, {:.1} MiB at the end",
        before as f64 / (1024.0 * 1024.0),
        after as f64 / (1024.0 * 1024.0)
    );
    ensure!(
        growth <= DRIFT,
        "the process grew by {:.1} MiB over the second half of the soak",
        growth as f64 / (1024.0 * 1024.0)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Misbehaving plugins, under load
// ---------------------------------------------------------------------------

/// A fault the host absorbs, driven hard enough to race with itself.
struct Hostile {
    fault: &'static str,
    /// Small for an engine that works a byte at a time, so that a case is a
    /// stress test and not an endurance test.
    payload: usize,
    /// Connections held open for the whole run.
    held: usize,
    /// Connections opened and closed per second underneath them.
    rate: f64,
}

fn hostile_under_load() -> Vec<Scenario> {
    let cases = [
        // The one that most wants a sanitizer: the readiness callback stays
        // valid only until `destroy_instance` returns, and here instances are
        // being destroyed continuously while plugin threads call it.
        Hostile {
            fault: "wake-from-thread",
            payload: 4096,
            held: 32,
            rate: 40.0,
        },
        // An engine that takes a byte at a time turns every exchange into
        // thousands of trips through the host's buffer bookkeeping, which is
        // where an off-by-one in a split or a reclaim would live. Slower work
        // per connection, so fewer of them and a gentler arrival rate.
        Hostile {
            fault: "one-byte-consumer",
            payload: 256,
            held: 16,
            rate: 15.0,
        },
    ];

    cases
        .into_iter()
        .map(|case| {
            Scenario::new(
                format!("stress/hostile/{}-under-load", case.fault),
                "stress",
                move || boxed(under_load(case.fault, case.payload, case.held, case.rate)),
            )
            .tags([Tag::Plugin, Tag::Hostile, Tag::Stress, Tag::Slow])
            .needs([Fixture::Conformance])
            .env(ENV_LOG_LEVEL, "info")
            .timeout(Duration::from_secs(180))
        })
        .collect()
}

/// Drives the conformance plugin's fault across connections that stay open and
/// connections that keep being replaced, and requires every instance the host
/// created to have been destroyed.
///
/// The replacements arrive at a fixed rate rather than as fast as they can be
/// opened. As fast as they can be opened is not a harder test, it is a
/// different one: it exhausts the machine's ephemeral ports, and then every
/// case running beside it fails with the harness's symptoms instead of the
/// host's.
async fn under_load(fault: &'static str, payload: usize, held: usize, rate: f64) -> Result<()> {
    const FOR: Duration = Duration::from_secs(10);

    let before = conformance::stats()?;
    let origin = Origin::tcp_echo().await?;
    let node = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "conformance",
            &Fixture::Conformance.path()?,
            Some(origin.addr()),
            &format!("fault={}", fault),
        ))
        .start()
        .await?;
    let socks = Socks5::new(node.socks_addr()?);

    let sustained = Load::new(Payload::Echo { size: payload })
        .concurrency(held)
        .for_duration(FOR)
        .scaled()
        .run(socks, origin.addr());
    let storm = Churn::new(rate, FOR)
        .payload(Payload::Echo { size: payload })
        .scaled()
        .run(socks, origin.addr());

    let (sustained, storm) = tokio::join!(sustained, storm);
    let sustained = sustained?;
    let storm = storm?;
    eprintln!("leaf-e2e: stress/hostile/{}: held {}", fault, sustained);
    eprintln!("leaf-e2e: stress/hostile/{}: storm {}", fault, storm);
    sustained
        .require_clean()
        .context("the connections held open")?;
    storm
        .require_completion(RELIABLE)
        .context("the connections being replaced")?;

    let after = conformance::wait_for_balanced_instances(Duration::from_secs(30)).await?;
    let created = after.instances_created - before.instances_created;
    let completed = (sustained.concurrency + storm.completed) as u64;
    ensure!(
        created >= completed,
        "{} connections were served but only {} engine instances were created",
        completed,
        created
    );
    node.shutdown().await
}
