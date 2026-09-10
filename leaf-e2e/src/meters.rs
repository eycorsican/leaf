//! What the plugin boundary costs.
//!
//! Every meter here is relative: the same work is measured over a native
//! topology and over one with a plugin in it, in the same run on the same
//! machine, and only the ratio is asserted. Absolute numbers from a shared CI
//! runner say more about the runner than about the code -- they are written to
//! `meters.json` beside the case's logs, where they inform without failing
//! anything.
//!
//! The budgets are loose on purpose. This is a guard against the kind of
//! regression that turns a bulk copy into a byte-at-a-time loop or adds a
//! round trip to every write -- not a benchmark, and not a place to tune. As
//! measured when they were written, a plugin path runs at roughly 0.8-1.0x the
//! native one on every meter here, so each budget leaves three to five times
//! that in headroom.
//!
//! The set is chosen so that each meter can fail on its own:
//!
//! * one stream and eight of them, because a per-connection cost and a
//!   contended one are different regressions;
//! * each direction alone, because an echo hides a decode path that broke
//!   behind an encode path that did not;
//! * messages rather than bytes, because the per-call cost of the engine's
//!   state machine is invisible in a bulk copy;
//! * latency under load, because a poll loop that blocks one direction while
//!   the other is busy still passes an idle round trip.

use std::time::Instant;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::differential::{Budget, Measurement, MeasurementFuture, Meter, Net};
use crate::flow;
use crate::load::{Histogram, Load, Payload};
use crate::scenario::Tag;

/// A meter, with what the registry needs to know to place it.
pub struct Entry {
    pub meter: Meter,
    /// Tags the case gets on top of the ones every perf case carries.
    pub extra_tags: &'static [Tag],
    /// Needs a datagram engine, so it is skipped for a candidate that only
    /// registers a stream one.
    pub datagram: bool,
}

impl Entry {
    const fn new(meter: Meter) -> Self {
        Self {
            meter,
            extra_tags: &[],
            datagram: false,
        }
    }

    const fn tagged(meter: Meter, extra_tags: &'static [Tag]) -> Self {
        Self {
            meter,
            extra_tags,
            datagram: false,
        }
    }

    const fn datagram(meter: Meter) -> Self {
        Self {
            meter,
            extra_tags: &[],
            datagram: true,
        }
    }
}

/// Bytes moved through a bulk echo on one connection, per second.
pub const THROUGHPUT: Meter = Meter {
    name: "throughput",
    run: |net| Box::pin(throughput(net)) as MeasurementFuture,
    // A plugin adds a copy and a state machine; a quarter of the native rate is
    // far below anything healthy and far above anything broken.
    budget: Budget::AtLeast(0.25),
};

/// The same, over several connections at once.
///
/// A cost that only appears under contention -- a lock held across a copy, a
/// waker that loses a wake-up and waits for the next poll -- does not show up
/// on one stream.
pub const THROUGHPUT_PARALLEL: Meter = Meter {
    name: "throughput-parallel",
    run: |net| Box::pin(throughput_parallel(net)) as MeasurementFuture,
    budget: Budget::AtLeast(0.25),
};

/// Bytes pushed towards an origin that only reads.
pub const UPLINK: Meter = Meter {
    name: "uplink",
    run: |net| Box::pin(uplink(net)) as MeasurementFuture,
    budget: Budget::AtLeast(0.25),
};

/// Bytes pulled from an origin that only writes.
pub const DOWNLINK: Meter = Meter {
    name: "downlink",
    run: |net| Box::pin(downlink(net)) as MeasurementFuture,
    budget: Budget::AtLeast(0.25),
};

/// Small messages per second, pipelined so that no round trip separates them.
///
/// What is left when the bytes are few is the fixed cost of each pass through
/// the engine: the `poll_state` call, the size hints, the buffer bookkeeping.
pub const MESSAGES: Meter = Meter {
    name: "messages",
    run: |net| Box::pin(messages(net)) as MeasurementFuture,
    budget: Budget::AtLeast(0.25),
};

/// Time for one small exchange on an established connection.
pub const ROUND_TRIP: Meter = Meter {
    name: "round-trip",
    run: |net| Box::pin(round_trip(net)) as MeasurementFuture,
    budget: Budget::AtMost(5.0),
};

/// The same, while a bulk transfer is running on another connection.
///
/// The tail is the point: an engine whose poll loop finishes the bulk stream
/// before looking at anything else is indistinguishable from a fast one until
/// something else needs the loop.
pub const ROUND_TRIP_LOADED: Meter = Meter {
    name: "round-trip-loaded",
    run: |net| Box::pin(round_trip_loaded(net)) as MeasurementFuture,
    // Wider than the idle budget: a background transfer is contention, and
    // native is exposed to it too, but not identically.
    budget: Budget::AtMost(8.0),
};

/// Time to open a connection, use it, and close it.
pub const CONNECTION_SETUP: Meter = Meter {
    name: "connection-setup",
    run: |net| Box::pin(connection_setup(net)) as MeasurementFuture,
    budget: Budget::AtMost(5.0),
};

/// Datagrams echoed per second, with a window of them in flight.
pub const DATAGRAM_THROUGHPUT: Meter = Meter {
    name: "datagram-throughput",
    run: |net| Box::pin(datagram_throughput(net)) as MeasurementFuture,
    budget: Budget::AtLeast(0.25),
};

/// Bytes moved per second of processor time.
///
/// Loopback is fast enough that a path doing twice the work can still saturate
/// it, which is exactly the regression a wall-clock meter is blind to.
#[cfg(unix)]
pub const CPU_COST: Meter = Meter {
    name: "cpu-cost",
    run: |net| Box::pin(cpu_cost(net)) as MeasurementFuture,
    budget: Budget::AtLeast(0.20),
};

pub fn all() -> Vec<Entry> {
    let mut entries = vec![
        Entry::new(THROUGHPUT),
        Entry::new(THROUGHPUT_PARALLEL),
        Entry::new(UPLINK),
        Entry::new(DOWNLINK),
        Entry::new(MESSAGES),
        Entry::new(ROUND_TRIP),
        Entry::new(CONNECTION_SETUP),
        Entry::datagram(DATAGRAM_THROUGHPUT),
        // Both of these take minutes rather than seconds to say something the
        // cheaper meters mostly already said, so they run in the nightly lane.
        Entry::tagged(ROUND_TRIP_LOADED, &[Tag::Soak]),
    ];
    #[cfg(unix)]
    entries.push(Entry::tagged(CPU_COST, &[Tag::Soak]));
    entries
}

/// How much a single-stream meter moves. Public because the discard origin has
/// to know when to acknowledge it.
pub const STREAM_BYTES: usize = 4 * 1024 * 1024;

async fn throughput(net: Net) -> Result<Measurement> {
    let stream = net
        .socks
        .connect(net.tcp_origin)
        .await
        .context("opening the connection to measure")?;
    let payload = flow::shared_payload(STREAM_BYTES);
    let started = Instant::now();
    flow::bulk_transfer(stream, &payload).await?;
    let elapsed = started.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
    Ok(Measurement {
        name: "throughput",
        value: (STREAM_BYTES as f64) / elapsed / (1024.0 * 1024.0),
        unit: "MiB/s",
    })
}

async fn throughput_parallel(net: Net) -> Result<Measurement> {
    const STREAMS: usize = 8;
    const SIZE: usize = 1024 * 1024;
    // Generated once, before the clock: see `Payload::Transfer`.
    let _ = flow::shared_payload(SIZE);
    let outcome = Load::new(Payload::Transfer { size: SIZE })
        .concurrency(STREAMS)
        .run(net.socks, net.tcp_origin)
        .await?;
    // A meter measures a working system. A transfer that failed would drag the
    // rate down and read as a slow path rather than as a broken one.
    outcome
        .require_clean()
        .context("the parallel transfers did not all complete")?;
    Ok(Measurement {
        name: "throughput-parallel",
        value: outcome.throughput_mib(),
        unit: "MiB/s",
    })
}

/// Writes to an origin that only reads, and stops the clock when the origin
/// says it has everything.
///
/// The acknowledgement is what makes the end observable. Waiting for the
/// origin to close instead would mean half-closing first, and a half-close
/// does not cross every chain: leaf's websocket transport cannot express one,
/// so the origin would never learn the request had ended and this would time
/// leaf's ten-second idle timeout. It did, until it stopped asking for one --
/// the tls chain measured 0.4 MiB/s while carrying forty.
async fn uplink(net: Net) -> Result<Measurement> {
    let payload = flow::shared_payload(STREAM_BYTES);
    let mut stream = net
        .socks
        .connect(net.tcp_discard)
        .await
        .context("opening the connection to measure")?;

    let started = Instant::now();
    stream.write_all(&payload).await.context("writing uplink")?;
    stream.flush().await?;
    let mut ack = [0u8; 1];
    stream
        .read_exact(&mut ack)
        .await
        .context("waiting for the origin to acknowledge the upload")?;
    if ack[0] != crate::servers::ACK {
        bail!("the discard origin answered with {:#04x}", ack[0]);
    }
    let elapsed = started.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
    Ok(Measurement {
        name: "uplink",
        value: (STREAM_BYTES as f64) / elapsed / (1024.0 * 1024.0),
        unit: "MiB/s",
    })
}

/// Reads from an origin that never stops writing.
async fn downlink(net: Net) -> Result<Measurement> {
    let mut stream = net
        .socks
        .connect(net.tcp_source)
        .await
        .context("opening the connection to measure")?;

    let started = Instant::now();
    let mut received = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    while received < STREAM_BYTES {
        let n = stream
            .read(&mut buf)
            .await
            .with_context(|| format!("reading downlink after {} bytes", received))?;
        if n == 0 {
            bail!(
                "the source origin closed after {} of {} bytes",
                received,
                STREAM_BYTES
            );
        }
        received += n;
    }
    let elapsed = started.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
    Ok(Measurement {
        name: "downlink",
        value: (received as f64) / elapsed / (1024.0 * 1024.0),
        unit: "MiB/s",
    })
}

async fn messages(net: Net) -> Result<Measurement> {
    const SIZE: usize = 512;
    const DEPTH: usize = 32;
    const ROUNDS: usize = 100;
    let outcome = Load::new(Payload::Messages {
        size: SIZE,
        depth: DEPTH,
    })
    .iterations(ROUNDS)
    .run(net.socks, net.tcp_origin)
    .await?;
    outcome
        .require_clean()
        .context("the message rounds did not all complete")?;
    Ok(Measurement {
        name: "messages",
        value: outcome.ops_per_second(),
        unit: "msg/s",
    })
}

async fn round_trip(net: Net) -> Result<Measurement> {
    let mut stream = net.socks.connect(net.tcp_origin).await?;
    let latency = exchange_latency(&mut stream, 200).await?;
    Ok(Measurement {
        name: "round-trip",
        value: percentile_us(&latency, 0.50)?,
        unit: "us",
    })
}

async fn round_trip_loaded(net: Net) -> Result<Measurement> {
    // Transfers back to back for as long as the exchanges take. Unverified,
    // like the throughput meters: the contention this puts on the poll loops
    // is the point, and hashing it in the harness would spend the machine on
    // something that is not under test.
    let payload = flow::shared_payload(STREAM_BYTES);
    let load = tokio::spawn(async move {
        loop {
            let Ok(stream) = net.socks.connect(net.tcp_origin).await else {
                return;
            };
            if flow::bulk_transfer(stream, &payload).await.is_err() {
                return;
            }
        }
    });

    let mut stream = net.socks.connect(net.tcp_origin).await?;
    let measured = exchange_latency(&mut stream, 200).await;
    load.abort();
    let latency = measured?;

    Ok(Measurement {
        name: "round-trip-loaded",
        // The tail, not the middle: contention is a distribution, and the
        // interesting half of it is the slow one.
        value: percentile_us(&latency, 0.99)?,
        unit: "us",
    })
}

/// Times `exchanges` small round trips on an established connection.
async fn exchange_latency(
    stream: &mut tokio::net::TcpStream,
    exchanges: usize,
) -> Result<Histogram> {
    let payload = flow::pseudo_random(64, 0x77);
    let mut echoed = vec![0u8; payload.len()];

    // One exchange first, so the handshake is not counted as latency.
    stream.write_all(&payload).await?;
    stream.flush().await?;
    stream.read_exact(&mut echoed).await?;

    let mut latency = Histogram::default();
    for _ in 0..exchanges {
        let started = Instant::now();
        stream.write_all(&payload).await?;
        stream.flush().await?;
        stream.read_exact(&mut echoed).await?;
        latency.record(started.elapsed());
    }
    Ok(latency)
}

fn percentile_us(latency: &Histogram, fraction: f64) -> Result<f64> {
    let sample = latency
        .percentile(fraction)
        .ok_or_else(|| anyhow::anyhow!("no exchange completed"))?;
    Ok(sample.as_secs_f64() * 1_000_000.0)
}

async fn connection_setup(net: Net) -> Result<Measurement> {
    const CONNECTIONS: usize = 30;
    let started = Instant::now();
    for index in 0..CONNECTIONS {
        let mut stream = net
            .socks
            .connect(net.tcp_origin)
            .await
            .with_context(|| format!("opening connection {}", index))?;
        flow::echo_roundtrip(&mut stream, b"hi")
            .await
            .with_context(|| format!("using connection {}", index))?;
        // One connection at a time, closed by the drop. Holding them all open
        // until the clock stopped would measure setup alone, but a chain puts
        // five or six descriptors behind every connection -- both leaf nodes
        // run in this process -- and the default limit on a Mac is 256.
        // Closing them in order instead would cost leaf's downlink timeout on
        // every one of them.
    }
    let elapsed = started.elapsed().as_secs_f64();
    Ok(Measurement {
        name: "connection-setup",
        value: elapsed / CONNECTIONS as f64 * 1000.0,
        unit: "ms",
    })
}

/// Datagrams echoed per second, a window at a time.
///
/// A window rather than one at a time, because sending and waiting would
/// measure the round trip that `round-trip` already measures. Loopback UDP can
/// still drop, so a window that comes back short is tolerated and counted; the
/// measurement fails only if most of them go missing, which is a defect rather
/// than noise.
async fn datagram_throughput(net: Net) -> Result<Measurement> {
    const WINDOW: usize = 16;
    const WINDOWS: usize = 40;
    const SIZE: usize = 1200;
    let session = net.socks.udp_associate().await?;
    let payload = flow::pseudo_random(SIZE, 0xda7a);

    let started = Instant::now();
    let mut received = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    for _ in 0..WINDOWS {
        for _ in 0..WINDOW {
            session.send_to(&payload, net.udp_origin).await?;
        }
        for _ in 0..WINDOW {
            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                session.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok((n, _))) if n == SIZE => received += 1,
                Ok(Ok((n, _))) => bail!("a datagram of {} bytes came back as {}", SIZE, n),
                Ok(Err(err)) => return Err(err).context("receiving a datagram"),
                // A window that came back short: stop waiting for it and send
                // the next one.
                Err(_) => break,
            }
        }
    }
    let elapsed = started.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);

    let sent = WINDOW * WINDOWS;
    if received * 2 < sent {
        bail!(
            "only {} of {} datagrams came back; this is not a slow path but a broken one",
            received,
            sent
        );
    }
    Ok(Measurement {
        name: "datagram-throughput",
        value: received as f64 / elapsed,
        unit: "pkt/s",
    })
}

/// Bytes moved per second of processor time this process spent.
///
/// Both leaf nodes and the plugin run in this process, so `RUSAGE_SELF` covers
/// the whole path. The harness is in there too, and identically on both sides.
#[cfg(unix)]
async fn cpu_cost(net: Net) -> Result<Measurement> {
    let stream = net
        .socks
        .connect(net.tcp_origin)
        .await
        .context("opening the connection to measure")?;
    let payload = flow::shared_payload(STREAM_BYTES);
    let before = cpu_seconds();
    flow::bulk_transfer(stream, &payload).await?;
    let spent = (cpu_seconds() - before).max(f64::MIN_POSITIVE);
    Ok(Measurement {
        name: "cpu-cost",
        value: (STREAM_BYTES as f64) / spent / (1024.0 * 1024.0),
        unit: "MiB/cpu-s",
    })
}

/// User plus system time this process has used.
#[cfg(unix)]
fn cpu_seconds() -> f64 {
    // Safety: `getrusage` fills a `rusage` this function owns.
    unsafe {
        let mut usage = std::mem::zeroed::<libc::rusage>();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) != 0 {
            return 0.0;
        }
        let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
        seconds(usage.ru_utime) + seconds(usage.ru_stime)
    }
}
