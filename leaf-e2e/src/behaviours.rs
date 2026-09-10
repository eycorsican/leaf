//! Traffic patterns, written once and run over every implementation.
//!
//! A behaviour knows nothing about what carries it. That is what lets the same
//! one serve as the native baseline and as the plugin case, and what makes the
//! comparison between them meaningful.
//!
//! Every fact a behaviour records has to be reproducible across two runs of the
//! same topology: no timings, no ports, no addresses. Anything else would make
//! the comparison flaky rather than informative.

use std::time::Duration;

use anyhow::{ensure, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::client::Target;
use crate::differential::{Behaviour, Net, Observation, ObservationFuture};
use crate::flow;
use crate::scenario::Tag;

/// How long one exchange may take before the behaviour calls it lost. The case
/// deadline is the real backstop; this exists to report *which* step hung.
const STEP: Duration = Duration::from_secs(15);

/// How much the bulk behaviour moves. Adjustable so that a soak run can push
/// harder and a slow machine can push less, without editing the suite.
const ENV_BULK_BYTES: &str = "LEAF_E2E_BULK_BYTES";
const DEFAULT_BULK_BYTES: usize = 4 * 1024 * 1024;

pub fn bulk_bytes() -> usize {
    std::env::var(ENV_BULK_BYTES)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_BULK_BYTES)
}

pub const ECHO: Behaviour = Behaviour {
    name: "echo",
    run: |net| Box::pin(echo(net)) as ObservationFuture,
};

pub const LARGE_WRITE: Behaviour = Behaviour {
    name: "large-write",
    run: |net| Box::pin(large_write(net)) as ObservationFuture,
};

pub const CONCURRENT: Behaviour = Behaviour {
    name: "concurrent-connections",
    run: |net| Box::pin(concurrent(net)) as ObservationFuture,
};

pub const BULK: Behaviour = Behaviour {
    name: "bulk-transfer",
    run: |net| Box::pin(bulk(net)) as ObservationFuture,
};

pub const UDP: Behaviour = Behaviour {
    name: "udp",
    run: |net| Box::pin(udp(net)) as ObservationFuture,
};

pub const HALF_CLOSE_TAIL: Behaviour = Behaviour {
    name: "half-close-tail",
    run: |net| Box::pin(half_close_tail(net)) as ObservationFuture,
};

pub const HALF_CLOSE: Behaviour = Behaviour {
    name: "half-close",
    run: |net| Box::pin(half_close(net)) as ObservationFuture,
};

pub const PEER_CLOSES_FIRST: Behaviour = Behaviour {
    name: "peer-closes-first",
    run: |net| Box::pin(peer_closes_first(net)) as ObservationFuture,
};

pub const DOMAIN_DESTINATION: Behaviour = Behaviour {
    name: "domain-destination",
    run: |net| Box::pin(domain_destination(net)) as ObservationFuture,
};

pub const CONNECTION_CHURN: Behaviour = Behaviour {
    name: "connection-churn",
    run: |net| Box::pin(connection_churn(net)) as ObservationFuture,
};

/// A name the server node resolves from its own hosts map, so a domain
/// destination is a fact about address handling rather than about DNS.
pub const TEST_DOMAIN: &str = "origin.e2e.invalid";

/// The behaviours every stream-carrying topology must pass, with the extra tags
/// each one earns.
pub fn stream_suite() -> Vec<(Behaviour, Vec<Tag>)> {
    vec![
        (ECHO, vec![]),
        (LARGE_WRITE, vec![]),
        (CONCURRENT, vec![]),
        (HALF_CLOSE, vec![]),
        (HALF_CLOSE_TAIL, vec![]),
        (PEER_CLOSES_FIRST, vec![]),
        (DOMAIN_DESTINATION, vec![]),
        (CONNECTION_CHURN, vec![]),
        (BULK, vec![Tag::Slow]),
    ]
}

/// Two exchanges on one connection.
///
/// The second one is the point: a handshake that leaves the engine in a bad
/// state still passes the first.
async fn echo(net: Net) -> Result<Observation> {
    let mut observed = Observation::default();
    let mut stream = net.socks.connect(net.tcp_origin).await?;
    for (index, payload) in [&b"hello"[..], &b"and again"[..]].into_iter().enumerate() {
        tokio::time::timeout(STEP, flow::echo_roundtrip(&mut stream, payload)).await??;
        observed.record(format!("exchange-{}", index), payload.len());
    }
    Ok(observed)
}

/// One write far larger than any sane engine buffer, so the reply arrives in
/// pieces the reader has to reassemble.
async fn large_write(net: Net) -> Result<Observation> {
    const SIZE: usize = 256 * 1024;
    let mut observed = Observation::default();
    let payload = flow::pseudo_random(SIZE, 0x1a26e);
    let mut stream = net.socks.connect(net.tcp_origin).await?;

    let expected = flow::digest(&payload);
    tokio::time::timeout(STEP, async {
        stream.write_all(&payload).await?;
        stream.flush().await
    })
    .await??;

    let mut echoed = vec![0u8; SIZE];
    tokio::time::timeout(STEP, stream.read_exact(&mut echoed)).await??;
    observed.record("bytes", SIZE);
    observed.record("digest", flow::hex(&flow::digest(&echoed)));
    ensure!(
        flow::digest(&echoed) == expected,
        "large write came back altered"
    );
    Ok(observed)
}

/// Four connections in flight at once, each with its own payload.
///
/// Engine instances are per connection, so this is where a plugin that keeps
/// state in a global shows up.
async fn concurrent(net: Net) -> Result<Observation> {
    const CONNECTIONS: usize = 4;
    let mut tasks = Vec::new();
    for index in 0..CONNECTIONS {
        let socks = net.socks;
        let origin = net.tcp_origin;
        tasks.push(tokio::spawn(async move {
            let payload = flow::pseudo_random(8 * 1024, 0x5eed + index as u64);
            let mut stream = socks.connect(origin).await?;
            tokio::time::timeout(STEP, flow::echo_roundtrip(&mut stream, &payload)).await??;
            Ok::<usize, anyhow::Error>(payload.len())
        }));
    }

    // Recorded in connection order, not completion order, so the observation
    // does not depend on scheduling.
    let mut observed = Observation::default();
    for (index, task) in tasks.into_iter().enumerate() {
        let echoed = task.await??;
        observed.record(format!("connection-{}", index), echoed);
    }
    Ok(observed)
}

/// Several megabytes in both directions at once, which is what drives an engine
/// through short writes, backpressure and output-buffer growth.
async fn bulk(net: Net) -> Result<Observation> {
    let size = bulk_bytes();
    let mut observed = Observation::default();
    let stream = net.socks.connect(net.tcp_origin).await?;
    let digest = flow::bulk_echo(stream, size, 0xE2E).await?;
    observed.record("bytes", size);
    observed.record("digest", flow::hex(&digest));
    Ok(observed)
}

/// The client half-closes with a megabyte of reply still in flight, and has to
/// receive all of it.
///
/// The end of a request travelling through the chain must not cut the reply
/// short. Everything between here and the origin learns that the client has
/// finished writing while the reply is still being carried back: leaf's
/// inbound, every engine in the chain, and leaf's outbound. A stage that
/// treats "the request ended" as "the connection ended" -- or a close that
/// resets instead of draining -- loses the tail, and loses it silently, since
/// the bytes that did arrive are perfectly good.
async fn half_close_tail(net: Net) -> Result<Observation> {
    /// Small enough to sit in the buffers along the path while nobody is
    /// reading it, so the whole reply is already delivered when the chain
    /// tears the connection down.
    const SIZE: usize = 64 * 1024;
    /// Long enough for the reply to arrive and the far end to finish.
    const PAUSE: Duration = Duration::from_millis(500);

    let mut observed = Observation::default();
    let payload = flow::pseudo_random(SIZE, 0x7a11);
    let mut stream = net.socks.connect(net.tcp_origin).await?;

    tokio::time::timeout(STEP, async {
        stream.write_all(&payload).await?;
        stream.flush().await?;
        // The request has ended. Everything in the chain learns it while the
        // reply is still on its way back.
        stream.shutdown().await
    })
    .await??;

    // Nobody reads for half a second, so the reply lands in a buffer and waits
    // there. A connection torn down with a reset rather than closed loses
    // exactly this, and loses it silently.
    tokio::time::sleep(PAUSE).await;

    let mut echoed = vec![0u8; SIZE];
    tokio::time::timeout(STEP, stream.read_exact(&mut echoed)).await??;
    observed.record("bytes", SIZE);
    observed.record("digest", flow::hex(&flow::digest(&echoed)));
    ensure!(echoed == payload, "the reply came back altered");
    Ok(observed)
}

/// The client stops writing; the far end has to notice, finish, and let the
/// close travel back.
///
/// Whether the read *terminates* is what is compared, not how. The plugin and
/// native paths reach that point differently: an engine reports the peer's
/// close through `close(NET)` and the host turns it into a clean end of
/// stream, while the native path lets the socket close carry it, which can
/// still arrive as a reset when leaf aborts a session of its own accord. All
/// of those are correct, and none is the bug this is looking for, which is a
/// close that never arrives at all.
async fn half_close(net: Net) -> Result<Observation> {
    let mut observed = Observation::default();
    let mut stream = net.socks.connect(net.tcp_origin).await?;

    // Both directions first: a close that propagates on a connection that never
    // worked would prove nothing.
    tokio::time::timeout(STEP, flow::echo_roundtrip(&mut stream, b"hello")).await??;
    observed.record("exchange", 5);

    stream.shutdown().await?;
    observed.record("shutdown", "sent");

    let mut tail = Vec::new();
    tokio::time::timeout(STEP, stream.read_to_end(&mut tail))
        .await
        .map_err(|_| anyhow::anyhow!("the connection stayed open after a half close"))?
        .ok();
    observed.record("tail-bytes", tail.len());
    observed.record("ended", "terminated");
    Ok(observed)
}

/// The far end ends the conversation. The close has to reach the client rather
/// than leave it waiting.
///
/// As with the half close, the manner is not compared: the native path ends
/// this in a reset and the plugin path in a clean end of stream, reproducibly
/// and for good reasons on both sides. What matters is that the client is told
/// at all.
async fn peer_closes_first(net: Net) -> Result<Observation> {
    const EXPECT: usize = 32;
    let mut observed = Observation::default();
    let mut stream = net.socks.connect(net.tcp_sink).await?;

    let payload = flow::pseudo_random(EXPECT, 0xc105e);
    tokio::time::timeout(STEP, async {
        stream.write_all(&payload).await?;
        stream.flush().await
    })
    .await??;
    observed.record("written", EXPECT);

    let mut tail = Vec::new();
    tokio::time::timeout(STEP, stream.read_to_end(&mut tail))
        .await
        .map_err(|_| anyhow::anyhow!("the peer closed but the client was never told"))?
        .ok();
    observed.record("tail-bytes", tail.len());
    observed.record("ended", "terminated");
    Ok(observed)
}

/// A destination named rather than numbered.
///
/// It travels through the proxy protocol as a domain and is resolved at the far
/// end, which is a different path through both the address conversion and the
/// protocol header than an address the client already resolved.
async fn domain_destination(net: Net) -> Result<Observation> {
    let mut observed = Observation::default();
    let target = Target::domain(TEST_DOMAIN, net.tcp_origin.port());
    let mut stream = net.socks.connect(target).await?;
    tokio::time::timeout(STEP, flow::echo_roundtrip(&mut stream, b"named")).await??;
    observed.record("exchange", 5);
    Ok(observed)
}

/// Connections one after another, each opened, used and closed.
///
/// Engine instances are per connection, so this is where state that outlives
/// one of them shows up.
async fn connection_churn(net: Net) -> Result<Observation> {
    const ROUNDS: usize = 12;
    let mut observed = Observation::default();
    for round in 0..ROUNDS {
        let payload = flow::pseudo_random(64, 0xc4u64 + round as u64);
        let mut stream = net.socks.connect(net.tcp_origin).await?;
        tokio::time::timeout(STEP, flow::echo_roundtrip(&mut stream, &payload)).await??;
    }
    observed.record("connections", ROUNDS);
    Ok(observed)
}

/// Datagrams of growing size, so a framing mistake shows up as a specific one
/// going missing rather than as everything failing.
async fn udp(net: Net) -> Result<Observation> {
    let mut observed = Observation::default();
    let session = net.socks.udp_associate().await?;
    for (index, size) in [1usize, 64, 1200].into_iter().enumerate() {
        let payload = flow::pseudo_random(size, 0xd06 + index as u64);
        session.send_to(&payload, net.udp_origin).await?;
        let mut buf = vec![0u8; 64 * 1024];
        let (n, source) = tokio::time::timeout(STEP, session.recv_from(&mut buf)).await??;
        ensure!(
            buf[..n] == payload[..],
            "datagram of {} bytes came back as {} bytes",
            size,
            n
        );
        ensure!(
            source == Target::Ip(net.udp_origin),
            "datagram came back from {:?}",
            source
        );
        observed.record(format!("datagram-{}", index), n);
    }
    Ok(observed)
}
