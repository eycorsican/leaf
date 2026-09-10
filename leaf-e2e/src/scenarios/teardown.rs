//! What happens to bytes that have arrived but have not been read yet.
//!
//! A proxy ends sessions the client did not end: an idle timeout fires, a
//! relay errors, the process shuts down. How it ends them is not a detail. A
//! connection closed gracefully leaves whatever it already delivered in the
//! peer's hands; a connection reset takes it back -- and takes it back
//! silently, because every byte that did arrive is perfectly good and the
//! application simply never sees the rest.
//!
//! leaf gave every accepted inbound socket `SO_LINGER = 0` until that became
//! `TCP_INBOUND_ABORT_ON_CLOSE`, which is off by default. These cases hold the
//! shape that decision is about: the origin speaks first and closes, leaf ends
//! the idle session itself, and the client is still behind. What they cannot
//! do is fail when the option is turned back on -- whether a reset costs the
//! client anything depends on how much is queued in leaf at that instant,
//! which depends on the kernel's buffer sizes rather than on anything a case
//! can arrange portably. Measured at the socket level on one machine, a reset
//! with a full send queue cost the reader a hundred kilobytes; through this
//! harness on loopback it usually costs nothing.
//!
//! So take these for what they are: cover for the ordinary case, not a proof
//! about the option.

use std::time::Duration;

use anyhow::{ensure, Result};
use tokio::io::AsyncReadExt;

use crate::scenario::{boxed, Scenario, Tag};
use crate::scenarios::differential as matrix;
use crate::servers::{self, Origin};

/// How much the origin sends before closing. Enough that a reader taking it in
/// at a deliberate pace is still behind when leaf gives up on the session.
const GREETING: usize = 768 * 1024;

/// How the client reads: a chunk at a time, with a pause between them.
///
/// Slowly is what matters, not how slowly. A reader that keeps up leaves
/// nothing in leaf's hands, and then the manner of the close decides nothing;
/// a reader that is behind is the ordinary case -- a phone on a slow link, an
/// application busy with the last chunk -- and the one where a reset takes
/// back bytes that were already delivered.
const CHUNK: usize = 8 * 1024;
const PACE: Duration = Duration::from_millis(25);

/// What the case sets leaf's idle timeouts to. The default is ten seconds,
/// which is the right default and the wrong test: this case is here to watch
/// the teardown, not to wait for it.
const IDLE_SECONDS: u64 = 1;

pub fn scenarios() -> Vec<Scenario> {
    let mut scenarios = Vec::new();
    for candidate in matrix::candidates() {
        // The question is about leaf's own inbound, which is the same
        // underneath every candidate; the plugin one is here because the
        // engine has to have flushed what it decoded before the stream is
        // dropped, and that is not the same code path as the native one.
        if !matches!(candidate.name, "shadowsocks") {
            continue;
        }
        for stage in ["native", "plugin"] {
            let group = if stage == "native" {
                candidate.group.native()
            } else {
                candidate.group
            };
            let fixtures = if stage == "native" {
                Vec::new()
            } else {
                candidate.group.fixtures()
            };
            let mut tags = vec![Tag::Differential];
            if stage == "native" {
                tags.push(Tag::Native);
            } else {
                tags.push(Tag::Plugin);
                tags.extend(matrix::toolchain_tags(&fixtures));
            }
            scenarios.push(
                Scenario::new(
                    format!("teardown/idle-timeout/{}", stage),
                    "teardown",
                    move || boxed(tail_survives_an_idle_teardown(group)),
                )
                .tags(tags)
                .needs(fixtures)
                .env("TCP_UPLINK_TIMEOUT", IDLE_SECONDS.to_string())
                .env("TCP_DOWNLINK_TIMEOUT", IDLE_SECONDS.to_string())
                .timeout(Duration::from_secs(45)),
            );
        }
    }
    scenarios
}

/// The origin greets and closes; the client reads it slowly enough to still be
/// behind when leaf's idle timeout ends the session. Every byte still has to
/// arrive.
///
/// This is the sequence a reset destroys, and close to the only one that
/// reaches it. leaf has to be the side that closes first, which happens when
/// its own idle timeout fires rather than when either end says it is
/// finished -- a client that closes or half-closes first makes leaf the
/// passive closer, and then there is nothing queued for a reset to discard.
/// And the client has to be behind, because bytes that have already been read
/// cannot be taken back.
async fn tail_survives_an_idle_teardown(group: matrix::Group) -> Result<()> {
    let greeting = Origin::tcp_greeting(GREETING).await?;
    let deployment = group.deploy().await?;
    let net = deployment.net();

    // The destination is named by the client, so this needs nothing of the
    // topology beyond a way through it.
    let mut stream = net.socks.connect(greeting.addr()).await?;

    let mut received = Vec::with_capacity(GREETING);
    let mut buf = vec![0u8; CHUNK];
    let outcome = loop {
        match stream.read(&mut buf).await {
            Ok(0) => break Ok(()),
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(err) => break Err(err),
        }
        if received.len() >= GREETING {
            break Ok(());
        }
        tokio::time::sleep(PACE).await;
    };

    let expected = servers::greeting(GREETING);
    ensure!(
        received.len() == expected.len(),
        "read {} of {} bytes: the session ended {}",
        received.len(),
        expected.len(),
        match outcome {
            Ok(()) => "with the stream closed".to_string(),
            Err(err) => format!("with: {}", err),
        }
    );
    ensure!(received == expected, "the reply came back altered");

    deployment.shutdown().await
}
