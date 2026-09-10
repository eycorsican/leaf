//! Traffic patterns a scenario runs over whatever topology it built.
//!
//! Keeping them separate from the topology is what makes an implementation
//! matrix possible: the same behaviour runs over a native chain and over a
//! plugin chain, and the two are expected to agree.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{bail, Result};
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Writes `payload` and expects exactly it back.
pub async fn echo_roundtrip(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    stream.write_all(payload).await?;
    stream.flush().await?;
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await?;
    if echoed != payload {
        bail!(
            "echo mismatch: sent {} bytes, got {} different bytes",
            payload.len(),
            echoed.iter().zip(payload).filter(|(a, b)| a != b).count()
        );
    }
    Ok(())
}

/// Pushes `size` bytes through an echo server while reading the reply
/// concurrently, and compares digests.
///
/// Concurrency is the point: a sequential write of more than a window's worth
/// would deadlock, and it is the interleaving that drives an engine through
/// partial writes, backpressure and output-buffer growth.
///
/// The client does not half-close after writing, and closes on its own terms
/// once it has read everything back. Teardown is its own question -- one the
/// `half-close` behaviours and the `teardown/` cases ask directly -- and a
/// transfer that answered it by accident would be measuring two things at
/// once.
pub async fn bulk_echo(stream: TcpStream, size: usize, seed: u64) -> Result<[u8; 32]> {
    let payload = pseudo_random(size, seed);
    let expected = digest(&payload);
    // `into_split`, not `tokio::io::split`: the latter puts both halves behind
    // one lock whose contended path spins with `yield_now` and an immediate
    // re-wake. With a reader and a writer both saturated that spin starves the
    // executor, and several concurrent transfers stall outright.
    let (mut reader, mut writer) = stream.into_split();

    // Progress, so that a stall is reported as "stopped here" rather than as a
    // deadline the runner had to kill.
    let sent = Arc::new(AtomicUsize::new(0));
    let sender_progress = Arc::clone(&sent);
    let sender = tokio::spawn(async move {
        for chunk in payload.chunks(CHUNK) {
            writer.write_all(chunk).await?;
            sender_progress.fetch_add(chunk.len(), Ordering::Relaxed);
        }
        writer.flush().await?;
        // An owned write half shuts the socket's write side down when it is
        // dropped, which would half-close the connection. Hand it over instead:
        // teardown belongs to the cases that are about teardown.
        writer.forget();
        Ok::<(), std::io::Error>(())
    });

    let mut hasher = Sha256::new();
    let mut received = 0usize;
    let mut buf = vec![0u8; CHUNK];
    while received < size {
        let read = tokio::time::timeout(STALL, reader.read(&mut buf))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "transfer stalled: nothing arrived for {:?} after receiving {} of {} bytes \
                     (the sender had written {})",
                    STALL,
                    received,
                    size,
                    sent.load(Ordering::Relaxed)
                )
            })?;
        let n = read.map_err(|err| {
            anyhow::anyhow!("read failed after {} of {} bytes: {}", received, size, err)
        })?;
        if n == 0 {
            bail!("echo closed after {} of {} bytes", received, size);
        }
        hasher.update(&buf[..n]);
        received += n;
    }
    sender
        .await?
        .map_err(|err| anyhow::anyhow!("write of {} bytes failed: {}", size, err))?;

    let actual: [u8; 32] = hasher.finalize().into();
    if actual != expected {
        bail!("echoed {} bytes but the digest differs", size);
    }
    Ok(actual)
}

/// Pushes `payload` through an echo and reads the same number of bytes back,
/// without generating or verifying anything.
///
/// For the meters. A generated payload and two passes of SHA-256 cost about
/// half a second per four megabytes in a debug build, which is most of what a
/// timed transfer over loopback would otherwise be measuring -- and a fixed
/// cost in the timed region is worse than slow, because it flattens the ratio
/// the meter exists to watch. Integrity is the differential behaviours' job,
/// and they check every byte.
pub async fn bulk_transfer(stream: TcpStream, payload: &[u8]) -> Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let size = payload.len();
    let owned = payload.to_vec();

    let sent = Arc::new(AtomicUsize::new(0));
    let sender_progress = Arc::clone(&sent);
    let sender = tokio::spawn(async move {
        for chunk in owned.chunks(CHUNK) {
            writer.write_all(chunk).await?;
            sender_progress.fetch_add(chunk.len(), Ordering::Relaxed);
        }
        writer.flush().await?;
        writer.forget();
        Ok::<(), std::io::Error>(())
    });

    let mut received = 0usize;
    let mut buf = vec![0u8; CHUNK];
    while received < size {
        let read = tokio::time::timeout(STALL, reader.read(&mut buf))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "transfer stalled: nothing arrived for {:?} after receiving {} of {} bytes \
                     (the sender had written {})",
                    STALL,
                    received,
                    size,
                    sent.load(Ordering::Relaxed)
                )
            })?;
        let n = read.map_err(|err| {
            anyhow::anyhow!("read failed after {} of {} bytes: {}", received, size, err)
        })?;
        if n == 0 {
            bail!("echo closed after {} of {} bytes", received, size);
        }
        received += n;
    }
    sender
        .await?
        .map_err(|err| anyhow::anyhow!("write of {} bytes failed: {}", size, err))?;
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

/// The unit both halves of a bulk transfer work in.
const CHUNK: usize = 64 * 1024;

/// How long a bulk transfer may go without a single byte arriving before the
/// harness calls it stalled. Generous next to any real scheduling hiccup, and
/// far short of the case deadline, so a stall is reported with its position
/// rather than killed.
const STALL: Duration = Duration::from_secs(20);

/// A payload of `size` bytes, generated once per process and shared.
///
/// Generating four megabytes costs about two hundred milliseconds in a debug
/// build, which is an order of magnitude more than moving them over loopback.
/// A meter must not pay that inside its timed region, and a load that
/// reconnects a hundred times must not pay it a hundred times.
pub fn shared_payload(size: usize) -> Arc<Vec<u8>> {
    static CACHE: OnceLock<Mutex<HashMap<usize, Arc<Vec<u8>>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().expect("the payload cache is never poisoned");
    Arc::clone(
        cache
            .entry(size)
            .or_insert_with(|| Arc::new(pseudo_random(size, SHARED_SEED))),
    )
}

/// One seed for every shared payload: the bytes only have to be unlike each
/// other, and nothing compares two payloads of different sizes.
const SHARED_SEED: u64 = 0x5_1a2e;

pub fn pseudo_random(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
}

pub fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
