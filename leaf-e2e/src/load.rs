//! Sustained load, and what came back from it.
//!
//! The behaviours in `behaviours.rs` answer "does this work"; this answers
//! "does it keep working with sixty-four of them at once, for a quarter of a
//! minute, while connections come and go". The host's per-connection engine
//! instances, its two wakers, the mutex behind a datagram instance and its
//! buffer caps are all things that a single connection never presses on.
//!
//! Three properties keep a load generator from producing failures of its own:
//!
//! * **A failure says which step failed.** Every iteration is attributed to
//!   `connect`, `exchange`, `stall` or `mismatch`, counted by kind, and the
//!   first one keeps its full context. A wall of a thousand identical errors is
//!   not a diagnosis.
//! * **The descriptor limit is respected, not discovered.** A chain puts five
//!   or six descriptors behind every connection -- both leaf nodes run in this
//!   process -- and the default soft limit on a Mac is 256. Concurrency is
//!   derived from the limit after raising it, and a case that asked for more is
//!   told what it got.
//! * **A stall is reported where it stopped.** Every operation runs under a
//!   deadline of its own, well short of the case deadline, so a hang arrives as
//!   "stalled in exchange after 40 of 64 iterations" rather than as a child the
//!   runner had to kill.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::client::Socks5;
use crate::flow;
use crate::runner;

/// Scales concurrency and duration for every load that asks to be scaled.
/// A constrained runner sets it below 1, a soak run above.
pub const ENV_SCALE: &str = "LEAF_E2E_STRESS_SCALE";

/// How long one operation may take before it is called a stall. Multiplied by
/// the run's timeout scale, so a sanitized lane gets the same slack the runner
/// is already giving the case.
const STEP: Duration = Duration::from_secs(20);

/// How long a worker waits before reconnecting after a failed connect.
/// Deliberately long next to a connect that works, which is a millisecond or
/// two here: a load generator has no business hammering a listener that is
/// already refusing it.
const RETRY_BACKOFF: Duration = Duration::from_millis(100);

/// Descriptors a single proxied connection occupies in this process: the
/// client's socket, the client node's inbound and outbound, the server node's
/// inbound and outbound, and the origin's accepted socket. Rounded up, because
/// running out is a limit this harness hit rather than a defect it found.
const FDS_PER_CONNECTION: u64 = 8;

/// Descriptors left for everything that is not a connection: the listeners,
/// the log files, the plugin libraries.
const RESERVED_FDS: u64 = 96;

/// Above this, raising the soft limit starts to fail on macOS rather than
/// clamping, and no case here wants thousands of connections anyway.
const FD_CEILING: u64 = 10_240;

/// The most latency samples one run keeps. Percentiles from a hundred thousand
/// samples are not improved by a million, and a soak run should not spend
/// memory the case is there to watch.
const MAX_SAMPLES: usize = 100_000;

/// What one iteration of a load does on its connection.
#[derive(Clone, Copy, Debug)]
pub enum Payload {
    /// Writes `size` bytes and reads them back. One operation, one round trip.
    Echo { size: usize },
    /// Writes `depth` messages of `size` bytes back to back and then reads all
    /// of them back. `depth` operations without a round trip between them, so
    /// the per-call cost of the engine's state machine is what is left.
    Messages { size: usize, depth: usize },
    /// Pushes `size` bytes through the echo while reading concurrently, and
    /// compares digests. One operation; the connection is used once and
    /// closed.
    Bulk { size: usize },
    /// The same transfer without the generating and the hashing, over a
    /// payload shared by every worker.
    ///
    /// For the meters. Half a second of SHA-256 per four megabytes in a debug
    /// build is a fixed cost inside the timed region, and a fixed cost is
    /// worse than a slow one: it flattens the very ratio the meter exists to
    /// watch. What arrived is the differential behaviours' question.
    Transfer { size: usize },
}

impl Payload {
    /// Bytes moved in one direction by one iteration. Counted one way rather
    /// than both, so a rate here is comparable with the throughput meter.
    fn bytes(self) -> u64 {
        match self {
            Payload::Echo { size } => size as u64,
            Payload::Messages { size, depth } => (size * depth) as u64,
            Payload::Bulk { size } | Payload::Transfer { size } => size as u64,
        }
    }

    fn ops(self) -> u64 {
        match self {
            Payload::Echo { .. } | Payload::Bulk { .. } | Payload::Transfer { .. } => 1,
            Payload::Messages { depth, .. } => depth as u64,
        }
    }

    /// A bulk transfer takes the stream by value and ends with the connection
    /// having served its purpose, so it never reuses one.
    fn consumes_connection(self) -> bool {
        matches!(self, Payload::Bulk { .. } | Payload::Transfer { .. })
    }
}

/// A workload: how many connections, doing what, for how long.
#[derive(Clone, Copy, Debug)]
pub struct Load {
    payload: Payload,
    concurrency: usize,
    duration: Option<Duration>,
    iterations: usize,
    reconnect: bool,
}

impl Load {
    /// One connection, one iteration.
    pub fn new(payload: Payload) -> Self {
        Self {
            payload,
            concurrency: 1,
            duration: None,
            iterations: 1,
            reconnect: false,
        }
    }

    pub fn concurrency(mut self, connections: usize) -> Self {
        self.concurrency = connections.max(1);
        self
    }

    /// Repeats until this much time has passed, instead of a fixed count.
    pub fn for_duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    pub fn iterations(mut self, iterations: usize) -> Self {
        self.iterations = iterations.max(1);
        self
    }

    /// Opens a fresh connection for every iteration rather than holding one.
    pub fn reconnect_each_iteration(mut self) -> Self {
        self.reconnect = true;
        self
    }

    /// Applies [`ENV_SCALE`] to concurrency and duration.
    ///
    /// Opt-in, because it belongs to the stress lane: a meter that scaled with
    /// it would stop comparing like with like across machines.
    pub fn scaled(mut self) -> Self {
        let scale = scale();
        self.concurrency = ((self.concurrency as f64) * scale).round().max(1.0) as usize;
        self.duration = self
            .duration
            .map(|duration| duration.mul_f64(scale).max(Duration::from_secs(1)));
        self
    }

    /// Runs the load through `socks`, every connection aimed at `target`.
    ///
    /// Takes the plan by value so that a builder chain can be handed straight
    /// to `join!` without outliving a borrow of itself.
    pub async fn run(self, socks: Socks5, target: SocketAddr) -> Result<Outcome> {
        let (concurrency, note) = budgeted(self.concurrency);
        let started = Instant::now();
        let deadline = self.duration.map(|duration| started + duration);

        let mut tasks = Vec::with_capacity(concurrency);
        for index in 0..concurrency {
            let plan = self;
            tasks.push(tokio::spawn(async move {
                worker(socks, target, plan, index as u64, deadline).await
            }));
        }

        let mut outcome = Outcome::new(concurrency, note);
        for task in tasks {
            outcome.absorb(task.await.context("a load worker panicked")?);
        }
        outcome.elapsed = started.elapsed();
        Ok(outcome)
    }
}

/// Connections arriving at a fixed rate, each used once and closed.
///
/// Open loop on purpose: a closed loop slows down when the system does, which
/// is exactly the moment a connection storm stops being one. Arrivals that
/// cannot start because every permit is taken are deferred rather than
/// dropped, and counted, so that a system falling behind shows up as a note
/// instead of as an invented error.
#[derive(Clone, Copy, Debug)]
pub struct Churn {
    rate: f64,
    duration: Duration,
    payload: Payload,
}

impl Churn {
    pub fn new(rate: f64, duration: Duration) -> Self {
        Self {
            rate: rate.max(1.0),
            duration,
            payload: Payload::Echo { size: 64 },
        }
    }

    pub fn payload(mut self, payload: Payload) -> Self {
        self.payload = payload;
        self
    }

    /// Applies [`ENV_SCALE`] to the rate and the duration.
    pub fn scaled(mut self) -> Self {
        let scale = scale();
        self.rate = (self.rate * scale).max(1.0);
        self.duration = self.duration.mul_f64(scale).max(Duration::from_secs(1));
        self
    }

    /// Runs the storm through `socks`, every connection aimed at `target`.
    pub async fn run(self, socks: Socks5, target: SocketAddr) -> Result<Outcome> {
        let (in_flight_cap, note) = budgeted(self.rate.ceil() as usize);
        let permits = Arc::new(Semaphore::new(in_flight_cap));
        let mut deferred = 0usize;
        let interval = Duration::from_secs_f64(1.0 / self.rate);

        let started = Instant::now();
        let deadline = started + self.duration;
        let mut tasks = Vec::new();
        let mut index = 0u64;
        while Instant::now() < deadline {
            let due = started + interval.mul_f64(index as f64);
            if due > Instant::now() {
                tokio::time::sleep_until(due).await;
            }
            if permits.available_permits() == 0 {
                deferred += 1;
            }
            let permits = Arc::clone(&permits);
            let payload = self.payload;
            tasks.push(tokio::spawn(async move {
                let _permit = permits.acquire().await.expect("the semaphore stays open");
                let mut stats = Worker::default();
                stats.iteration(socks, target, payload, index).await;
                stats
            }));
            index += 1;
        }

        let mut outcome = Outcome::new(in_flight_cap, note);
        for task in tasks {
            outcome.absorb(task.await.context("a churn worker panicked")?);
        }
        outcome.elapsed = started.elapsed();
        if deferred > 0 {
            outcome.add_note(format!(
                "{} of {} arrivals waited for a free slot at {:.0} connections in flight",
                deferred, index, in_flight_cap
            ));
        }
        Ok(outcome)
    }
}

/// What a load did.
pub struct Outcome {
    /// Connections actually run at once, after the descriptor budget.
    pub concurrency: usize,
    pub attempted: usize,
    pub completed: usize,
    pub ops: u64,
    /// Payload bytes, counted in one direction.
    pub bytes: u64,
    pub elapsed: Duration,
    pub errors: Errors,
    pub latency: Histogram,
    /// Anything about the run that is not a failure but changes what the
    /// numbers mean: a clamped concurrency, a deferred arrival.
    pub notes: Vec<String>,
}

impl Outcome {
    fn new(concurrency: usize, note: Option<String>) -> Self {
        Self {
            concurrency,
            attempted: 0,
            completed: 0,
            ops: 0,
            bytes: 0,
            elapsed: Duration::ZERO,
            errors: Errors::default(),
            latency: Histogram::default(),
            notes: note.into_iter().collect(),
        }
    }

    fn absorb(&mut self, worker: Worker) {
        self.attempted += worker.attempted;
        self.completed += worker.completed;
        self.ops += worker.ops;
        self.bytes += worker.bytes;
        self.errors.merge(worker.errors);
        self.latency.merge(worker.latency);
    }

    fn add_note(&mut self, note: String) {
        self.notes.push(note);
    }

    pub fn completion_ratio(&self) -> f64 {
        if self.attempted == 0 {
            return 0.0;
        }
        self.completed as f64 / self.attempted as f64
    }

    pub fn throughput_mib(&self) -> f64 {
        let seconds = self.elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
        self.bytes as f64 / seconds / (1024.0 * 1024.0)
    }

    pub fn ops_per_second(&self) -> f64 {
        let seconds = self.elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
        self.ops as f64 / seconds
    }

    /// Fails unless every iteration completed.
    ///
    /// This is what a stress case asserts. Not a rate, not a duration: those
    /// belong to the meters, where they are compared against native rather
    /// than against a number someone chose.
    pub fn require_clean(&self) -> Result<()> {
        self.require_completion(1.0)
    }

    /// Fails unless at least `floor` of the iterations completed.
    ///
    /// For loads that open a connection per iteration. Hundreds of arrivals a
    /// second through two leaf nodes will occasionally meet a listener backlog
    /// that is momentarily full, or an ephemeral port the machine has just
    /// handed back. That says nothing about either implementation and is not
    /// worth a flaky suite. A load that holds its connections open is exposed
    /// to none of it and asserts [`require_clean`](Self::require_clean)
    /// instead.
    pub fn require_completion(&self, floor: f64) -> Result<()> {
        if self.attempted > 0 && self.completion_ratio() >= floor && self.completed > 0 {
            return Ok(());
        }
        bail!(
            "{} of {} iterations failed across {} connections ({:.1}% completed, floor is \
             {:.1}%): {}",
            self.attempted - self.completed,
            self.attempted,
            self.concurrency,
            self.completion_ratio() * 100.0,
            floor * 100.0,
            self.errors
        );
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} connections, {}/{} iterations, {} ops, {:.1} MiB in {:.1}s \
             ({:.1} MiB/s, {:.0} ops/s)",
            self.concurrency,
            self.completed,
            self.attempted,
            self.ops,
            self.bytes as f64 / (1024.0 * 1024.0),
            self.elapsed.as_secs_f64(),
            self.throughput_mib(),
            self.ops_per_second(),
        )?;
        if let Some(p50) = self.latency.percentile(0.50) {
            write!(
                f,
                ", p50 {:.2}ms p99 {:.2}ms max {:.2}ms",
                p50.as_secs_f64() * 1000.0,
                self.latency
                    .percentile(0.99)
                    .unwrap_or_default()
                    .as_secs_f64()
                    * 1000.0,
                self.latency.max().unwrap_or_default().as_secs_f64() * 1000.0,
            )?;
        }
        for note in &self.notes {
            write!(f, "; {}", note)?;
        }
        Ok(())
    }
}

/// Failures, counted by kind, with the first one's full context kept.
#[derive(Default)]
pub struct Errors {
    counts: BTreeMap<&'static str, usize>,
    first: Option<String>,
}

impl Errors {
    fn record(&mut self, kind: &'static str, detail: String) {
        *self.counts.entry(kind).or_default() += 1;
        if self.first.is_none() {
            self.first = Some(detail);
        }
    }

    fn merge(&mut self, other: Errors) {
        for (kind, count) in other.counts {
            *self.counts.entry(kind).or_default() += count;
        }
        if self.first.is_none() {
            self.first = other.first;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    pub fn total(&self) -> usize {
        self.counts.values().sum()
    }
}

impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.counts.is_empty() {
            return write!(f, "no failures");
        }
        let kinds: Vec<String> = self
            .counts
            .iter()
            .map(|(kind, count)| format!("{} x{}", kind, count))
            .collect();
        write!(f, "{}", kinds.join(", "))?;
        if let Some(first) = &self.first {
            write!(f, " -- first: {}", first)?;
        }
        Ok(())
    }
}

/// Latencies, kept as samples so that a percentile is exact rather than
/// bucketed.
#[derive(Default)]
pub struct Histogram {
    samples: Vec<Duration>,
    dropped: usize,
}

impl Histogram {
    /// Adds one sample. Public because a meter builds its own histogram out of
    /// exchanges it timed itself.
    pub fn record(&mut self, sample: Duration) {
        if self.samples.len() < MAX_SAMPLES {
            self.samples.push(sample);
        } else {
            self.dropped += 1;
        }
    }

    fn merge(&mut self, other: Histogram) {
        for sample in other.samples {
            self.record(sample);
        }
        self.dropped += other.dropped;
    }

    pub fn len(&self) -> usize {
        self.samples.len() + self.dropped
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The sample at `fraction` of the way through the sorted samples.
    pub fn percentile(&self, fraction: f64) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let index = ((sorted.len() as f64 - 1.0) * fraction.clamp(0.0, 1.0)).round() as usize;
        Some(sorted[index])
    }

    pub fn max(&self) -> Option<Duration> {
        self.samples.iter().copied().max()
    }
}

/// One connection's worth of work.
#[derive(Default)]
struct Worker {
    attempted: usize,
    completed: usize,
    ops: u64,
    bytes: u64,
    errors: Errors,
    latency: Histogram,
}

impl Worker {
    /// Connects, runs the payload once, and records what happened.
    async fn iteration(&mut self, socks: Socks5, target: SocketAddr, payload: Payload, seed: u64) {
        self.attempted += 1;
        let started = Instant::now();
        let stream = match connect(socks, target).await {
            Ok(stream) => stream,
            Err(failure) => {
                self.errors.record(failure.kind, failure.detail);
                return;
            }
        };
        match exchange(stream, payload, seed).await {
            Ok(_) => {
                self.completed += 1;
                self.ops += payload.ops();
                self.bytes += payload.bytes();
                self.latency.record(started.elapsed());
            }
            Err(failure) => self.errors.record(failure.kind, failure.detail),
        }
    }
}

/// A failure, attributed to the step that produced it.
struct Failure {
    kind: &'static str,
    detail: String,
}

impl Failure {
    fn new(kind: &'static str, detail: impl fmt::Display) -> Self {
        Self {
            kind,
            detail: detail.to_string(),
        }
    }
}

async fn worker(
    socks: Socks5,
    target: SocketAddr,
    plan: Load,
    seed: u64,
    deadline: Option<Instant>,
) -> Worker {
    let mut stats = Worker::default();
    let mut held: Option<TcpStream> = None;
    let mut iteration = 0usize;

    loop {
        match deadline {
            Some(deadline) if Instant::now() >= deadline => break,
            None if iteration >= plan.iterations => break,
            _ => {}
        }
        iteration += 1;
        stats.attempted += 1;
        let started = Instant::now();

        let reuse = held.take();
        let stream = match reuse {
            Some(stream) if !plan.reconnect && !plan.payload.consumes_connection() => stream,
            other => {
                drop(other);
                match connect(socks, target).await {
                    Ok(stream) => stream,
                    Err(failure) => {
                        stats.errors.record(failure.kind, failure.detail);
                        // Backing off rather than retrying immediately. A
                        // worker that reconnects in a tight loop is a
                        // connection storm of its own making: it overruns the
                        // listener's backlog and exhausts ephemeral ports,
                        // and every case then fails with the harness's
                        // symptoms rather than the host's.
                        tokio::time::sleep(retry_backoff()).await;
                        continue;
                    }
                }
            }
        };

        match exchange(stream, plan.payload, seed * 1_000_003 + iteration as u64).await {
            Ok(stream) => {
                stats.completed += 1;
                stats.ops += plan.payload.ops();
                stats.bytes += plan.payload.bytes();
                stats.latency.record(started.elapsed());
                held = stream;
            }
            Err(failure) => {
                stats.errors.record(failure.kind, failure.detail);
            }
        }
    }
    stats
}

async fn connect(socks: Socks5, target: SocketAddr) -> Result<TcpStream, Failure> {
    match tokio::time::timeout(step(), socks.connect(target)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(err)) => Err(Failure::new("connect", format!("{:#}", err))),
        Err(_) => Err(Failure::new(
            "stall",
            format!("no socks reply within {:?}", step()),
        )),
    }
}

/// Runs one iteration, handing the connection back when it survived and can be
/// used again.
async fn exchange(
    mut stream: TcpStream,
    payload: Payload,
    seed: u64,
) -> Result<Option<TcpStream>, Failure> {
    match payload {
        Payload::Echo { size } => {
            let bytes = flow::pseudo_random(size, seed);
            deadline(flow::echo_roundtrip(&mut stream, &bytes)).await?;
            Ok(Some(stream))
        }
        Payload::Messages { size, depth } => {
            let message = flow::pseudo_random(size, seed);
            deadline(async {
                for _ in 0..depth {
                    stream.write_all(&message).await?;
                }
                stream.flush().await?;
                let mut echoed = vec![0u8; size * depth];
                stream.read_exact(&mut echoed).await?;
                for (index, chunk) in echoed.chunks(size).enumerate() {
                    if chunk != message {
                        bail!("message {} of {} came back altered", index, depth);
                    }
                }
                Ok::<(), anyhow::Error>(())
            })
            .await?;
            Ok(Some(stream))
        }
        Payload::Bulk { size } => {
            // `bulk_echo` carries its own stall deadline and reports where a
            // transfer stopped, which is more than a timeout here could say.
            flow::bulk_echo(stream, size, seed)
                .await
                .map_err(|err| Failure::new("exchange", format!("{:#}", err)))?;
            Ok(None)
        }
        Payload::Transfer { size } => {
            let payload = flow::shared_payload(size);
            flow::bulk_transfer(stream, &payload)
                .await
                .map_err(|err| Failure::new("exchange", format!("{:#}", err)))?;
            Ok(None)
        }
    }
}

/// Runs one operation under the step deadline, attributing a timeout to
/// `stall` and anything else to `exchange`.
async fn deadline<F>(operation: F) -> Result<(), Failure>
where
    F: std::future::Future<Output = Result<()>>,
{
    match tokio::time::timeout(step(), operation).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => {
            let detail = format!("{:#}", err);
            // An echo that came back different is a correctness failure and
            // deserves its own counter; everything else is I/O.
            let kind = if detail.contains("mismatch") || detail.contains("altered") {
                "mismatch"
            } else {
                "exchange"
            };
            Err(Failure::new(kind, detail))
        }
        Err(_) => Err(Failure::new(
            "stall",
            format!("nothing completed within {:?}", step()),
        )),
    }
}

fn step() -> Duration {
    STEP.mul_f64(runner::timeout_scale())
}

/// How long a worker waits after a failed connect before trying again.
fn retry_backoff() -> Duration {
    RETRY_BACKOFF.mul_f64(runner::timeout_scale())
}

pub fn scale() -> f64 {
    std::env::var(ENV_SCALE)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|scale| scale.is_finite() && *scale > 0.0)
        .unwrap_or(1.0)
}

/// The concurrency a load actually gets, and why, when the descriptor limit
/// does not allow what it asked for.
fn budgeted(wanted: usize) -> (usize, Option<String>) {
    let allowed = max_concurrency();
    if wanted <= allowed {
        return (wanted, None);
    }
    (
        allowed,
        Some(format!(
            "concurrency clamped from {} to {}: {} descriptors available, {} per connection",
            wanted,
            allowed,
            file_limit(),
            FDS_PER_CONNECTION
        )),
    )
}

/// The most connections this process can hold open at once.
pub fn max_concurrency() -> usize {
    let limit = file_limit().saturating_sub(RESERVED_FDS);
    ((limit / FDS_PER_CONNECTION).max(1) as usize).min(4096)
}

/// The soft descriptor limit, raised towards the hard one the first time it is
/// asked for.
///
/// Raising it here rather than telling the operator to is deliberate: a suite
/// that fails on a developer's laptop because of `ulimit -n 256` teaches people
/// that the stress lane is unreliable, which is the opposite of the point.
pub fn file_limit() -> u64 {
    static LIMIT: OnceLock<u64> = OnceLock::new();
    *LIMIT.get_or_init(raise_file_limit)
}

#[cfg(unix)]
fn raise_file_limit() -> u64 {
    // Safety: `getrlimit` and `setrlimit` fill and read a `rlimit` this
    // function owns, and both are checked for failure.
    unsafe {
        let mut limit = std::mem::zeroed::<libc::rlimit>();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return 256;
        }
        let hard = if limit.rlim_max == libc::RLIM_INFINITY {
            FD_CEILING
        } else {
            (limit.rlim_max as u64).min(FD_CEILING)
        };
        if (limit.rlim_cur as u64) < hard {
            let raised = libc::rlimit {
                rlim_cur: hard as libc::rlim_t,
                rlim_max: limit.rlim_max,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &raised) == 0 {
                return hard;
            }
        }
        limit.rlim_cur as u64
    }
}

#[cfg(not(unix))]
fn raise_file_limit() -> u64 {
    // No equivalent knob, and no case in this suite runs there yet.
    FD_CEILING
}
