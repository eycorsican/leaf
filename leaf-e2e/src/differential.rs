//! Comparing a plugin against the implementation it stands in for.
//!
//! A plugin is only correct if it is indistinguishable from the native
//! implementation of the same protocol. Asserting that directly is stronger
//! than any hand-written expectation, and it costs nothing to maintain: a
//! behaviour is written once and run against both.
//!
//! It also tells the two kinds of failure apart. When the native run fails, the
//! harness or leaf is at fault and the case says so before it ever looks at the
//! plugin.

use std::fmt::Display;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{bail, Context, Result};

use crate::client::Socks5;
use crate::node::LeafNode;
use crate::servers::Origin;

/// What a behaviour observed, in the order it observed it.
///
/// Facts are normalised on purpose: no timings, no ports, no addresses that
/// differ between two runs of the same thing. Anything left here is something
/// the two implementations genuinely have to agree on.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Observation {
    facts: Vec<(String, String)>,
}

impl Observation {
    pub fn record(&mut self, name: impl Into<String>, value: impl Display) {
        self.facts.push((name.into(), value.to_string()));
    }

    /// Describes the first disagreement, or `None` when the two agree.
    fn disagreement(&self, other: &Observation) -> Option<String> {
        for (index, expected) in self.facts.iter().enumerate() {
            match other.facts.get(index) {
                Some(actual) if actual == expected => continue,
                Some((name, value)) => {
                    return Some(format!(
                    "fact {} differs: native recorded [{}] = [{}], the plugin recorded [{}] = [{}]",
                    index, expected.0, expected.1, name, value
                ))
                }
                None => {
                    return Some(format!(
                        "the plugin stopped after {} facts; native also recorded [{}] = [{}]",
                        index, expected.0, expected.1
                    ))
                }
            }
        }
        if other.facts.len() > self.facts.len() {
            let (name, value) = &other.facts[self.facts.len()];
            return Some(format!(
                "the plugin recorded an extra fact [{}] = [{}]",
                name, value
            ));
        }
        None
    }
}

/// The entry points a behaviour drives. Deliberately small and `Copy`: a
/// behaviour must not be able to reach into the topology it is running over.
#[derive(Clone, Copy)]
pub struct Net {
    pub socks: Socks5,
    pub tcp_origin: SocketAddr,
    /// Reads a fixed amount and then closes, for the cases about a peer that
    /// ends the conversation first.
    pub tcp_sink: SocketAddr,
    /// Sends without reading, for measuring one direction on its own.
    pub tcp_source: SocketAddr,
    /// Reads without sending, the other half of the same idea.
    pub tcp_discard: SocketAddr,
    pub udp_origin: SocketAddr,
}

/// Everything a topology started, kept alive for the duration of a run.
pub struct Deployment {
    net: Net,
    nodes: Vec<LeafNode>,
    // Dropped with the deployment, which stops the listeners.
    _origins: Vec<Origin>,
}

impl Deployment {
    pub fn new(net: Net, nodes: Vec<LeafNode>, origins: Vec<Origin>) -> Self {
        Self {
            net,
            nodes,
            _origins: origins,
        }
    }

    pub fn net(&self) -> Net {
        self.net
    }

    /// Stops every node and waits for it. Waiting is the point: a node that
    /// will not stop is a defect, most plausibly in a plugin that embeds its
    /// own runtime.
    pub async fn shutdown(self) -> Result<()> {
        for node in self.nodes {
            node.shutdown().await?;
        }
        Ok(())
    }
}

pub type DeploymentFuture = Pin<Box<dyn Future<Output = Result<Deployment>> + Send>>;
pub type Topology = Arc<dyn Fn() -> DeploymentFuture + Send + Sync>;

pub type ObservationFuture = Pin<Box<dyn Future<Output = Result<Observation>> + Send>>;

#[derive(Clone, Copy)]
pub struct Behaviour {
    pub name: &'static str,
    pub run: fn(Net) -> ObservationFuture,
}

/// Runs `behaviour` over the native topology, then over the plugin one, and
/// requires the two to have observed the same thing.
///
/// The topologies run one after the other rather than side by side: they would
/// otherwise compete for the machine, and a bulk transfer that is merely slower
/// under contention is not a difference worth reporting.
pub async fn compare(oracle: &Topology, candidate: &Topology, behaviour: Behaviour) -> Result<()> {
    let native = {
        let deployment = oracle().await.context("starting the native topology")?;
        let observed = (behaviour.run)(deployment.net()).await.context(
            "the native topology failed this behaviour, so it says nothing about the plugin",
        )?;
        deployment.shutdown().await?;
        observed
    };

    let plugged = {
        let deployment = candidate().await.context("starting the plugin topology")?;
        let observed = (behaviour.run)(deployment.net())
            .await
            .context("the plugin topology failed this behaviour")?;
        deployment.shutdown().await?;
        observed
    };

    if let Some(disagreement) = native.disagreement(&plugged) {
        bail!("behaviour [{}]: {}", behaviour.name, disagreement);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cost
// ---------------------------------------------------------------------------

/// One number a meter produced, with the unit it is in.
pub struct Measurement {
    pub name: &'static str,
    pub value: f64,
    pub unit: &'static str,
}

pub type MeasurementFuture = Pin<Box<dyn Future<Output = Result<Measurement>> + Send>>;

/// What the plugin path is allowed to cost relative to the native one.
#[derive(Clone, Copy)]
pub enum Budget {
    /// The candidate must reach at least this fraction of the oracle.
    AtLeast(f64),
    /// The candidate may take at most this multiple of the oracle.
    AtMost(f64),
}

#[derive(Clone, Copy)]
pub struct Meter {
    pub name: &'static str,
    pub run: fn(Net) -> MeasurementFuture,
    pub budget: Budget,
}

/// How many times each side is measured, unless [`ENV_METER_REPS`] says
/// otherwise. The best result is kept: scheduling noise only ever makes a run
/// worse, so the best one is the closest thing to the cost itself.
const DEFAULT_REPETITIONS: usize = 3;

/// How many measurements each side takes. A noisy machine can buy a steadier
/// ratio with more of them; nothing else in the suite changes.
pub const ENV_METER_REPS: &str = "LEAF_E2E_METER_REPS";

fn repetitions() -> usize {
    std::env::var(ENV_METER_REPS)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|reps| *reps > 0)
        .unwrap_or(DEFAULT_REPETITIONS)
}

/// Every measurement one side produced.
struct Series {
    unit: &'static str,
    best: f64,
    median: f64,
    samples: Vec<f64>,
}

impl Series {
    fn new(unit: &'static str, samples: Vec<f64>, budget: Budget) -> Self {
        let mut sorted = samples.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).expect("a measurement is never NaN"));
        let best = match budget {
            Budget::AtLeast(_) => sorted.last().copied(),
            Budget::AtMost(_) => sorted.first().copied(),
        }
        .unwrap_or(f64::NAN);
        let median = sorted[sorted.len() / 2];
        Self {
            unit,
            best,
            median,
            samples,
        }
    }

    fn as_json(&self) -> serde_json::Value {
        serde_json::json!({
            "best": self.best,
            "median": self.median,
            "samples": self.samples,
        })
    }
}

/// Measures the native topology and the plugin one, and requires the plugin to
/// stay within its budget.
///
/// Ratios rather than absolute numbers, because the absolute ones say more
/// about the machine than about the code. The budgets are deliberately loose:
/// this is a guard against a regression of the kind that turns a copy into a
/// byte-at-a-time loop, not a benchmark.
///
/// Both sides are also written to `meters.json` in the case's artifact
/// directory. The ratio is what fails a build; the absolute numbers are what
/// tells anyone looking whether both sides halved while the ratio held.
pub async fn compare_cost(oracle: &Topology, candidate: &Topology, meter: Meter) -> Result<()> {
    let native = measure(oracle, meter)
        .await
        .context("measuring the native topology")?;
    let plugged = measure(candidate, meter)
        .await
        .context("measuring the plugin topology")?;

    let ratio = plugged.best / native.best;
    let (within, described) = match meter.budget {
        Budget::AtLeast(fraction) => (
            ratio >= fraction,
            format!(
                "{:.1}% of native, floor is {:.0}%",
                ratio * 100.0,
                fraction * 100.0
            ),
        ),
        Budget::AtMost(multiple) => (
            ratio <= multiple,
            format!("{:.2}x native, ceiling is {:.0}x", ratio, multiple),
        ),
    };

    let (budget_kind, budget_value) = match meter.budget {
        Budget::AtLeast(fraction) => ("at-least", fraction),
        Budget::AtMost(multiple) => ("at-most", multiple),
    };
    crate::report::append(
        "meters.json",
        serde_json::json!({
            "case": crate::report::case(),
            "meter": meter.name,
            "unit": native.unit,
            "repetitions": repetitions(),
            "native": native.as_json(),
            "plugin": plugged.as_json(),
            "ratio": ratio,
            "budget": { "kind": budget_kind, "value": budget_value },
            "within_budget": within,
        }),
    );
    // Also in the case log, where someone reading a failure is already looking.
    eprintln!(
        "leaf-e2e: {}: native {:.1} {} (median {:.1}), plugin {:.1} {} (median {:.1}) -- {}",
        meter.name,
        native.best,
        native.unit,
        native.median,
        plugged.best,
        plugged.unit,
        plugged.median,
        described
    );

    if !within {
        bail!(
            "{}: native {:.1} {}, plugin {:.1} {} -- {}",
            meter.name,
            native.best,
            native.unit,
            plugged.best,
            plugged.unit,
            described
        );
    }
    Ok(())
}

/// Deploys the topology once and measures it, after a warm-up run that is
/// thrown away.
///
/// The warm-up is not ceremony: the first transfer through a fresh deployment
/// pays for connection setup in both leaf nodes, the plugin's first allocation
/// of whatever it allocates lazily, and on a Go plugin the runtime's first
/// growth of its heap. Keeping it would put the plugin's startup into a
/// steady-state number, and the two sides do not start up alike.
async fn measure(topology: &Topology, meter: Meter) -> Result<Series> {
    let deployment = topology().await?;
    let reps = repetitions();

    // Errors here are ignored on purpose: a warm-up that failed says nothing
    // the measured runs will not say louder.
    let _ = (meter.run)(deployment.net()).await;

    let mut samples = Vec::with_capacity(reps);
    let mut unit = "";
    let mut last_failure = None;
    for _ in 0..reps {
        // One repetition failing is tolerated, all of them failing is not.
        //
        // A meter that opens connection after connection is exposed to
        // something none of the code under test controls: a listener backlog
        // that fills, an ephemeral port that has just been handed back, a
        // machine doing something else. It is rare, it says nothing about
        // either implementation, and both sides are equally exposed. Keeping
        // the best of several runs already assumes that noise only makes a run
        // worse; a run that did not finish is simply the worst kind of noise.
        match (meter.run)(deployment.net()).await {
            Ok(measured) => {
                unit = measured.unit;
                samples.push(measured.value);
            }
            Err(err) => last_failure = Some(err),
        }
    }
    deployment.shutdown().await?;

    if samples.is_empty() {
        return match last_failure {
            Some(err) => Err(err.context(format!(
                "every one of the {} attempts to measure failed",
                reps
            ))),
            None => Err(anyhow::anyhow!("no measurement was taken")),
        };
    }
    Ok(Series::new(unit, samples, meter.budget))
}
