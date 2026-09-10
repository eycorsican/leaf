//! Reading the conformance plugin's own counters.
//!
//! The plugin exports a symbol outside the ABI for this. Opening the library a
//! second time from the test gets the image the host already mapped, so the
//! counters read here are the ones the host's calls incremented -- and the ABI
//! did not have to grow a hole for a test's benefit.

use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::fixtures::Fixture;

/// Selects which descriptor the conformance plugin publishes.
pub const ENV_DESCRIPTOR: &str = "LEAF_CONFORMANCE_DESCRIPTOR";

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub instances_created: u64,
    pub instances_destroyed: u64,
    pub descriptor_reads: u64,
}

type StatsFn = unsafe extern "C" fn(*mut Stats);

pub fn stats() -> Result<Stats> {
    let path = Fixture::Conformance.path()?;
    // Safety: the path names the conformance plugin this suite built, and the
    // symbol is its own, with the signature declared above.
    unsafe {
        let library = libloading::Library::new(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        let read: libloading::Symbol<StatsFn> = library
            .get(b"leaf_conformance_stats\0")
            .context("the conformance plugin does not export leaf_conformance_stats")?;
        let mut stats = Stats::default();
        read(&mut stats);
        Ok(stats)
    }
}

/// Waits for every engine instance to have been destroyed.
///
/// Instances go away when the host drops the stream, which happens after the
/// session ends rather than when the client closes, so this is a poll rather
/// than a single read.
pub async fn wait_for_balanced_instances(within: Duration) -> Result<Stats> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let stats = stats()?;
        if stats.instances_created == stats.instances_destroyed {
            return Ok(stats);
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "{} engine instances were created but only {} destroyed after {:?}",
                stats.instances_created,
                stats.instances_destroyed,
                within
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
