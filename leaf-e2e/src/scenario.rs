//! What a test case is.
//!
//! Cases are values, not `#[test]` functions. The interesting suites are
//! matrices -- implementation x protocol x transport x behaviour -- so they are
//! generated at registry build time and turned into `libtest-mimic` trials.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use crate::fixtures::Fixture;

pub type CaseFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// A case body. Boxed rather than a function pointer so that generated cases
/// can capture the matrix cell they stand for.
pub type CaseFn = Arc<dyn Fn() -> CaseFuture + Send + Sync>;

/// Boxes a scenario body. Written out so that a case closure has the
/// trait-object return type rather than the concrete future.
pub fn boxed<F>(future: F) -> CaseFuture
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    Box::pin(future)
}

/// Selection labels. Lanes (sanitizers, nightly-only jobs, quick local runs)
/// pick cases by tag rather than by fragile name globs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Tag {
    /// Exercises a leaf-native implementation only; the harness's own smoke test.
    Native,
    /// Drives at least one plugin across the C ABI.
    Plugin,
    /// Needs a Go toolchain.
    Go,
    /// Needs a C compiler.
    Cc,
    /// Needs a Zig toolchain.
    Zig,
    /// Compares a plugin against the native implementation it stands in for.
    Differential,
    /// Measures what the plugin boundary costs, relative to native.
    Perf,
    /// Deliberately misbehaving plugin; run this lane under a sanitizer.
    Hostile,
    /// Spawns a real `leaf` process instead of an in-process node.
    Cli,
    /// Drives sustained load: many connections at once, a connection storm, or
    /// a reader that stops reading. These assert invariants -- no errors, no
    /// leaked instances, bounded memory -- rather than timings.
    Stress,
    /// Runs for minutes rather than seconds. Excluded from the default lane;
    /// a nightly job runs it on its own.
    Soak,
    /// Noticeably slower than the rest; excluded from the quick lane.
    Slow,
}

impl Tag {
    pub const ALL: &'static [Tag] = &[
        Tag::Native,
        Tag::Plugin,
        Tag::Go,
        Tag::Cc,
        Tag::Zig,
        Tag::Differential,
        Tag::Perf,
        Tag::Hostile,
        Tag::Cli,
        Tag::Stress,
        Tag::Soak,
        Tag::Slow,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Tag::Native => "native",
            Tag::Plugin => "plugin",
            Tag::Go => "go",
            Tag::Cc => "cc",
            Tag::Zig => "zig",
            Tag::Differential => "differential",
            Tag::Perf => "perf",
            Tag::Hostile => "hostile",
            Tag::Cli => "cli",
            Tag::Stress => "stress",
            Tag::Soak => "soak",
            Tag::Slow => "slow",
        }
    }

    pub fn parse(s: &str) -> Option<Tag> {
        Tag::ALL.iter().copied().find(|tag| tag.as_str() == s)
    }
}

pub struct Scenario {
    /// Stable, slash-separated identity; also the trial name and the artifact
    /// directory name.
    pub id: String,
    /// Printed in brackets before the name by the test reporter.
    pub kind: &'static str,
    pub tags: Vec<Tag>,
    /// Artifacts that must exist before this case can run. When one cannot be
    /// built the case is reported as ignored, with the reason.
    pub needs: Vec<Fixture>,
    /// Extra environment for the case's child process. This is how a case
    /// selects a plugin's load-time behaviour, which cannot be changed once the
    /// library is mapped -- and part of why cases get their own process.
    pub env: Vec<(String, String)>,
    /// Hard deadline. The runner kills the child when it expires.
    pub timeout: Duration,
    /// A defect this case is known to hit, kept here rather than deleted.
    ///
    /// A case marked this way is reported as an expected failure instead of a
    /// failure, so a known bug does not train everyone to ignore a red suite --
    /// and it fails the day it starts passing, which is when the marker should
    /// come off.
    pub known_defect: Option<String>,
    pub run: CaseFn,
}

impl Scenario {
    pub fn new<F>(id: impl Into<String>, kind: &'static str, run: F) -> Self
    where
        F: Fn() -> CaseFuture + Send + Sync + 'static,
    {
        Self {
            id: id.into(),
            kind,
            tags: Vec::new(),
            needs: Vec::new(),
            env: Vec::new(),
            timeout: Duration::from_secs(30),
            known_defect: None,
            run: Arc::new(run),
        }
    }

    pub fn tags(mut self, tags: impl IntoIterator<Item = Tag>) -> Self {
        self.tags = tags.into_iter().collect();
        self
    }

    pub fn needs(mut self, needs: impl IntoIterator<Item = Fixture>) -> Self {
        self.needs = needs.into_iter().collect();
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Marks this case as hitting a known defect. State what is wrong, not that
    /// something is.
    pub fn known_defect(mut self, description: impl Into<String>) -> Self {
        self.known_defect = Some(description.into());
        self
    }

    pub fn has_tag(&self, tag: Tag) -> bool {
        self.tags.contains(&tag)
    }
}
