//! The case registry.
//!
//! Cases are values rather than `#[test]` functions, so a suite can be a matrix
//! -- implementation x protocol x transport x behaviour -- instead of a wall of
//! copies.

use crate::fixtures::Fixture;
use crate::scenario::{Scenario, Tag};

pub mod abi;
pub mod blackbox;
pub mod coexist;
pub mod datagram;
pub mod differential;
pub mod halfclose;
pub mod hostile;
pub mod loader;
pub mod protocols;
pub mod smoke;
pub mod stress;
pub mod teardown;

pub fn all() -> Vec<Scenario> {
    let scenarios: Vec<Scenario> = smoke::scenarios()
        .into_iter()
        .chain(differential::scenarios())
        .chain(loader::scenarios())
        .chain(abi::scenarios())
        .chain(hostile::scenarios())
        .chain(datagram::scenarios())
        .chain(blackbox::scenarios())
        .chain(coexist::scenarios())
        .chain(stress::scenarios())
        .chain(teardown::scenarios())
        .chain(halfclose::scenarios())
        .chain(protocols::scenarios())
        .collect();

    let mut seen = std::collections::BTreeSet::new();
    for scenario in &scenarios {
        // A duplicate id would make `--exact` ambiguous and would collide in
        // the artifact directory: a harness bug, not a test failure.
        assert!(
            seen.insert(scenario.id.as_str()),
            "duplicate scenario id [{}]",
            scenario.id
        );
        // Tags drive lane selection, so one that disagrees with what a case
        // actually needs would quietly exclude it from the lane that exists for
        // it -- or include it in one that cannot run it. Every toolchain a case
        // can be skipped for gets the same treatment.
        for (tag, needs_toolchain, toolchain) in [
            (Tag::Go, Fixture::needs_go as fn(Fixture) -> bool, "Go"),
            (Tag::Cc, Fixture::needs_cc as fn(Fixture) -> bool, "C"),
            (Tag::Zig, Fixture::needs_zig as fn(Fixture) -> bool, "Zig"),
        ] {
            let wanted = scenario.needs.iter().copied().any(needs_toolchain);
            assert_eq!(
                wanted,
                scenario.has_tag(tag),
                "scenario [{}] must be tagged `{}` exactly when it needs a {} fixture",
                scenario.id,
                tag.as_str(),
                toolchain
            );
        }
        let wants_plugin = scenario.needs.iter().any(|fixture| fixture.is_plugin());
        assert_eq!(
            wants_plugin,
            scenario.has_tag(Tag::Plugin),
            "scenario [{}] must be tagged `plugin` exactly when it needs a plugin",
            scenario.id
        );
    }
    scenarios
}
