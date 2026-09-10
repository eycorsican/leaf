//! What the host makes of a descriptor, across a real `dlopen`.
//!
//! The compatibility rules -- exact major match, a frozen prefix every peer
//! must provide, trailing fields a newer peer may add -- decide whether a
//! deployment starts at all. They are checked here through the loader, with a
//! plugin that publishes each shape in turn, rather than against structures
//! fabricated in the host's own address space.
//!
//! A case selects a shape through the environment, because the descriptor is
//! read once when the library is mapped and cannot be changed afterwards. That
//! is one of the reasons every case owns a process.

use std::time::Duration;

use anyhow::{ensure, Result};

use crate::client::Socks5;
use crate::fixtures::Fixture;
use crate::flow;
use crate::net;
use crate::node::{cfg, Node};
use crate::scenario::{boxed, Scenario, Tag};
use crate::servers::Origin;

/// Selects which descriptor the conformance plugin publishes.
const ENV_DESCRIPTOR: &str = "LEAF_CONFORMANCE_DESCRIPTOR";

/// A descriptor the host must load, and then use.
struct Accepted {
    id: &'static str,
    variant: &'static str,
}

/// A descriptor the host must refuse, and what it has to say about it.
struct Rejected {
    id: &'static str,
    variant: &'static str,
    message: &'static str,
}

pub fn scenarios() -> Vec<Scenario> {
    let accepted = [
        Accepted {
            id: "abi/accepts-a-matching-version",
            variant: "ok",
        },
        // Larger structures with fields this host has never heard of: the size
        // prefix is what makes that safe, and ignoring the tail is the whole
        // point of it.
        Accepted {
            id: "abi/accepts-a-newer-minor-version",
            variant: "newer-minor",
        },
        // A flag bit from a minor version this host predates. Flags are
        // additive in the same way fields are, and the rule that makes them so
        // is that one may only ever ask for treatment that is safe to omit --
        // so an unknown bit is ignored and the plugin still loads and works.
        Accepted {
            id: "abi/accepts-an-unknown-flag",
            variant: "unknown-flag",
        },
    ];

    let rejected = [
        Rejected {
            id: "abi/rejects-a-lower-major-version",
            variant: "abi-major-lower",
            message: "ABI major version",
        },
        Rejected {
            id: "abi/rejects-a-higher-major-version",
            variant: "abi-major-higher",
            message: "ABI major version",
        },
        Rejected {
            id: "abi/rejects-a-short-descriptor",
            variant: "short-descriptor",
            message: "is smaller than",
        },
        Rejected {
            id: "abi/rejects-a-short-stream-engine",
            variant: "short-stream-engine",
            message: "is smaller than",
        },
        Rejected {
            id: "abi/rejects-a-null-name",
            variant: "null-name",
            message: "null metadata field [name]",
        },
        Rejected {
            id: "abi/rejects-a-non-utf8-name",
            variant: "invalid-utf8-name",
            message: "not valid UTF-8",
        },
        Rejected {
            id: "abi/rejects-an-empty-version",
            variant: "empty-version",
            message: "metadata field [version] is empty",
        },
        Rejected {
            id: "abi/rejects-a-descriptor-with-no-engine",
            variant: "no-engine",
            message: "exports neither stream nor datagram engine",
        },
        Rejected {
            id: "abi/rejects-a-null-required-entry",
            variant: "null-required-fn",
            message: "null required field [stream.pull]",
        },
        Rejected {
            id: "abi/rejects-an-invalid-connect-type",
            variant: "bad-connect-type",
            message: "invalid connect_type",
        },
    ];

    let mut scenarios = Vec::new();
    for case in accepted {
        scenarios.push(
            Scenario::new(case.id, "abi", move || boxed(accepts(case.variant)))
                .tags([Tag::Plugin])
                .needs([Fixture::Conformance])
                .env(ENV_DESCRIPTOR, case.variant)
                .timeout(Duration::from_secs(30)),
        );
    }
    for case in rejected {
        scenarios.push(
            Scenario::new(case.id, "abi", move || {
                boxed(rejects(case.variant, case.message))
            })
            .tags([Tag::Plugin])
            .needs([Fixture::Conformance])
            .env(ENV_DESCRIPTOR, case.variant)
            .timeout(Duration::from_secs(30)),
        );
    }
    scenarios
}

/// Loads, and then carries traffic: a descriptor that is merely accepted proves
/// little if the vtable behind it was read wrong.
async fn accepts(variant: &'static str) -> Result<()> {
    ensure!(
        std::env::var(ENV_DESCRIPTOR).as_deref() == Ok(variant),
        "the case did not receive its descriptor selection"
    );
    let origin = Origin::tcp_echo().await?;
    let node = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "conformance",
            &Fixture::Conformance.path()?,
            Some(origin.addr()),
            "",
        ))
        .start()
        .await?;

    let mut stream = Socks5::new(node.socks_addr()?)
        .connect(origin.addr())
        .await?;
    flow::echo_roundtrip(&mut stream, b"hello").await?;

    node.shutdown().await
}

async fn rejects(variant: &'static str, message: &'static str) -> Result<()> {
    ensure!(
        std::env::var(ENV_DESCRIPTOR).as_deref() == Ok(variant),
        "the case did not receive its descriptor selection"
    );
    let error = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "conformance",
            &Fixture::Conformance.path()?,
            // An endpoint that is never dialled: the descriptor is rejected
            // long before anything connects.
            Some(net::loopback(1)),
            "",
        ))
        .start_expecting_failure()
        .await?;
    ensure!(
        error.contains(message),
        "expected the error to mention [{}], got: {}",
        message,
        error
    );
    Ok(())
}
