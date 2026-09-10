//! Cases that use no plugin at all.
//!
//! They exist to tell a broken harness apart from a broken plugin: if these
//! fail, nothing else in the suite means anything.

use std::path::Path;
use std::time::Duration;

use anyhow::{ensure, Result};

use crate::behaviours;
use crate::client::Socks5;
use crate::flow;
use crate::node::{cfg, Node};
use crate::paths;
use crate::scenario::{boxed, Scenario, Tag};
use crate::servers::Origin;

pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario::new("smoke/native/socks-direct/tcp", "smoke", || {
            boxed(socks_direct_tcp())
        })
        .tags([Tag::Native])
        .timeout(Duration::from_secs(20)),
        Scenario::new("smoke/native/socks-direct/udp", "smoke", || {
            boxed(socks_direct_udp())
        })
        .tags([Tag::Native])
        .timeout(Duration::from_secs(20)),
        // The oracle for every bulk case that goes through a plugin: the same
        // traffic over a stock direct outbound.
        // No leaf at all: if this fails, the harness is at fault and nothing
        // else in the suite means anything.
        Scenario::new("smoke/harness/loopback-bulk", "smoke", || {
            boxed(loopback_bulk())
        })
        .tags([Tag::Native])
        .timeout(Duration::from_secs(60)),
        Scenario::new("smoke/harness/knows-its-profile-directory", "smoke", || {
            boxed(knows_its_profile_directory())
        })
        .tags([Tag::Native])
        .timeout(Duration::from_secs(20)),
        Scenario::new("smoke/native/socks-direct/bulk-transfer", "smoke", || {
            boxed(socks_direct_bulk())
        })
        .tags([Tag::Native, Tag::Slow])
        .timeout(Duration::from_secs(60)),
    ]
}

/// Where cargo put this binary is how the harness works out where to build
/// plugins and where to look for them. Cargo has changed that layout underneath
/// it once already, and the way it showed up was every case in the run
/// reporting a fixture it could not build -- so the layouts it has produced are
/// pinned here, where a change says what it is.
async fn knows_its_profile_directory() -> Result<()> {
    let layouts = [
        // Cargo's long-standing layout for a test binary.
        (
            "/w/target/debug/deps/e2e-2b080c7f72c4fcfd",
            Some("/w/target/debug"),
        ),
        // What the sanitizer lane produced once a newer cargo moved
        // intermediates under a hashed directory of their own.
        (
            "/w/target/x86_64-unknown-linux-gnu/debug/build/leaf-e2e/3a4b84209787/out/e2e-3a4b84209787",
            Some("/w/target/x86_64-unknown-linux-gnu/debug"),
        ),
        // A custom profile keeps its own directory name, which is the name
        // `--profile` has to be given back.
        ("/w/target/ci/deps/e2e-abc", Some("/w/target/ci")),
        // The nearest match wins, so a workspace that itself lives under a
        // directory called `build` is not mistaken for one of these layouts.
        (
            "/home/build/w/target/debug/deps/e2e-abc",
            Some("/home/build/w/target/debug"),
        ),
        // And a binary somewhere else entirely is refused rather than guessed
        // at, because guessing is what produced `--profile <build hash>`.
        ("/somewhere/else/e2e", None),
    ];
    for (exe, expected) in layouts {
        let derived = paths::derive_profile_dir(Path::new(exe));
        ensure!(
            derived.as_deref() == expected.map(Path::new),
            "[{}] resolved to {:?}, expected {:?}",
            exe,
            derived,
            expected
        );
    }

    // And the live one, which every fixture path in the suite is built from.
    let live = paths::profile_dir()?;
    ensure!(
        live.is_dir(),
        "the profile directory [{}] is not a directory",
        live.display()
    );
    Ok(())
}

async fn loopback_bulk() -> Result<()> {
    let origin = Origin::tcp_echo().await?;
    let stream = tokio::net::TcpStream::connect(origin.addr()).await?;
    flow::bulk_echo(stream, behaviours::bulk_bytes(), 0xE2E).await?;
    Ok(())
}

async fn socks_direct_bulk() -> Result<()> {
    let origin = Origin::tcp_echo().await?;
    let node = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::direct("direct"))
        .start()
        .await?;

    let stream = Socks5::new(node.socks_addr()?)
        .connect(origin.addr())
        .await?;
    flow::bulk_echo(stream, behaviours::bulk_bytes(), 0xE2E).await?;

    node.shutdown().await
}

async fn socks_direct_tcp() -> Result<()> {
    let origin = Origin::tcp_echo().await?;
    let node = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::direct("direct"))
        .start()
        .await?;

    let mut stream = Socks5::new(node.socks_addr()?)
        .connect(origin.addr())
        .await?;
    flow::echo_roundtrip(&mut stream, b"hello").await?;

    node.shutdown().await
}

async fn socks_direct_udp() -> Result<()> {
    let origin = Origin::udp_echo().await?;
    let node = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::direct("direct"))
        .start()
        .await?;

    let session = Socks5::new(node.socks_addr()?).udp_associate().await?;
    session.send_to(b"hello", origin.addr()).await?;
    let mut buf = [0u8; 64];
    let (n, source) = tokio::time::timeout(Duration::from_secs(5), session.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("no datagram came back"))??;
    anyhow::ensure!(&buf[..n] == b"hello", "udp echo mismatch: {:?}", &buf[..n]);
    anyhow::ensure!(
        source == crate::client::Target::Ip(origin.addr()),
        "unexpected datagram source {:?}",
        source
    );

    node.shutdown().await
}
