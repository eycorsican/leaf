//! Several plugins mapped in one process at once, and what a plugin that
//! carries a language runtime costs the host.
//!
//! Every other case in this suite loads one implementation at a time, which is
//! not how a deployment uses them: a chain can name plugins written in
//! different languages, and a process that reloads its configuration maps and
//! unmaps them while the rest keeps running. Two things only show up there --
//! plugins colliding over something process-wide, and a library being unmapped
//! while code in it is still running -- and neither is visible to a case that
//! loads one plugin and stops.

use std::time::Duration;

use anyhow::{ensure, Context, Result};

use crate::behaviours;
use crate::differential::Deployment;
use crate::fixtures::Fixture;
use crate::logs;
use crate::node::{cfg, Node};
use crate::scenario::{boxed, Scenario, Tag};
use crate::scenarios::differential::{Group, Stage};

const VERDICT: Duration = Duration::from_secs(10);

pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario::new("coexist/every-language-at-once", "coexist", || {
            boxed(every_language_at_once())
        })
        .tags([Tag::Plugin, Tag::Go, Tag::Cc, Tag::Zig])
        .needs([
            Fixture::ShadowsocksCabiRs,
            Fixture::Socks5CabiC,
            Fixture::Socks5CabiZig,
            Fixture::TlsCabiGo,
            Fixture::TrojanCabiGo,
        ])
        .timeout(Duration::from_secs(120)),
        Scenario::new("coexist/a-runtime-outlives-its-handlers", "coexist", || {
            boxed(a_runtime_outlives_its_handlers())
        })
        .tags([Tag::Plugin, Tag::Go])
        .needs([Fixture::TlsCabiGo])
        .timeout(Duration::from_secs(90)),
        Scenario::new(
            "coexist/the-runtime-flag-reaches-the-host",
            "coexist",
            || boxed(the_runtime_flag_reaches_the_host()),
        )
        .tags([Tag::Plugin, Tag::Go])
        .needs([Fixture::TlsCabiGo, Fixture::TlsCabiRs])
        .timeout(Duration::from_secs(60)),
        Scenario::new("coexist/two-runtimes-are-announced", "coexist", || {
            boxed(two_runtimes_are_announced())
        })
        .tags([Tag::Plugin, Tag::Go])
        .needs([Fixture::TlsCabiGo, Fixture::TrojanCabiGo])
        .timeout(Duration::from_secs(60)),
    ]
}

/// A process that ends up with two language runtimes in it says so, once.
///
/// The host allows this -- it works, and the suite exercises it under fault in
/// `hostile/go/a-fault-with-another-runtime-live` -- but it is a configuration
/// the runtimes' own projects decline to guarantee, and nothing else in a
/// running process makes it visible. One line in the log is what turns "this
/// deployment behaves strangely and nothing explains it" into a place to look.
async fn two_runtimes_are_announced() -> Result<()> {
    let node = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "go-tls",
            &Fixture::TlsCabiGo.path()?,
            None,
            r#"{"server_name":"localhost","insecure":true}"#,
        ))
        .outbound(cfg::plugin(
            "go-trojan",
            &Fixture::TrojanCabiGo.path()?,
            Some(crate::net::loopback(crate::net::reserve_dual_port()?)),
            "password",
        ))
        .start()
        .await?;
    let line = logs::wait_for("embeds a language runtime", VERDICT).await?;
    ensure!(
        line.contains("count=2"),
        "the host warned about runtimes but did not say how many: {}",
        line
    );
    node.shutdown().await
}

/// Every plugin language the suite has, mapped and carrying traffic at the same
/// time, in one process.
///
/// Deployed together rather than one after another, which is the whole point: a
/// plugin that is correct alone can still collide with another over something
/// there is only one of in a process. Two of these libraries are Go
/// `c-shared` builds, so this is also two independent Go runtimes side by side,
/// each with its own threads and its own heap, reached through export tables
/// that name the same symbols.
///
/// The shutdown at the end is not a formality. It is where a library gets
/// unmapped, and where a plugin whose runtime is still running would take the
/// process with it.
async fn every_language_at_once() -> Result<()> {
    let groups: [(&str, Group); 4] = [
        (
            "shadowsocks-cabi-rs",
            Group::Shadowsocks {
                outbound: Stage::Plugin(Fixture::ShadowsocksCabiRs),
            },
        ),
        (
            "socks5-cabi-c",
            Group::Socks5 {
                outbound: Stage::Plugin(Fixture::Socks5CabiC),
                auth: false,
            },
        ),
        (
            "socks5-cabi-zig",
            Group::Socks5 {
                outbound: Stage::Plugin(Fixture::Socks5CabiZig),
                auth: false,
            },
        ),
        (
            "tls-cabi-go over trojan-cabi-go",
            Group::TlsChain {
                tls: Stage::Plugin(Fixture::TlsCabiGo),
                trojan: Stage::Plugin(Fixture::TrojanCabiGo),
            },
        ),
    ];

    let mut deployments: Vec<(&str, Deployment)> = Vec::new();
    for (name, group) in groups {
        let deployment = group
            .deploy()
            .await
            .with_context(|| format!("starting the topology for [{}]", name))?;
        deployments.push((name, deployment));
    }

    // Concurrently, so the engines are actually live at the same moment rather
    // than merely loaded at the same moment.
    let running = deployments.iter().map(|(name, deployment)| {
        let net = deployment.net();
        async move {
            (behaviours::ECHO.run)(net)
                .await
                .with_context(|| format!("[{}] failed while the others were running", name))
        }
    });
    futures::future::try_join_all(running).await?;

    for (name, deployment) in deployments {
        deployment
            .shutdown()
            .await
            .with_context(|| format!("stopping the topology for [{}]", name))?;
    }
    Ok(())
}

/// A plugin that embeds a runtime is used, let go of entirely, and then used
/// again in the same process.
///
/// Letting go is the hard part. The host maps a library when the first outbound
/// names it and holds it only for as long as something needs it, so when the
/// last node using it stops, the last reference goes. For an ordinary plugin
/// that is when the library is unmapped, which is what the host wants: a
/// configuration that no longer names a plugin should not go on paying for it.
/// A Go `c-shared` library cannot be unmapped at all -- its runtime's threads
/// are not something the host holds a reference to, and they go on running code
/// in it -- which is what `PLUGIN_FLAG_EMBEDS_RUNTIME` tells the host, and this
/// is the case that fails if the host stops honouring it.
///
/// How loudly it fails is the platform's choice, as with the reload case in
/// `hostile/`: Windows really does unmap and the process dies inside
/// `FreeLibrary`, while Linux and macOS decline to unmap a library like this
/// and the case passes whether or not the flag was honoured. Worth running
/// everywhere for the second half, which is about the reload after.
async fn a_runtime_outlives_its_handlers() -> Result<()> {
    let group = Group::TlsChain {
        tls: Stage::Plugin(Fixture::TlsCabiGo),
        trojan: Stage::Native,
    };

    let first = group.deploy().await.context("first deployment")?;
    (behaviours::ECHO.run)(first.net())
        .await
        .context("the first deployment failed before anything interesting happened")?;
    first.shutdown().await.context(
        "stopping the first deployment, which drops the last handler holding the library",
    )?;

    // Everything that referenced the library is now gone. If it was unmapped,
    // the runtime it carried is running in freed address space and this process
    // is already dead; if the process is still here, the second deployment then
    // asks the harder question of whether the host can map it again -- which
    // for a library it never really let go of means finding it already there
    // and picking it back up.
    let second = group.deploy().await.context(
        "second deployment: the plugin could not be loaded again after its handlers went",
    )?;
    (behaviours::ECHO.run)(second.net())
        .await
        .context("the plugin no longer carries traffic after being let go of and taken up again")?;
    second
        .shutdown()
        .await
        .context("stopping the second deployment")
}

/// The flag survives the trip from the Go SDK's static descriptor, through the
/// C ABI, to the decision the host makes about the library.
///
/// Asserted from the log because that is the only place the decision is
/// visible: keeping a library mapped looks exactly like not needing to unmap it
/// yet. The negative half matters as much as the positive -- a host that
/// treated every plugin as though it embedded a runtime would pass the case
/// above while quietly never unmapping anything.
async fn the_runtime_flag_reaches_the_host() -> Result<()> {
    let go = Node::new("go-client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "go-tls",
            &Fixture::TlsCabiGo.path()?,
            None,
            r#"{"server_name":"localhost","insecure":true}"#,
        ))
        .start()
        .await?;
    let line = logs::wait_for("keeping its library mapped", VERDICT).await?;
    ensure!(
        line.contains("leaf-tls-cabi-go-plugin"),
        "the host kept a library mapped, but not the Go plugin's: {}",
        line
    );
    logs::wait_for("embeds_runtime=true", VERDICT).await?;
    go.shutdown().await?;

    let rust = Node::new("rust-client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "rust-tls",
            &Fixture::TlsCabiRs.path()?,
            None,
            r#"{"server_name":"localhost","insecure":true}"#,
        ))
        .start()
        .await?;
    let line = logs::wait_for("embeds_runtime=false", VERDICT).await?;
    ensure!(
        line.contains("tls-cabi-rs") || line.contains("leaf-tls-cabi-rs-plugin"),
        "a plugin reported no runtime, but not the Rust one: {}",
        line
    );
    rust.shutdown().await
}
