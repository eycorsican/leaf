//! Builtin plugins: plugins compiled into the client, named by `builtin=`.
//!
//! On mobile the plugin is linked into the app and registered under a name.
//! These cases stand in for the link by taking the descriptor function out of
//! a fixture library and registering that -- the host cannot tell the
//! difference, since all it is ever given is the function. What they check is
//! everything on the host's side of it: that a registered builtin carries real
//! traffic against a stock leaf server, that it wins over `path` and `url` and
//! needs neither a file nor a cache, that a client without it falls back to
//! them, that one with neither says which builtins it does have, and that a
//! builtin's descriptor is held to the same validation as a library's.
//!
//! The static link itself -- several plugins in one binary, the C one renamed
//! by `LEAF_PLUGIN_STATIC_NAME` -- is `leaf-ffi`'s to test, since that is the
//! binary that links them.

use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use leaf::app::outbound::plugin::{self as host, PluginDescriptorFn};
use leaf::app::outbound::plugin_fetch;

use crate::client::{Socks5, Target};
use crate::conformance::ENV_DESCRIPTOR;
use crate::fixtures::Fixture;
use crate::flow;
use crate::net;
use crate::node::{cfg, Node};
use crate::plugin_server::{PluginServer, Route};
use crate::scenario::{boxed, Scenario, Tag};
use crate::servers::Origin;

const METHOD: &str = "aes-128-gcm";
const PASSWORD: &str = "builtin-password";

pub fn scenarios() -> Vec<Scenario> {
    let shadowsocks = |id: &str, run: fn() -> crate::scenario::CaseFuture| {
        Scenario::new(id.to_string(), "builtin", run)
            .tags([Tag::Plugin])
            .needs([Fixture::ShadowsocksCabiRs])
            .timeout(Duration::from_secs(30))
    };
    vec![
        shadowsocks("builtin/carries-tcp-and-udp-to-a-native-server", || {
            boxed(carries_tcp_and_udp_to_a_native_server())
        }),
        shadowsocks("builtin/wins-over-path", || boxed(wins_over_path())),
        shadowsocks("builtin/wins-over-url", || boxed(wins_over_url())),
        shadowsocks("builtin/falls-back-to-url-when-not-built-in", || {
            boxed(falls_back_to_url_when_not_built_in())
        })
        .tags([Tag::Plugin, Tag::Fetch]),
        shadowsocks(
            "builtin/missing-without-fallback-names-what-is-built-in",
            || boxed(missing_without_fallback_names_what_is_built_in()),
        ),
        Scenario::new(
            "builtin/descriptor-is-validated-like-a-library",
            "builtin",
            || boxed(descriptor_is_validated_like_a_library()),
        )
        .tags([Tag::Plugin])
        .needs([Fixture::Conformance])
        .env(ENV_DESCRIPTOR, "abi-major-lower")
        .timeout(Duration::from_secs(30)),
    ]
}

/// Registers `fixture`'s descriptor function as the builtin `name`, the way an
/// app registers a plugin it linked in.
fn register_from(fixture: Fixture, name: &str) -> Result<()> {
    let path = fixture.path()?;
    // Safety: the fixture is a plugin this suite built, and the symbol is the
    // one every plugin exports, with the type the ABI gives it.
    unsafe {
        let library = libloading::Library::new(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        let get_descriptor: PluginDescriptorFn = *library
            .get::<PluginDescriptorFn>(b"leaf_plugin_get_descriptor\0")
            .context("the fixture exports no descriptor")?;
        // A linked-in plugin is there for the life of the process; so is this.
        std::mem::forget(library);
        host::register_builtin_plugin(name, get_descriptor)?;
    }
    Ok(())
}

/// A stock leaf shadowsocks server in front of `direct`.
async fn native_server() -> Result<(crate::node::LeafNode, std::net::SocketAddr)> {
    let port = net::reserve_dual_port()?;
    let node = Node::new("server")
        .inbound(cfg::shadowsocks_inbound("ss-in", port, METHOD, PASSWORD))
        .outbound(cfg::direct("direct"))
        .start()
        .await?;
    Ok((node, net::loopback(port)))
}

/// A client conf with one plugin proxy, `plugin_line` declaring its plugin,
/// and every connection through it.
fn client_conf(socks_port: u16, plugin_line: &str, server: std::net::SocketAddr) -> String {
    format!(
        "[General]\nloglevel = trace\nsocks-interface = 127.0.0.1\nsocks-port = {}\n\n\
         [Plugin]\n{}\n\n\
         [Proxy]\nSS = plugin, {}, {}, plugin=ss, args={};{}\n\n\
         [Rule]\nFINAL, SS\n",
        socks_port,
        plugin_line,
        server.ip(),
        server.port(),
        METHOD,
        PASSWORD
    )
}

/// Neither the environment nor the defaults point at a cache, so that a case
/// which should need none fails if it asks.
fn no_cache_directory() {
    plugin_fetch::set_default_options(None);
    std::env::remove_var(plugin_fetch::ENV_CACHE_DIR);
}

async fn echo_tcp(client: std::net::SocketAddr, origin: &Origin) -> Result<()> {
    let mut stream = Socks5::new(client).connect(origin.addr()).await?;
    flow::echo_roundtrip(&mut stream, b"through a builtin plugin").await
}

/// The builtin is real protocol code talking to leaf's own implementation of
/// the other end, over TCP and over UDP.
async fn carries_tcp_and_udp_to_a_native_server() -> Result<()> {
    register_from(Fixture::ShadowsocksCabiRs, "shadowsocks-rs")?;
    let (server, server_addr) = native_server().await?;
    let tcp_origin = Origin::tcp_echo().await?;
    let udp_origin = Origin::udp_echo().await?;
    let socks_port = net::reserve_dual_port()?;
    let conf = client_conf(socks_port, "ss = builtin=shadowsocks-rs", server_addr);
    let client = Node::start_conf("client", &conf, socks_port).await?;

    echo_tcp(client.socks_addr()?, &tcp_origin).await?;

    let session = Socks5::new(client.socks_addr()?).udp_associate().await?;
    session
        .send_to(b"builtin datagram", udp_origin.addr())
        .await?;
    let mut buf = [0u8; 64];
    let (n, source) = tokio::time::timeout(Duration::from_secs(5), session.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow!("no datagram came back through the builtin"))??;
    ensure!(
        &buf[..n] == b"builtin datagram",
        "udp echo mismatch: {:?}",
        &buf[..n]
    );
    ensure!(
        source == Target::Ip(udp_origin.addr()),
        "unexpected datagram source {:?}",
        source
    );

    client.shutdown().await?;
    server.shutdown().await
}

/// With the builtin registered, a `path` is for other clients: one that does
/// not exist is never looked at.
async fn wins_over_path() -> Result<()> {
    register_from(Fixture::ShadowsocksCabiRs, "shadowsocks-rs")?;
    no_cache_directory();
    let (server, server_addr) = native_server().await?;
    let origin = Origin::tcp_echo().await?;
    let socks_port = net::reserve_dual_port()?;
    let line = "ss = builtin=shadowsocks-rs, path=./there-is-no-such-plugin.dll";
    let client = Node::start_conf(
        "client",
        &client_conf(socks_port, line, server_addr),
        socks_port,
    )
    .await?;

    echo_tcp(client.socks_addr()?, &origin).await?;

    client.shutdown().await?;
    server.shutdown().await
}

/// So is a `url`: it is not fetched, and no cache directory is asked for --
/// which is what lets a mobile client run the desktop config unchanged.
async fn wins_over_url() -> Result<()> {
    register_from(Fixture::ShadowsocksCabiRs, "shadowsocks-rs")?;
    no_cache_directory();
    let plugins = PluginServer::start().await?;
    let (server, server_addr) = native_server().await?;
    let origin = Origin::tcp_echo().await?;
    let socks_port = net::reserve_dual_port()?;
    let line = format!(
        "ss = builtin=shadowsocks-rs, url={}, sha256={}",
        plugins.url("/ss.dll"),
        "0".repeat(64)
    );
    let client = Node::start_conf(
        "client",
        &client_conf(socks_port, &line, server_addr),
        socks_port,
    )
    .await?;

    echo_tcp(client.socks_addr()?, &origin).await?;
    ensure!(
        plugins.total_requests() == 0,
        "the url of a builtin was fetched"
    );

    client.shutdown().await?;
    server.shutdown().await
}

/// The same config on a client built without the plugin: the builtin is not
/// there, so the url is, and the download is what runs.
async fn falls_back_to_url_when_not_built_in() -> Result<()> {
    let plugins = PluginServer::start().await?;
    let path = Fixture::ShadowsocksCabiRs.path()?;
    let bytes = std::fs::read(&path)?;
    let file = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("unnamed fixture"))?;
    let route = format!("/plugins/{}", file);
    plugins.route(&route, Route::ok(bytes.clone()));
    let cache = crate::paths::artifacts_dir()?
        .join(crate::paths::artifact_slug(
            &crate::report::case().unwrap_or_else(|| "in-process".to_string()),
        ))
        .join("plugin-cache");
    let _ = std::fs::remove_dir_all(&cache);
    let mut options = plugin_fetch::FetchOptions::new(&cache);
    options.extra_roots = vec![plugins.ca()];
    plugin_fetch::set_default_options(Some(options));

    let (server, server_addr) = native_server().await?;
    let origin = Origin::tcp_echo().await?;
    let socks_port = net::reserve_dual_port()?;
    // The size is declared, as a real config would: without it a download is
    // held to MAX_UNDECLARED_SIZE, and a debug build of this fixture on Linux,
    // debug info and all, is well past that.
    let line = format!(
        "ss = builtin=shadowsocks-rs, url={}, sha256={}, size={}",
        plugins.url(&route),
        flow::hex(&<sha2::Sha256 as sha2::Digest>::digest(&bytes)),
        bytes.len()
    );
    ensure!(
        !host::is_builtin_plugin("shadowsocks-rs"),
        "this case is about a client without the builtin"
    );
    // The start downloads the fixture before it listens, and hashes it twice
    // -- as it arrives, and again as the host loads it. A debug build of it on
    // Linux is over 150 MB, which on CI takes well past the usual wait.
    let client = Node::start_conf_within(
        "client",
        &client_conf(socks_port, &line, server_addr),
        socks_port,
        Duration::from_secs(60),
    )
    .await?;

    echo_tcp(client.socks_addr()?, &origin).await?;
    ensure!(
        plugins.requests(&route) == 1,
        "expected the fallback to be downloaded once"
    );

    client.shutdown().await?;
    server.shutdown().await
}

/// A builtin the client lacks, with nothing to fall back on, fails the start --
/// and the message lists what the client does have, which is the first thing
/// anyone reading it will want to know.
async fn missing_without_fallback_names_what_is_built_in() -> Result<()> {
    register_from(Fixture::ShadowsocksCabiRs, "shadowsocks-rs")?;
    no_cache_directory();
    let conf = client_conf(
        net::reserve_dual_port()?,
        "ss = builtin=not-in-this-client",
        net::loopback(9),
    );
    let error = Node::start_conf_expecting_failure("client", &conf).await?;
    ensure!(
        error.contains("[not-in-this-client]")
            && error.contains("not built with")
            && error.contains("shadowsocks-rs"),
        "unexpected error: {}",
        error
    );
    Ok(())
}

/// Being linked in buys a plugin nothing at validation: the conformance
/// plugin's wrong-major descriptor is refused as a builtin exactly as it is as
/// a library, and the error says which builtin.
async fn descriptor_is_validated_like_a_library() -> Result<()> {
    ensure!(
        std::env::var(ENV_DESCRIPTOR).as_deref() == Ok("abi-major-lower"),
        "the case did not receive its descriptor selection"
    );
    register_from(Fixture::Conformance, "conformance")?;
    no_cache_directory();
    let conf = format!(
        "[General]\nsocks-interface = 127.0.0.1\nsocks-port = {}\n\
         [Plugin]\nc = builtin=conformance\n\
         [Proxy]\nC = plugin, 127.0.0.1, 9, plugin=c\n\
         [Rule]\nFINAL, C\n",
        net::reserve_dual_port()?
    );
    let error = Node::start_conf_expecting_failure("client", &conf).await?;
    ensure!(
        error.contains("builtin:conformance") && error.contains("ABI major version"),
        "unexpected error: {}",
        error
    );
    Ok(())
}
