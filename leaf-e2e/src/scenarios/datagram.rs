//! The datagram engine, on both kinds of transport.
//!
//! An unreliable transport hands the engine one whole frame per call. A
//! reliable one carries frames over a byte stream, so a single read can hold
//! half a frame, several frames, or a frame with keepalives around it -- and
//! `decode_packet` reports which of those happened through `consumed`. The host
//! has to act on each differently, and none of that is reachable from a test
//! that only sends well-formed, one-at-a-time datagrams.
//!
//! The shapes are produced by the peer rather than by a fault, so the engine
//! stays honest and the host is the only thing under test. Faults are reserved
//! for what the host has to refuse.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, ensure, Result};

use crate::client::{Socks5, Target, UdpSession};
use crate::conformance::ENV_DESCRIPTOR;
use crate::fixtures::Fixture;
use crate::flow;
use crate::framing::{Peer, Style};
use crate::logs;
use crate::node::{cfg, LeafNode, Node};
use crate::scenario::{boxed, Scenario, Tag};

/// A destination the peer echoes back untouched, so the reply's source address
/// is a fact about the engine's address handling rather than about routing.
/// Documentation space: nothing is ever sent there.
const DESTINATION: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7)),
    9000,
);

const VERDICT: Duration = Duration::from_secs(10);

pub fn scenarios() -> Vec<Scenario> {
    let mut scenarios = vec![
        unreliable("datagram/unreliable/roundtrip", Style::plain(), "", None),
        // A keepalive arrives as a datagram of its own: consumed, but carrying
        // nothing. The host has to drop it and keep waiting.
        unreliable(
            "datagram/unreliable/skips-keepalives",
            Style::with_keepalives(2),
            "",
            None,
        ),
        // The engine refuses the first output buffer; the host has to grow it
        // and present the same input again.
        unreliable(
            "datagram/unreliable/grows-a-small-output-buffer",
            Style::plain(),
            "dgram-fault=buffer-too-small-once",
            None,
        ),
        unreliable(
            "datagram/unreliable/clamps-absurd-hints",
            Style::plain(),
            "dgram-fault=huge-hints",
            None,
        ),
        // The engine asks for half of what it needs, in both directions: the
        // host has to notice and grow rather than give up.
        unreliable(
            "datagram/unreliable/grows-understated-buffers",
            Style::plain(),
            "dgram-fault=understated-hints",
            None,
        ),
        unreliable_failure(
            "datagram/unreliable/rejects-an-oversized-address",
            "dgram-fault=address-overrun",
            "reported a",
        ),
        unreliable_failure(
            "datagram/unreliable/rejects-a-swapped-address-buffer",
            "dgram-fault=address-pointer-swap",
            "replaced the host address buffer pointer",
        ),
        unreliable_failure(
            "datagram/unreliable/rejects-over-reported-consumed",
            "dgram-fault=overreport-consumed",
            "decode_packet consumed",
        ),
    ];

    // A datagram decoded into more than the receiver can hold is a lost packet,
    // not a lost session: a server that could end the session with one reply
    // would be a denial of service wearing a bug's clothes.
    scenarios.push(
        Scenario::new(
            "datagram/unreliable/drops-an-oversized-payload",
            "datagram",
            || boxed(unreliable_oversize_payload_is_dropped()),
        )
        .tags([Tag::Plugin, Tag::Hostile])
        .needs([Fixture::Conformance])
        .env(ENV_DESCRIPTOR, "datagram-unreliable")
        .timeout(Duration::from_secs(45)),
    );

    // A plugin with no stream engine at all. The ABI allows it -- a UDP-only
    // protocol has nothing to put in a stream vtable -- and the UDP path never
    // asks the handler for a stream, so such an outbound has to start and
    // carry datagrams like any other.
    scenarios.push(
        Scenario::new("datagram/unreliable/datagram-only-plugin", "datagram", || {
            boxed(datagram_only_roundtrip())
        })
        .tags([Tag::Plugin])
        .needs([Fixture::Conformance])
        .env(ENV_DESCRIPTOR, "datagram-only")
        .timeout(Duration::from_secs(45)),
    );

    scenarios.extend([
        reliable("datagram/reliable/roundtrip", Style::plain()),
        // A byte at a time to begin with, so every frame arrives as a run of
        // partial frames the host has to hold on to.
        reliable(
            "datagram/reliable/reassembles-split-frames",
            Style::dribbled(),
        ),
        // Several frames in one read, which the host has to take one at a
        // time. The peer holds replies back until three have accumulated, so
        // this one sends all three before reading any.
        Scenario::new(
            "datagram/reliable/handles-several-frames-in-one-read",
            "datagram",
            || boxed(reliable_pipelined()),
        )
        .tags([Tag::Plugin])
        .needs([Fixture::Conformance])
        .env(ENV_DESCRIPTOR, "datagram-reliable")
        .timeout(Duration::from_secs(45)),
        reliable(
            "datagram/reliable/skips-keepalives",
            Style::with_keepalives(2),
        ),
        // A frame that never completes has to stop somewhere: the host cannot
        // reassemble without limit.
        Scenario::new(
            "datagram/reliable/bounds-a-frame-that-never-completes",
            "datagram",
            || boxed(reliable_never_completes()),
        )
        .tags([Tag::Plugin, Tag::Hostile])
        .needs([Fixture::Conformance])
        .env(ENV_DESCRIPTOR, "datagram-reliable")
        .timeout(Duration::from_secs(60)),
    ]);

    scenarios
}

fn unreliable(id: &'static str, style: Style, args: &'static str, _unused: Option<()>) -> Scenario {
    Scenario::new(id, "datagram", move || {
        boxed(unreliable_roundtrip(style, args))
    })
    .tags([Tag::Plugin])
    .needs([Fixture::Conformance])
    .env(ENV_DESCRIPTOR, "datagram-unreliable")
    .timeout(Duration::from_secs(45))
}

fn unreliable_failure(id: &'static str, args: &'static str, reported: &'static str) -> Scenario {
    Scenario::new(id, "datagram", move || {
        boxed(unreliable_rejected(args, reported))
    })
    .tags([Tag::Plugin, Tag::Hostile])
    .needs([Fixture::Conformance])
    .env(ENV_DESCRIPTOR, "datagram-unreliable")
    .timeout(Duration::from_secs(45))
}

fn reliable(id: &'static str, style: Style) -> Scenario {
    Scenario::new(id, "datagram", move || boxed(reliable_roundtrip(style)))
        .tags([Tag::Plugin])
        .needs([Fixture::Conformance])
        .env(ENV_DESCRIPTOR, "datagram-reliable")
        .timeout(Duration::from_secs(45))
}

/// `socks -> conformance datagram engine -> framed udp peer`
async fn start_unreliable(peer: SocketAddr, args: &str) -> Result<LeafNode> {
    Node::new("client")
        .socks_inbound()?
        .outbound(cfg::plugin(
            "conformance",
            &Fixture::Conformance.path()?,
            Some(peer),
            args,
        ))
        .start()
        .await
}

/// `socks -> chain[conformance stream, conformance datagram] -> framed tcp peer`
///
/// Two tags on one library: the first is used for its stream engine, which
/// carries the second's frames. That is the shape a reliable datagram engine
/// is deployed in -- it never opens its own connection.
async fn start_reliable(peer: SocketAddr) -> Result<LeafNode> {
    let path = Fixture::Conformance.path()?;
    Node::new("client")
        .socks_inbound()?
        .outbound(cfg::chain("chain-out", &["carrier", "frames"]))
        .outbound(cfg::plugin("carrier", &path, Some(peer), ""))
        .outbound(cfg::plugin("frames", &path, Some(peer), ""))
        .start()
        .await
}

async fn exchange(session: &UdpSession, payload: &[u8], target: &Target) -> Result<()> {
    session.send_to(payload, target.clone()).await?;
    let mut buf = vec![0u8; 64 * 1024];
    let (n, source) = tokio::time::timeout(VERDICT, session.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("no reply to a {} byte datagram", payload.len()))??;
    ensure!(
        buf[..n] == payload[..],
        "a {} byte datagram came back as {} bytes",
        payload.len(),
        n
    );
    ensure!(
        &source == target,
        "the reply claimed to come from {:?}, not {:?}",
        source,
        target
    );
    Ok(())
}

/// Datagrams of growing size, so a framing mistake shows up as one specific
/// size going missing.
async fn drive(socks: Socks5) -> Result<()> {
    let session = socks.udp_associate().await?;
    let target = Target::Ip(DESTINATION);
    for (index, size) in [1usize, 64, 1200].into_iter().enumerate() {
        let payload = flow::pseudo_random(size, 0xda7a + index as u64);
        exchange(&session, &payload, &target).await?;
    }
    Ok(())
}

/// The same exchange as `unreliable_roundtrip`, over a plugin whose descriptor
/// exports a datagram engine and no stream engine.
async fn datagram_only_roundtrip() -> Result<()> {
    let peer = Peer::udp_echo(Style::plain()).await?;
    let node = start_unreliable(peer.addr(), "").await?;
    drive(Socks5::new(node.socks_addr()?)).await?;
    node.shutdown().await
}

async fn unreliable_roundtrip(style: Style, args: &'static str) -> Result<()> {
    let peer = Peer::udp_echo(style).await?;
    let node = start_unreliable(peer.addr(), args).await?;
    drive(Socks5::new(node.socks_addr()?)).await?;
    node.shutdown().await
}

/// The first reply decodes into a megabyte, which no caller's buffer holds.
/// The host has to drop that one and keep the session, so the datagram after
/// it comes back as usual.
async fn unreliable_oversize_payload_is_dropped() -> Result<()> {
    let peer = Peer::udp_echo(Style::plain()).await?;
    let node = start_unreliable(peer.addr(), "dgram-fault=oversize-payload-once").await?;
    let socks = Socks5::new(node.socks_addr()?);
    let session = socks.udp_associate().await?;
    let target = Target::Ip(DESTINATION);

    // Echoed, decoded into more than can be delivered, and dropped.
    session.send_to(b"too-big-once", target.clone()).await?;

    let payload = flow::pseudo_random(512, 0x0f5e);
    exchange(&session, &payload, &target).await?;
    node.shutdown().await
}

/// The host has to refuse the frame and say why, rather than trust it.
async fn unreliable_rejected(args: &'static str, reported: &'static str) -> Result<()> {
    let peer = Peer::udp_echo(Style::plain()).await?;
    let node = start_unreliable(peer.addr(), args).await?;
    let socks = Socks5::new(node.socks_addr()?);

    let session = socks.udp_associate().await?;
    session.send_to(b"hello", Target::Ip(DESTINATION)).await?;

    let mut buf = vec![0u8; 4096];
    if let Ok(Ok((n, _))) =
        tokio::time::timeout(Duration::from_secs(3), session.recv_from(&mut buf)).await
    {
        bail!(
            "the host delivered {} bytes from a reply it should have refused",
            n
        );
    }
    logs::wait_for(reported, VERDICT).await?;

    node.shutdown().await
}

/// Sends everything before reading anything, so the peer can answer in one
/// write and the host meets several frames in a single read.
async fn drive_pipelined(socks: Socks5, count: usize) -> Result<()> {
    let session = socks.udp_associate().await?;
    let target = Target::Ip(DESTINATION);
    let sent: Vec<Vec<u8>> = (0..count)
        .map(|index| flow::pseudo_random(200 + index * 100, 0xba7c + index as u64))
        .collect();
    for payload in &sent {
        session.send_to(payload, target.clone()).await?;
    }

    let mut outstanding = sent.clone();
    for _ in 0..count {
        let mut buf = vec![0u8; 64 * 1024];
        let (n, source) = tokio::time::timeout(VERDICT, session.recv_from(&mut buf))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "only {} of {} replies arrived",
                    count - outstanding.len(),
                    count
                )
            })??;
        ensure!(
            source == target,
            "a reply claimed to come from {:?}, not {:?}",
            source,
            target
        );
        match outstanding
            .iter()
            .position(|payload| payload[..] == buf[..n])
        {
            Some(index) => {
                outstanding.remove(index);
            }
            None => bail!("a reply of {} bytes matched nothing that was sent", n),
        }
    }
    Ok(())
}

async fn reliable_pipelined() -> Result<()> {
    const FRAMES: usize = 3;
    let peer = Peer::tcp_echo(Style::batched(FRAMES)).await?;
    let node = start_reliable(peer.addr()).await?;
    drive_pipelined(Socks5::new(node.socks_addr()?), FRAMES).await?;
    node.shutdown().await
}

/// The engine reports every frame as incomplete, so the bytes the peer sends
/// pile up in the host's reassembly buffer. It has to give up and say so.
async fn reliable_never_completes() -> Result<()> {
    // Comfortably past what the host is willing to hold for one frame, in
    // datagrams small enough that none is dropped on the way in.
    const DATAGRAMS: usize = 600;
    const SIZE: usize = 1200;

    let peer = Peer::tcp_echo(Style::plain()).await?;
    let path = Fixture::Conformance.path()?;
    let node = Node::new("client")
        .socks_inbound()?
        .outbound(cfg::chain("chain-out", &["carrier", "frames"]))
        .outbound(cfg::plugin("carrier", &path, Some(peer.addr()), ""))
        .outbound(cfg::plugin(
            "frames",
            &path,
            Some(peer.addr()),
            "dgram-fault=never-completes",
        ))
        .start()
        .await?;

    let session = Socks5::new(node.socks_addr()?).udp_associate().await?;
    let payload = flow::pseudo_random(SIZE, 0x1ec0);
    for index in 0..DATAGRAMS {
        // The send direction works, so the peer echoes and the replies
        // accumulate on the side the engine will never finish decoding.
        session.send_to(&payload, Target::Ip(DESTINATION)).await?;
        if index % 16 == 15 {
            // Room for the other side to keep up, so the datagrams are not
            // simply dropped at the inbound. A yield is not enough: this is a
            // burst into one socket's receive buffer, and what drains that is
            // the node getting a turn on another thread, not this task
            // re-queueing itself. Windows delivered under a fifth of the burst
            // when the pause was a yield, which left the pending frame at half
            // the bound this case exists to reach -- passing or failing on how
            // the machine happened to schedule it.
            tokio::time::sleep(Duration::from_micros(200)).await;
        }
    }

    logs::wait_for("without completing", VERDICT).await?;
    node.shutdown().await
}

async fn reliable_roundtrip(style: Style) -> Result<()> {
    let peer = Peer::tcp_echo(style).await?;
    let node = start_reliable(peer.addr()).await?;
    drive(Socks5::new(node.socks_addr()?)).await?;
    node.shutdown().await
}
