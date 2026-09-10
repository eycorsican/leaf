//! Ports and readiness.
//!
//! Every listener in a scenario gets a port the operating system picked, so
//! cases run concurrently without a shared port registry. Nothing in the
//! harness sleeps to wait for a node: readiness is observed, never assumed.

use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{bail, Result};
use tokio::time::{timeout_at, Instant};

/// The environment variable through which the runner gives a case child
/// process a band of ports no concurrently running case will be given.
pub const ENV_PORT_BAND: &str = "LEAF_E2E_PORT_BAND";

/// Where the bands start, and how wide each is.
///
/// Below the ephemeral range every platform this suite runs on draws from --
/// Linux from 32768, Windows from 49152 -- so a port reserved here is never
/// also handed out to somebody's outgoing connection. A case reserves a
/// listener for each node it starts and each endpoint it names, which is a
/// handful; the width is the generous version of that, because the cost of
/// getting it wrong is a case that cannot start and the cost of the space is
/// nothing.
const BAND_BASE: u16 = 20000;
const BAND_WIDTH: u16 = 96;
/// How many bands there are before one is used again. A band comes back round
/// only after this many other cases have run, by which time nothing of the
/// previous tenant's is still in TIME_WAIT.
pub const BAND_COUNT: u32 = 128;

/// Picks a loopback port that is free for both TCP and UDP.
///
/// A socks inbound listens on both, so a port that is only free for one of them
/// would fail at bind time in a way that looks like a harness bug.
///
/// Asking the operating system for port zero and then closing the socket -- the
/// obvious way to do this -- is not safe here, and the way it fails is worse
/// than a flake. Cases run as concurrent processes, and the port is not bound
/// for real until the node starts a moment later; in between, another case
/// asking for a port of its own can be handed the same one. Both then bind it,
/// one wins, and the loser's client goes on to connect to whatever the winner
/// started. That is a case talking to another case's node while reporting a
/// protocol error of its own -- which is how this was found.
///
/// So a case is given a band of its own instead, and takes ports from it by
/// binding a specific number rather than zero. Two concurrent cases cannot
/// collide because their bands do not overlap. Within a case there is no race
/// to lose: it is one process, reserving in order.
pub fn reserve_dual_port() -> Result<u16> {
    match band() {
        Some((first, last)) => reserve_in_band(first, last),
        // No band: `--in-process`, where every case shares this process and
        // there is no second process to collide with.
        None => reserve_anywhere(),
    }
}

/// The band this process was given, as an inclusive range.
fn band() -> Option<(u16, u16)> {
    let index: u32 = std::env::var(ENV_PORT_BAND).ok()?.parse().ok()?;
    let first = BAND_BASE + (index % BAND_COUNT) as u16 * BAND_WIDTH;
    Some((first, first + BAND_WIDTH - 1))
}

fn reserve_in_band(first: u16, last: u16) -> Result<u16> {
    // From a different place each time rather than always from the bottom, so
    // that a port a node has already been told about but has not bound yet is
    // not the next one offered.
    let width = u32::from(last - first) + 1;
    let start = NEXT_IN_BAND.fetch_add(1, Ordering::Relaxed) % width;
    for step in 0..width {
        let port = first + ((start + step) % width) as u16;
        if is_dual_free(port) {
            return Ok(port);
        }
    }
    bail!(
        "no port in the band {}..={} is free for both TCP and UDP; a case is reserving far more \
         than the band was sized for, or something outside the suite is using them",
        first,
        last
    )
}

/// True if nothing holds this port on either protocol.
///
/// The sockets are closed again before the caller binds for real, which is the
/// same window the band exists to make harmless: no other case can be handed
/// this port, because no other case has this band.
fn is_dual_free(port: u16) -> bool {
    let Ok(tcp) = StdTcpListener::bind(("127.0.0.1", port)) else {
        return false;
    };
    let udp = StdUdpSocket::bind(("127.0.0.1", port));
    drop(tcp);
    udp.is_ok()
}

fn reserve_anywhere() -> Result<u16> {
    for _ in 0..64 {
        let tcp = StdTcpListener::bind(("127.0.0.1", 0))?;
        let port = tcp.local_addr()?.port();
        let udp = StdUdpSocket::bind(("127.0.0.1", port));
        drop(tcp);
        if udp.is_ok() {
            drop(udp);
            return Ok(port);
        }
    }
    bail!("could not find a loopback port free for both TCP and UDP")
}

static NEXT_IN_BAND: AtomicU32 = AtomicU32::new(0);

pub fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Waits until something else holds the UDP port.
///
/// A QUIC inbound listens on UDP alone, and a datagram listener cannot be
/// probed by connecting to it. What can be observed is that the port is taken:
/// the case reserved it free a moment ago, so a bind that now fails with
/// "address in use" is the node having bound it.
pub async fn wait_udp_bound(port: u16, within: Duration) -> Result<()> {
    let deadline = Instant::now() + within;
    let mut backoff = Duration::from_millis(1);
    loop {
        match StdUdpSocket::bind(("127.0.0.1", port)) {
            Ok(socket) => drop(socket),
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => return Ok(()),
            Err(err) => bail!("probing udp port {}: {}", port, err),
        }
        if Instant::now() + backoff >= deadline {
            bail!("nothing bound udp port {} after {:?}", port, within);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_millis(25));
    }
}

/// Waits until something accepts connections at `addr`.
pub async fn wait_tcp_ready(addr: SocketAddr, within: Duration) -> Result<()> {
    let deadline = Instant::now() + within;
    let mut backoff = Duration::from_millis(1);
    loop {
        match timeout_at(deadline, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(_)) => {}
            Err(_) => bail!("nothing listening on {} after {:?}", addr, within),
        }
        if Instant::now() + backoff >= deadline {
            bail!("nothing listening on {} after {:?}", addr, within);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_millis(25));
    }
}
