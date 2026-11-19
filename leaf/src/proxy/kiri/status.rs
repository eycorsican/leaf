//! The kiri state of a runtime as JSON for the app's UI
//! (`leaf_kiri_status`, [`crate::kiri_status`]): every `kiri` outbound with
//! its client's session and paths (kiri design §19.44), and the bridge.
//!
//! Local only: it holds the bridges' addresses (the device's owner may see
//! the bridges they use) but never a destination; never logged or sent.
//! Asking costs no traffic (kiri reads counters it keeps anyway).
//!
//! Schema (version 1; numbers are JSON numbers, absent values `null`):
//!
//! ```text
//! {
//!   "version": 1,
//!   "connect": bool,                  // the user's connect switch
//!   "outbounds": [{                   // by tag
//!     "tag": str,
//!     "state": "disabled" | "not-started" | "starting" | "failed" |
//!              "idle-stopped" | "stopped" | "idle" | "connecting" | "up",
//!     "error": str | null,            // why the last start failed
//!     "egress": str | null,           // egress id in use
//!     "nat": "unknown" | "cone" | "port-restricted" | "symmetric" | null,
//!     "ipv6": bool,                   // a global IPv6 address for ICE
//!                                     // (kiri §19.48): bridges with one
//!                                     // too are reachable whatever the NATs
//!     "mode": "bridged" | "direct" | null,
//!     "sessions": int,
//!     "traffic": null | {             // payload bytes since the client
//!       "up": int, "down": int,       // started, first sends / receipts
//!       "extra_up": int,              // re-sent on another path, copies
//!       "extra_down": int             // duplicates received (dropped)
//!     },                              // (kiri status.rs "Extra traffic")
//!     "location_err": num | null,     // the client's coordinate error once
//!                                     // its paths placed it (kiri §19.46);
//!                                     // null: not placed (cold order)
//!     "trials": null | {              // nearer-bridge trials (§19.46)
//!       "tried": int,                 // trial paths judged
//!       "nearer": int,                // of those, kept in place of a slower one
//!       "skipped": int                // due, but none could be clearly nearer
//!     },
//!     "egresses": [{                  // the signed config's: those with a usable
//!       "id": str,                    // bridge first, lowest first (kiri §19.46
//!       "rtt_ms": num | null,         // "Egress choice", §19.50); estimated end
//!                                     // to end over a usable bridge; null: unknown
//!       "current": bool,              // in use now
//!       "bridges": int,               // bridges serving it this client can use
//!                                     // now; 0: choosing it cannot work yet
//!       "reached": int                // of those, the ones that worked for it
//!     }],
//!     "egress_choice": str | null,    // the user's (set_kiri_egress); null: automatic.
//!                                     // A preference: while it has no usable bridge
//!                                     // the client is on another ("egress_id")
//!     "paths": [{
//!       "session": int,               // 0: the first session
//!       "transport": str,             // "tls-direct/1", "quic-direct/1",
//!                                     // "webrtc-dtls/1", "quic-ice/1",
//!                                     // "tls-server/1" (direct)
//!       "via_bridge": bool,
//!       "peer": "IP:port" | null,     // the bridge (egress if direct) as
//!                                     // this device sees it; punched: the
//!                                     // selected remote ICE candidate
//!       "ice_local": str | null,      // "host" | "srflx" | "prflx" | "relay"
//!       "ice_remote": str | null,
//!       "bridge_id": str | null,      // directory id, 8 hex digits
//!       "detail": str | null,         // e.g. "quic bbr ice host/srflx"
//!       "hop_rtt_ms": num | null,     // to the bridge: TCP kernel srtt,
//!                                     // QUIC srtt, ICE consent-check RTT
//!       "e2e_rtt_ms": num | null,     // to the egress: session PING/PONG
//!       "e2e_rtt_min_ms": num | null,
//!       "bridge_egress_ms": num | null,     // the bridge's round trip to the
//!                                           // egress, as the directory lists it
//!       "predicted_ms": num | null,         // end to end, predicted from the
//!                                           // coordinates (§19.46): compare
//!                                           // with e2e_rtt_min_ms
//!       "rate_up": num, "rate_down": num,   // payload bytes/s, last 2 s
//!       "bytes_up": int, "bytes_down": int, // payload bytes so far
//!       "age_s": num,
//!       "state": "probation" | "up" | "retiring"
//!     }]
//!   }],
//!   "bridge": {
//!     "state": int,                   // LEAF_KIRI_BRIDGE_* (leaf_kiri_bridge_state)
//!     "running": bool,
//!     "stats": null | { "circuits": int, "opened": int, "refused_full": int,
//!       "forwarded": int, "upstream_failures": int,
//!       "upstream_down": bool,        // reaches no egress: not offered
//!       "upstream_connections": int,  // to the egresses, each many circuits
//!       "offers": int, "answered": int, "refused": int, "connected": int,
//!       "failed": int },
//!     "nat": "unknown" | "cone" | "port-restricted" | "symmetric" | null,
//!                                     // measured; null: not yet / not running
//!     "port_mapping": "pcp" | "nat-pmp" | "upnp" |  // the router maps ports:
//!                                     // reachable from any NAT (kiri §19.48)
//!                     "none" |        // no router maps
//!                     "behind_nat" |  // it maps, but has no public address
//!                     "checking" | null,  // null: not tried
//!     "ipv6": bool                    // a global IPv6 address for ICE
//!   }
//! }
//! ```

use std::fmt::Write;
use std::time::Duration;

/// One `kiri` outbound of a runtime (see the module docs for `state`).
#[derive(Clone, Debug)]
pub struct OutboundStatus {
    pub tag: String,
    /// `disabled` (the user's switch), `not-started` (no stream yet),
    /// `starting`, `failed` (its last start; `error` says why, local text),
    /// `idle-stopped` (`idle-stop`), `stopped` (config revoked), or the
    /// client's own: `idle`, `connecting`, `up`.
    pub state: &'static str,
    pub error: Option<String>,
    /// The running client's status (`None` unless it runs).
    pub client: Option<kiri_core::status::ClientStatus>,
}

/// The bridge's part (module docs).
#[derive(Clone, Debug, Default)]
pub struct BridgePart {
    /// `BridgeState` as its number (LEAF_KIRI_BRIDGE_*).
    pub state: i32,
    pub running: bool,
    pub stats: Option<kiri_core::bridge::BridgeStats>,
    /// Measured NAT class (`None`: not yet, or not running).
    pub nat: Option<&'static str>,
    /// What the gateway's port mapping does (module docs).
    pub port_mapping: Option<&'static str>,
    pub ipv6: bool,
}

/// A runtime's kiri state ([`crate::kiri_status_snapshot`]); [`to_json`]
/// is what `leaf_kiri_status` returns.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// The user's connect switch.
    pub connect: bool,
    pub outbounds: Vec<OutboundStatus>,
    pub bridge: BridgePart,
}

/// A JSON string literal.
fn jstr(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn jopt_str(out: &mut String, s: Option<&str>) {
    match s {
        Some(s) => jstr(out, s),
        None => out.push_str("null"),
    }
}

fn jnum(out: &mut String, v: f64) {
    if v.is_finite() {
        let _ = write!(out, "{}", (v * 1000.0).round() / 1000.0);
    } else {
        out.push_str("null");
    }
}

fn jms(out: &mut String, d: Option<Duration>) {
    match d {
        Some(d) => jnum(out, d.as_secs_f64() * 1000.0),
        None => out.push_str("null"),
    }
}

/// `"key":` (after a comma unless first).
fn key(out: &mut String, first: &mut bool, k: &str) {
    if !*first {
        out.push(',');
    }
    *first = false;
    jstr(out, k);
    out.push(':');
}

fn outbound(out: &mut String, o: &OutboundStatus) {
    let mut f = true;
    out.push('{');
    key(out, &mut f, "tag");
    jstr(out, &o.tag);
    key(out, &mut f, "state");
    jstr(out, o.state);
    key(out, &mut f, "error");
    jopt_str(out, o.error.as_deref());
    let c = o.client.as_ref();
    key(out, &mut f, "egress");
    jopt_str(
        out,
        c.map(|c| c.egress_id.as_str()).filter(|e| !e.is_empty()),
    );
    key(out, &mut f, "nat");
    jopt_str(out, c.and_then(|c| c.nat).map(|n| n.name()));
    key(out, &mut f, "ipv6");
    out.push_str(if c.is_some_and(|c| c.ipv6) { "true" } else { "false" });
    key(out, &mut f, "mode");
    jopt_str(
        out,
        c.and_then(|c| c.mode).map(|m| match m {
            kiri_core::PathMode::Bridged => "bridged",
            kiri_core::PathMode::Direct => "direct",
        }),
    );
    key(out, &mut f, "sessions");
    let _ = write!(out, "{}", c.map_or(0, |c| c.sessions));
    key(out, &mut f, "traffic");
    match c.map(|c| c.traffic) {
        None => out.push_str("null"),
        Some(t) => {
            let _ = write!(
                out,
                "{{\"up\":{},\"down\":{},\"extra_up\":{},\"extra_down\":{}}}",
                t.up, t.down, t.extra_up, t.extra_down
            );
        }
    }
    key(out, &mut f, "location_err");
    match c.and_then(|c| c.location_err) {
        None => out.push_str("null"),
        Some(e) => jnum(out, e),
    }
    key(out, &mut f, "trials");
    match c.map(|c| c.trials) {
        None => out.push_str("null"),
        Some(t) => {
            let _ = write!(
                out,
                "{{\"tried\":{},\"nearer\":{},\"skipped\":{}}}",
                t.tried, t.nearer, t.skipped
            );
        }
    }
    key(out, &mut f, "egresses");
    out.push('[');
    for (i, e) in c.map(|c| c.egresses.as_slice()).unwrap_or(&[]).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let mut f = true;
        out.push('{');
        key(out, &mut f, "id");
        jstr(out, &e.id);
        key(out, &mut f, "rtt_ms");
        jms(out, e.rtt);
        key(out, &mut f, "current");
        out.push_str(if e.current { "true" } else { "false" });
        key(out, &mut f, "bridges");
        out.push_str(&e.bridges.to_string());
        key(out, &mut f, "reached");
        out.push_str(&e.reached.to_string());
        out.push('}');
    }
    out.push(']');
    key(out, &mut f, "egress_choice");
    jopt_str(out, c.and_then(|c| c.egress_choice.as_deref()));
    key(out, &mut f, "paths");
    out.push('[');
    for (i, p) in c
        .map(|c| c.paths.as_slice())
        .unwrap_or(&[])
        .iter()
        .enumerate()
    {
        if i > 0 {
            out.push(',');
        }
        let mut f = true;
        out.push('{');
        key(out, &mut f, "session");
        let _ = write!(out, "{}", p.session);
        key(out, &mut f, "transport");
        jstr(out, &p.transport);
        key(out, &mut f, "via_bridge");
        out.push_str(if p.via_bridge { "true" } else { "false" });
        key(out, &mut f, "peer");
        jopt_str(out, p.peer.map(|a| a.to_string()).as_deref());
        key(out, &mut f, "ice_local");
        jopt_str(out, p.ice.as_ref().map(|i| i.0.as_str()));
        key(out, &mut f, "ice_remote");
        jopt_str(out, p.ice.as_ref().map(|i| i.1.as_str()));
        key(out, &mut f, "bridge_id");
        jopt_str(out, p.bridge_id.as_deref());
        key(out, &mut f, "detail");
        jopt_str(out, p.detail.as_deref());
        key(out, &mut f, "hop_rtt_ms");
        jms(out, p.hop_rtt);
        key(out, &mut f, "e2e_rtt_ms");
        jms(out, p.e2e_rtt);
        key(out, &mut f, "e2e_rtt_min_ms");
        jms(out, p.e2e_rtt_min);
        key(out, &mut f, "bridge_egress_ms");
        jms(out, p.bridge_egress);
        key(out, &mut f, "predicted_ms");
        jms(out, p.predicted);
        key(out, &mut f, "rate_up");
        jnum(out, p.rate_up);
        key(out, &mut f, "rate_down");
        jnum(out, p.rate_down);
        key(out, &mut f, "bytes_up");
        let _ = write!(out, "{}", p.bytes_up);
        key(out, &mut f, "bytes_down");
        let _ = write!(out, "{}", p.bytes_down);
        key(out, &mut f, "age_s");
        jnum(out, p.age.as_secs_f64());
        key(out, &mut f, "state");
        jstr(out, p.state.name());
        out.push('}');
    }
    out.push_str("]}");
}

fn bridge(out: &mut String, b: &BridgePart) {
    let mut f = true;
    out.push('{');
    key(out, &mut f, "state");
    let _ = write!(out, "{}", b.state);
    key(out, &mut f, "running");
    out.push_str(if b.running { "true" } else { "false" });
    key(out, &mut f, "stats");
    match &b.stats {
        None => out.push_str("null"),
        Some(s) => {
            let _ = write!(
                out,
                "{{\"circuits\":{},\"opened\":{},\"refused_full\":{},\"forwarded\":{},\"upstream_failures\":{},\"upstream_down\":{},\"upstream_connections\":{},\"offers\":{},\"answered\":{},\"refused\":{},\"connected\":{},\"failed\":{}}}",
                s.circuits,
                s.opened,
                s.refused_full,
                s.forwarded,
                s.upstream_failures,
                s.upstream_down,
                s.upstream_connections,
                s.signal.offers,
                s.signal.answered,
                s.signal.refused,
                s.signal.connected,
                s.signal.failed
            );
        }
    }
    key(out, &mut f, "nat");
    jopt_str(out, b.nat);
    key(out, &mut f, "port_mapping");
    jopt_str(out, b.port_mapping);
    key(out, &mut f, "ipv6");
    out.push_str(if b.ipv6 { "true" } else { "false" });
    out.push('}');
}

/// Runtime `rt_id`'s state, `bridge` given by the caller. Blocks for at
/// most about 2 s (each client is asked on the runtime its outbound runs
/// on; none answering in time: no outbounds).
pub fn snapshot(rt_id: u16, bridge: BridgePart) -> Snapshot {
    let prefs = super::prefs::Prefs::of(rt_id);
    #[cfg(feature = "outbound-kiri")]
    let outbounds = match super::outbound::runtime_of(&prefs) {
        Some(rt) => {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let p = prefs.clone();
            rt.spawn(async move {
                let _ = tx.send(super::outbound::statuses(&p).await);
            });
            rx.recv_timeout(Duration::from_secs(2)).unwrap_or_default()
        }
        None => vec![],
    };
    #[cfg(not(feature = "outbound-kiri"))]
    let outbounds = vec![];
    Snapshot {
        connect: prefs.connect(),
        outbounds,
        bridge,
    }
}

/// The JSON of `s` (module docs).
pub fn to_json(s: &Snapshot) -> String {
    let mut out = String::with_capacity(1024);
    let mut f = true;
    out.push('{');
    key(&mut out, &mut f, "version");
    out.push('1');
    key(&mut out, &mut f, "connect");
    out.push_str(if s.connect { "true" } else { "false" });
    key(&mut out, &mut f, "outbounds");
    out.push('[');
    for (i, o) in s.outbounds.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        outbound(&mut out, o);
    }
    out.push(']');
    key(&mut out, &mut f, "bridge");
    bridge(&mut out, &s.bridge);
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped() {
        let mut s = String::new();
        jstr(&mut s, "a\"b\\c\n\u{1}é");
        assert_eq!(s, r#""a\"b\\c\n\u0001é""#);
        let mut n = String::new();
        jnum(&mut n, 12.34567);
        jnum(&mut n, f64::NAN);
        assert_eq!(n, "12.346null");
    }

    /// The bridge's reachability (kiri §19.48) and the device's IPv6.
    #[test]
    fn the_bridge_says_how_reachable_it_is() {
        let s = Snapshot {
            connect: true,
            outbounds: vec![],
            bridge: BridgePart { state: 0, running: true, stats: None, nat: Some("port-restricted"), port_mapping: Some("upnp"), ipv6: true },
        };
        let j = to_json(&s);
        assert!(j.ends_with(r#""bridge":{"state":0,"running":true,"stats":null,"nat":"port-restricted","port_mapping":"upnp","ipv6":true}}"#), "{j}");
        let j = to_json(&Snapshot::default());
        assert!(j.contains(r#""nat":null,"port_mapping":null,"ipv6":false"#), "{j}");
    }
}
