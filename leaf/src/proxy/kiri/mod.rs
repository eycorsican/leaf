//! kiri in leaf (kiri design §19.31): the `kiri` outbound ([`outbound`],
//! feature `outbound-kiri`) is a kiri client; the bridge service
//! (`crate::app::kiri_bridge`, feature `kiri-bridge`) a kiri WebRTC bridge.
//! Both are `kiri::embed` setups, which run the same config refresh,
//! directory and telemetry machinery as the `kiri` binary.
//!
//! State: under `state-dir` (else `$KIRI_STATE_DIR`, else
//! `$ASSET_LOCATION/kiri`; see [`state_dir`]), one directory
//! per outbound (`client-TAG`) and one for the bridge (`bridge`), so that
//! the roles never share a last-known-good config, directory or node key.
//!
//! Logging: kiri's status lines carry no addresses and go to leaf's log at
//! info level, prefixed `kiri[TAG]` / `kiri bridge`. kiri compiles the `log`
//! crate's macros out for the whole build (S1, design §19.13): leaf's own
//! logging uses `tracing` and is unaffected.
//!
//! Sockets: kiri's own sockets follow `OUTBOUND_INTERFACE` and, on Android,
//! leaf's protect callback, like leaf's outbound sockets ([`protect`]).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::internal;

#[cfg(feature = "outbound-kiri")]
pub mod outbound;
pub mod protect;

/// The state directory root: `explicit` (the conf's `state-dir`), else the
/// environment's `KIRI_STATE_DIR` (set by the app, so that a conf served to
/// every platform needs no local path), else `$ASSET_LOCATION/kiri`.
pub fn base_state_dir(explicit: &str) -> PathBuf {
    if !explicit.is_empty() {
        return PathBuf::from(explicit);
    }
    match std::env::var_os("KIRI_STATE_DIR") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => Path::new(&*crate::option::ASSET_LOCATION).join("kiri"),
    }
}

/// The state directory `sub` of the root (see [`base_state_dir`]) if it can
/// be created and written; else `None` with a warning, and the role runs
/// without persisted state (no last-known-good config or directory across
/// restarts: slower starts, more first fetches) instead of failing to start,
/// e.g. when the default lands in a read-only app bundle.
pub fn state_dir(explicit: &str, sub: &str, prefix: &str) -> Option<PathBuf> {
    let dir = base_state_dir(explicit).join(sub);
    match writable(&dir) {
        Ok(()) => Some(dir),
        Err(e) => {
            tracing::warn!(
                "{}: state directory not writable ({}), running without persisted state; \
                 set state-dir or KIRI_STATE_DIR",
                prefix,
                e
            );
            None
        }
    }
}

fn writable(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let probe = dir.join(".write-probe");
    std::fs::write(&probe, b"")?;
    std::fs::remove_file(&probe)
}

/// A file name for `tag`: ASCII letters, digits, `-` and `_` kept, the rest `_`.
pub fn safe_name(tag: &str) -> String {
    tag.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The kiri settings shared by a client and a bridge.
pub fn settings(
    roots: &[Vec<u8>],
    signed: &[u8],
    state_dir: Option<PathBuf>,
    dev: Option<&internal::KiriDev>,
    tls_pin_only: bool,
    system_resolver: bool,
) -> ::kiri::embed::Settings {
    let mut s = ::kiri::embed::Settings {
        roots: roots
            .iter()
            .filter_map(|r| r.as_slice().try_into().ok())
            .collect(),
        signed_config: (!signed.is_empty()).then(|| signed.to_vec()),
        state_dir,
        ..Default::default()
    };
    s.trust.pin_only = tls_pin_only;
    s.protector = protect::protector();
    // kiri's own resolver whether or not there is a protector: inside an
    // Apple NetworkExtension (no OUTBOUND_INTERFACE, no protector) the system
    // resolver may ask the tunnel's DNS, i.e. leaf's fake DNS, and STUN names
    // would come back as fake IPs. `[Kiri] resolver = system` opts out.
    s.resolver = Some(if system_resolver {
        ::kiri_core::resolve::Mode::System
    } else {
        ::kiri_core::resolve::Mode::Kiri
    });
    let addrs = protect::bind_addresses();
    if !addrs.is_empty() {
        // `OUTBOUND_INTERFACE` names addresses: kiri's WebRTC sockets bind
        // them (they come bound, past the protector's own bind).
        s.webrtc.udp_bind = addrs;
    } else if let Some(name) = protect::bind_interface() {
        // An interface name: kiri's WebRTC sockets bind only its addresses
        // (looked up per connection), not one per local address of every
        // interface (a VPN's would only be a dead ICE candidate).
        s.webrtc.udp_interface = Some(name);
    }
    if let Some(d) = dev {
        if !d.udp_bind.is_empty() {
            s.webrtc.udp_bind = d.udp_bind.clone();
            s.webrtc.udp_interface = None;
        }
        if d.webrtc_all_host_candidates {
            s.webrtc.candidates = kiri_transport_webrtc::CandidatePolicy::permissive();
        }
        s.config_fallback_urls = d.config_fallback_urls.clone();
    }
    s
}

/// kiri status lines to leaf's log.
pub fn say(prefix: String) -> ::kiri::live_config::Say {
    Arc::new(move |line| tracing::info!("{}: {}", prefix, line))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory under the system temp dir (leaf has no tempfile).
    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("leaf-kiri-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn explicit_state_dir_wins_and_is_used_when_writable() {
        let tmp = tmp("explicit");
        let root = tmp.join("kiri root");
        let root_s = root.to_str().unwrap();
        assert_eq!(base_state_dir(root_s), root);
        assert_eq!(
            state_dir(root_s, "client-x", "t"),
            Some(root.join("client-x"))
        );
        assert!(root.join("client-x").is_dir(), "created");
        assert!(
            !root.join("client-x").join(".write-probe").exists(),
            "probe removed"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn unwritable_state_dir_is_none() {
        let tmp = tmp("unwritable");
        let file = tmp.join("file");
        std::fs::write(&file, b"").unwrap();
        let bad = file.join("kiri");
        assert_eq!(state_dir(bad.to_str().unwrap(), "bridge", "t"), None);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
