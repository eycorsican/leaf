//! kiri in leaf (kiri design §19.31): the `kiri` outbound ([`outbound`],
//! feature `outbound-kiri`) is a kiri client; the bridge service
//! (`crate::app::kiri_bridge`, feature `kiri-bridge`) a kiri WebRTC bridge.
//! Both are `kiri::embed` setups, which run the same config refresh,
//! directory and telemetry machinery as the `kiri` binary.
//!
//! State: under `state-dir` (default `$ASSET_LOCATION/kiri`), one directory
//! per outbound (`client-TAG`) and one for the bridge (`bridge`), so that
//! the roles never share a last-known-good config, directory or node key.
//!
//! Logging: kiri's status lines carry no addresses and go to leaf's log at
//! info level, prefixed `kiri[TAG]` / `kiri bridge`. kiri compiles the `log`
//! crate's macros out for the whole build (S1, design §19.13): leaf's own
//! logging uses `tracing` and is unaffected.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::internal;

#[cfg(feature = "outbound-kiri")]
pub mod outbound;

/// The state directory root: `explicit`, else `$ASSET_LOCATION/kiri`.
pub fn base_state_dir(explicit: &str) -> PathBuf {
    if explicit.is_empty() {
        Path::new(&*crate::option::ASSET_LOCATION).join("kiri")
    } else {
        PathBuf::from(explicit)
    }
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
    state_dir: PathBuf,
    dev: Option<&internal::KiriDev>,
) -> ::kiri::embed::Settings {
    let mut s = ::kiri::embed::Settings {
        roots: roots
            .iter()
            .filter_map(|r| r.as_slice().try_into().ok())
            .collect(),
        signed_config: (!signed.is_empty()).then(|| signed.to_vec()),
        state_dir: Some(state_dir),
        ..Default::default()
    };
    if let Some(d) = dev {
        if !d.udp_bind.is_empty() {
            s.webrtc.udp_bind = d.udp_bind.clone();
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
