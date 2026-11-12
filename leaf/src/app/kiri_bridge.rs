//! The kiri bridge service (feature `kiri-bridge`; kiri design §19.31): a
//! kiri WebRTC bridge (`kiri node --transport webrtc`) next to leaf's
//! runtime, run when the `[Kiri]` section (JSON: `kiri`) says `bridge =
//! true`, whether or not the config has a `kiri` outbound.
//!
//! Started with the runtime, changed on reload (a changed section restarts
//! it, an unchanged one keeps it), stopped on shutdown: the registrar links
//! close (the registrars drop it from their next directory) and every
//! circuit ends. The host may pause it at any time (e.g. off Wi-Fi or off
//! charge, the app's decision): [`BridgeService::set_paused`]. Status goes to
//! leaf's log (`kiri bridge: …`, no addresses).

use std::sync::{Arc, Mutex};

use protobuf::Message;

use ::kiri::embed::{BridgeSettings, EmbeddedBridge};
use kiri_core::bridge::BridgeLimits;

use crate::config::internal;

const PREFIX: &str = "kiri bridge";

pub struct BridgeService {
    rt: tokio::runtime::Handle,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// The section in force (bridge on).
    want: Option<internal::Kiri>,
    paused: bool,
    running: Option<Running>,
}

struct Running {
    settings: internal::Kiri,
    bridge: Arc<Mutex<Option<Arc<EmbeddedBridge>>>>,
    starter: tokio::task::JoinHandle<()>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.starter.abort();
        if let Some(b) = self.bridge.lock().unwrap().take() {
            let linked = b.stop();
            tracing::info!(
                "{}: stopped ({})",
                PREFIX,
                if linked { "unlinked" } else { "was not linked" }
            );
        }
    }
}

fn bridge_settings(k: &internal::Kiri) -> BridgeSettings {
    let dir = crate::proxy::kiri::base_state_dir(&k.state_dir).join("bridge");
    let mut s = BridgeSettings {
        common: crate::proxy::kiri::settings(
            &k.root_pubkeys,
            &k.signed_config,
            dir,
            k.dev.as_ref(),
            k.tls_pin_only,
        ),
        ..Default::default()
    };
    let kib = |n: u64| (n > 0).then(|| n * 1024);
    s.limits = BridgeLimits {
        per_circuit_bps: kib(k.bridge_circuit_kbps).or(s.limits.per_circuit_bps),
        total_bps: kib(k.bridge_max_kbps),
        max_circuits: if k.bridge_max_circuits > 0 {
            k.bridge_max_circuits as usize
        } else {
            s.limits.max_circuits
        },
    };
    s
}

impl BridgeService {
    /// Must be called inside the runtime the bridge is to run on.
    pub fn new() -> Self {
        Self {
            rt: tokio::runtime::Handle::current(),
            inner: Default::default(),
        }
    }

    /// Applies the `[Kiri]` section of a (re)loaded config.
    pub fn apply(&self, k: Option<&internal::Kiri>) {
        let mut g = self.inner.lock().unwrap();
        g.want = k.filter(|k| k.bridge).cloned();
        self.settle(&mut g);
    }

    /// Pauses (stops) or resumes the bridge the config asks for.
    pub fn set_paused(&self, paused: bool) {
        let mut g = self.inner.lock().unwrap();
        g.paused = paused;
        self.settle(&mut g);
    }

    /// True while a bridge runs (started, not stopped).
    pub fn is_running(&self) -> bool {
        let g = self.inner.lock().unwrap();
        g.running.as_ref().is_some_and(|r| {
            r.bridge
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|b| !b.stopped())
        })
    }

    /// Stops the bridge (runtime shutdown).
    pub fn stop(&self) {
        let mut g = self.inner.lock().unwrap();
        g.want = None;
        g.running = None;
    }

    fn settle(&self, g: &mut Inner) {
        let want = g.want.clone().filter(|_| !g.paused);
        let keep = match (&want, &g.running) {
            (Some(w), Some(r)) => r.settings.write_to_bytes().ok() == w.write_to_bytes().ok(),
            _ => false,
        };
        if keep {
            return;
        }
        // The old one stops before the new one starts (same node key).
        g.running = None;
        let Some(settings) = want else { return };
        let slot: Arc<Mutex<Option<Arc<EmbeddedBridge>>>> = Default::default();
        let s = bridge_settings(&settings);
        let into = slot.clone();
        let starter = self.rt.spawn(async move {
            match EmbeddedBridge::start(s, crate::proxy::kiri::say(PREFIX.to_string())).await {
                Ok(b) => {
                    tracing::info!("{}: started", PREFIX);
                    *into.lock().unwrap() = Some(Arc::new(b));
                }
                Err(e) => tracing::warn!("{}: not started: {}", PREFIX, e),
            }
        });
        g.running = Some(Running {
            settings,
            bridge: slot,
            starter,
        });
    }
}

impl Default for BridgeService {
    fn default() -> Self {
        Self::new()
    }
}
