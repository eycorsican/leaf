//! The kiri bridge service (feature `kiri-bridge`; kiri design §19.31): a
//! kiri WebRTC bridge (`kiri node --transport webrtc`) next to leaf's
//! runtime, whether or not the config has a `kiri` outbound.
//!
//! Whether it runs (§19.39, [`prefs::bridge_state`]): the `[Kiri]` section
//! (JSON: `kiri`) `bridge-override = off` stops it whatever the user chose;
//! else the user's choice (leaf `set_kiri_user_prefs`), else the section's
//! `bridge` (the server's default); and not while the host pauses it (e.g.
//! off Wi-Fi or off charge, the app's decision: [`BridgeService::set_paused`]).
//!
//! Started with the runtime (the user's choice is read before, so a bridge
//! the user turned off never starts), changed on reload (a changed section
//! restarts it, an unchanged one keeps it) and on every change of the user's
//! choice, stopped on shutdown: the registrar links close (the registrars
//! drop it from their next directory) and every circuit ends. Status goes to
//! leaf's log (`kiri bridge: …`, no addresses).

use std::sync::{Arc, Mutex};

use protobuf::Message;

use ::kiri::embed::{BridgeSettings, EmbeddedBridge};
use kiri_core::bridge::BridgeLimits;

use crate::config::internal;
use crate::proxy::kiri::prefs::{self, BridgeState, Prefs};

const PREFIX: &str = "kiri bridge";

pub struct BridgeService {
    rt: tokio::runtime::Handle,
    prefs: Arc<Prefs>,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// The config's `[Kiri]` section.
    section: Option<internal::Kiri>,
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
    let dir = crate::proxy::kiri::state_dir(&k.state_dir, "bridge", PREFIX);
    let mut s = BridgeSettings {
        common: crate::proxy::kiri::settings(
            &k.root_pubkeys,
            &k.signed_config,
            dir,
            k.dev.as_ref(),
            k.tls_pin_only,
            k.system_resolver,
        ),
        ..Default::default()
    };
    // quic-ice/1 next to webrtc-dtls/1 unless switched off (§19.43).
    s.common.webrtc.offer_quic_ice = !k.bridge_quic_ice_off;
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

/// The settings a running bridge depends on: the section without the
/// on/off switches (a new server default or override that leaves the
/// bridge on keeps it).
fn run_settings(k: &internal::Kiri) -> internal::Kiri {
    let mut k = k.clone();
    k.bridge = false;
    k.bridge_override_off = false;
    k
}

impl BridgeService {
    /// Must be called inside the runtime the bridge is to run on. Follows
    /// the user's choice in `prefs` (read at once: before any section is
    /// applied, so the first [`BridgeService::apply`] already has it).
    pub fn new(prefs: Arc<Prefs>) -> Arc<Self> {
        let s = Arc::new(Self {
            rt: tokio::runtime::Handle::current(),
            prefs: prefs.clone(),
            inner: Default::default(),
        });
        let weak: std::sync::Weak<dyn prefs::Listener> =
            Arc::downgrade(&s) as std::sync::Weak<Self>;
        prefs.listen(weak);
        s
    }

    /// Applies the `[Kiri]` section of a (re)loaded config.
    pub fn apply(&self, k: Option<&internal::Kiri>) {
        let mut g = self.inner.lock().unwrap();
        g.section = k.cloned();
        self.settle(&mut g);
    }

    /// Pauses (stops) or resumes the bridge the config asks for.
    pub fn set_paused(&self, paused: bool) {
        let mut g = self.inner.lock().unwrap();
        g.paused = paused;
        self.settle(&mut g);
    }

    /// Whether the bridge is wanted, and why not; `UpstreamDown` while it
    /// runs but reaches no egress (not offered to clients).
    pub fn state(&self) -> BridgeState {
        let g = self.inner.lock().unwrap();
        let s = prefs::bridge_state(g.section.as_ref(), self.prefs.bridge(), g.paused);
        let down = g.running.as_ref().is_some_and(|r| {
            r.bridge
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|b| b.stats())
                .is_some_and(|st| st.upstream_down)
        });
        if s == BridgeState::On && down {
            BridgeState::UpstreamDown
        } else {
            s
        }
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

    /// What the running bridge has carried (counts only, no addresses);
    /// `None` while none serves.
    pub fn stats(&self) -> Option<kiri_core::bridge::BridgeStats> {
        let g = self.inner.lock().unwrap();
        let r = g.running.as_ref()?;
        let b = r.bridge.lock().unwrap();
        b.as_ref()?.stats()
    }

    /// Stops the bridge (runtime shutdown).
    pub fn stop(&self) {
        let mut g = self.inner.lock().unwrap();
        g.section = None;
        g.running = None;
    }

    fn settle(&self, g: &mut Inner) {
        let state = prefs::bridge_state(g.section.as_ref(), self.prefs.bridge(), g.paused);
        let want = g
            .section
            .as_ref()
            .filter(|_| state == BridgeState::On)
            .map(run_settings);
        let keep = match (&want, &g.running) {
            (Some(w), Some(r)) => r.settings.write_to_bytes().ok() == w.write_to_bytes().ok(),
            _ => false,
        };
        if keep {
            // Only the diagnostic switch may have changed: applied in place.
            if let Some(b) = g
                .running
                .as_ref()
                .and_then(|r| r.bridge.lock().unwrap().clone())
            {
                b.set_activity_log(self.prefs.bridge_activity_log());
            }
            return;
        }
        if want.is_none() && g.running.is_some() {
            tracing::info!("{}: off ({:?})", PREFIX, state);
        }
        // The old one stops before the new one starts (same node key).
        g.running = None;
        let Some(settings) = want else { return };
        let slot: Arc<Mutex<Option<Arc<EmbeddedBridge>>>> = Default::default();
        let mut s = bridge_settings(&settings);
        s.activity_log = self.prefs.bridge_activity_log();
        let into = slot.clone();
        let prefs = self.prefs.clone();
        let starter = self.rt.spawn(async move {
            match EmbeddedBridge::start(s, crate::proxy::kiri::say(PREFIX.to_string())).await {
                Ok(b) => {
                    tracing::info!("{}: started", PREFIX);
                    let b = Arc::new(b);
                    *into.lock().unwrap() = Some(b.clone());
                    // Changed while it started: from now on `settle` finds
                    // it in the slot, so this read covers everything before.
                    b.set_activity_log(prefs.bridge_activity_log());
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

impl prefs::Listener for BridgeService {
    fn prefs_changed(self: Arc<Self>) {
        let mut g = self.inner.lock().unwrap();
        self.settle(&mut g);
    }
}
