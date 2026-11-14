//! The user's kiri switches (kiri design §19.39), set by the app through
//! leaf `set_kiri_user_prefs` (FFI `leaf_kiri_set_user_prefs`), per runtime
//! id, before the runtime starts or while it runs:
//!
//! - *connect* (default on): off, every `kiri` outbound of the runtime is
//!   disabled: its client stops (sessions, config and directory refresh,
//!   telemetry) and never starts, its streams and flows end, a `standby`
//!   group skips it, and used directly its connections go to its `fallback`
//!   or are refused.
//! - *bridge*: the user's choice for the bridge service (unset: the conf's
//!   `[Kiri] bridge`, the server's default). See [`bridge_state`] for how it
//!   combines with the conf's `bridge-override = off` and the app's pause.
//!
//! The values are kept for the id across runtime restarts; a runtime reads
//! them when it starts (so a bridge switched off before the start never
//! starts) and is told of every change at once (no reload).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

lazy_static::lazy_static! {
    static ref PREFS: Mutex<HashMap<u16, Arc<Prefs>>> = Mutex::new(HashMap::new());
}

/// Told when the switches of its runtime change.
pub trait Listener: Send + Sync {
    fn prefs_changed(self: Arc<Self>);
}

pub struct Prefs {
    connect: AtomicBool,
    bridge: Mutex<Option<bool>>,
    bridge_activity_log: AtomicBool,
    listeners: Mutex<Vec<Weak<dyn Listener>>>,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            connect: AtomicBool::new(true),
            bridge: Mutex::new(None),
            bridge_activity_log: AtomicBool::new(false),
            listeners: Mutex::new(Vec::new()),
        }
    }
}

impl Prefs {
    /// The switches of runtime `rt_id` (the defaults until set).
    pub fn of(rt_id: u16) -> Arc<Self> {
        PREFS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(rt_id)
            .or_default()
            .clone()
    }

    /// Sets both switches; the runtime's outbounds and bridge follow at once.
    pub fn set(&self, connect: bool, bridge: Option<bool>) {
        self.connect.store(connect, Ordering::SeqCst);
        *self.bridge.lock().unwrap_or_else(|e| e.into_inner()) = bridge;
        self.notify();
    }

    /// The bridge's client activity lines (`kiri bridge: client offer …`,
    /// `circuit opened …`): off by default, a diagnostic the app turns on
    /// (kiri §19.41: per-session records with times, S1). Never from the
    /// conf, which the server serves.
    pub fn set_bridge_activity_log(&self, on: bool) {
        self.bridge_activity_log.store(on, Ordering::SeqCst);
        self.notify();
    }

    /// Whether the bridge logs client activity (default false).
    pub fn bridge_activity_log(&self) -> bool {
        self.bridge_activity_log.load(Ordering::SeqCst)
    }

    fn notify(&self) {
        let listeners: Vec<Arc<dyn Listener>> = self
            .listeners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for l in listeners {
            l.prefs_changed();
        }
    }

    /// The user lets kiri connect (default true).
    pub fn connect(&self) -> bool {
        self.connect.load(Ordering::SeqCst)
    }

    /// The user's bridge choice; `None`: the server's default.
    pub fn bridge(&self) -> Option<bool> {
        *self.bridge.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Registers `l` for changes (until it is dropped).
    pub fn listen(&self, l: Weak<dyn Listener>) {
        let mut g = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|w| w.strong_count() > 0);
        g.push(l);
    }
}

/// Whether the bridge runs, and why (not). Codes are leaf-ffi's
/// `LEAF_KIRI_BRIDGE_*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum BridgeState {
    /// Wanted: running, or starting (or failed to start: see the log).
    On = 0,
    /// The user turned it off.
    OffByUser = 1,
    /// The user has not chosen and the conf's `bridge` is false or unset.
    OffByServerDefault = 2,
    /// The conf's `bridge-override = off`, whatever the user chose.
    ForcedOffByServer = 3,
    /// Wanted, but paused by the app (`leaf_kiri_bridge_pause`).
    Paused = 4,
    /// Wanted, but the conf has no `[Kiri]` section with ROOT key and
    /// signed config.
    NotConfigured = 5,
    /// leaf is built without the bridge (feature `kiri-bridge`).
    NotBuilt = 6,
    /// No runtime with this id runs.
    NoRuntime = 7,
}

/// The bridge's state from the conf's `[Kiri]` section (`None`: none),
/// the user's choice and the app's pause:
/// `bridge-override = off` ?? user choice ?? `bridge`, then the pause, then
/// whether there is a ROOT key and config to run with.
pub fn bridge_state(
    section: Option<&crate::config::internal::Kiri>,
    user: Option<bool>,
    paused: bool,
) -> BridgeState {
    if !cfg!(feature = "kiri-bridge") {
        return BridgeState::NotBuilt;
    }
    let default = section.is_some_and(|k| k.bridge);
    if section.is_some_and(|k| k.bridge_override_off) {
        return BridgeState::ForcedOffByServer;
    }
    match user {
        Some(false) => return BridgeState::OffByUser,
        None if !default => return BridgeState::OffByServerDefault,
        _ => {}
    }
    if paused {
        return BridgeState::Paused;
    }
    match section {
        Some(k) if !k.root_pubkeys.is_empty() && !k.signed_config.is_empty() => BridgeState::On,
        _ => BridgeState::NotConfigured,
    }
}

#[cfg(test)]
mod tests {
    use super::BridgeState::*;
    use super::*;
    use crate::config::internal::Kiri;

    fn section(bridge: bool, override_off: bool, configured: bool) -> Kiri {
        let mut k = Kiri::new();
        k.bridge = bridge;
        k.bridge_override_off = override_off;
        if configured {
            k.root_pubkeys = vec![vec![1; 32]];
            k.signed_config = vec![1];
        }
        k
    }

    /// override(off) ?? user ?? default, then pause, then configured.
    #[test]
    #[cfg(feature = "kiri-bridge")]
    fn bridge_priority_matrix() {
        for default in [false, true] {
            for paused in [false, true] {
                for user in [None, Some(true), Some(false)] {
                    // Override off wins over everything.
                    let k = section(default, true, true);
                    assert_eq!(
                        bridge_state(Some(&k), user, paused),
                        ForcedOffByServer,
                        "{default} {user:?} {paused}"
                    );
                    let k = section(default, false, true);
                    let want = match (user, default, paused) {
                        (Some(false), _, _) => OffByUser,
                        (None, false, _) => OffByServerDefault,
                        (_, _, true) => Paused,
                        _ => On,
                    };
                    assert_eq!(
                        bridge_state(Some(&k), user, paused),
                        want,
                        "{default} {user:?} {paused}"
                    );
                }
            }
        }
        // The user turns it on over a server default of off, but there is
        // nothing to run it with.
        let k = section(false, false, false);
        assert_eq!(bridge_state(Some(&k), Some(true), false), NotConfigured);
        assert_eq!(bridge_state(None, Some(true), false), NotConfigured);
        assert_eq!(bridge_state(None, None, false), OffByServerDefault);
    }

    #[test]
    #[cfg(not(feature = "kiri-bridge"))]
    fn bridge_not_built() {
        let k = section(true, false, true);
        assert_eq!(bridge_state(Some(&k), Some(true), false), NotBuilt);
    }

    struct Count(std::sync::atomic::AtomicUsize);
    impl Listener for Count {
        fn prefs_changed(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Kept per runtime id before any runtime runs; listeners are told of
    /// every change until dropped.
    #[test]
    fn prefs_are_kept_per_id_and_told() {
        let p = Prefs::of(64001);
        assert!(p.connect());
        assert_eq!(p.bridge(), None);
        p.set(false, Some(false));
        let again = Prefs::of(64001);
        assert!(!again.connect());
        assert_eq!(again.bridge(), Some(false));
        assert!(Prefs::of(64002).connect(), "other ids keep the defaults");
        let c = Arc::new(Count(Default::default()));
        let weak: Weak<dyn Listener> = Arc::downgrade(&c) as Weak<Count>;
        again.listen(weak);
        p.set(true, None);
        p.set(true, Some(true));
        assert_eq!(c.0.load(Ordering::SeqCst), 2);
        drop(c);
        p.set(false, None); // no listener left: nothing to tell
        assert!(!Prefs::of(64001).connect());
    }
}
