//! Forward and backward compatibility of the kiri and standby settings.
//!
//! One conf is served to app builds of many versions at once, so a setting
//! added to it must not break an older build, nor a setting removed from the
//! code a conf that still carries it. In the `[Kiri]` section, on a `kiri`
//! outbound line, on a `standby` group line and in their JSON:
//! - an unknown key is ignored with a warning (a newer option or a typo);
//! - a bad value of a known key falls back to its default with a warning, a
//!   number out of range is clamped; only the values without which the thing
//!   cannot work at all still fail (kiri: ROOT key, signed config, bootstrap
//!   link; standby: actors);
//! - a retired key (a per-parser list) is accepted silently or read under
//!   its new name.
//!
//! Notes are collected per thread while a config is parsed (the logger is
//! not set up yet then) and land in `internal::Config::notes`; leaf logs them
//! after setting up its logger ([`log`]). Other leaf settings are parsed as
//! upstream does.

use std::cell::RefCell;

use serde::de::{DeserializeOwned, Deserializer};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::config::internal;

thread_local! {
    static NOTES: RefCell<Vec<internal::ConfigNote>> = const { RefCell::new(Vec::new()) };
}

/// What became of a retired key.
#[derive(Clone, Copy, Debug)]
pub enum Retired {
    /// No longer read: accepted and dropped.
    Dropped,
    /// Read under this name (unless that is set too, which wins).
    Renamed(&'static str),
}

/// A parser's retired keys. JSON keys may name a field of a nested object
/// (`dev.tlsPinOnly`).
pub type RetiredKeys = &'static [(&'static str, Retired)];

/// Starts collecting the notes of one config load on this thread.
pub fn begin() {
    NOTES.with(|n| n.borrow_mut().clear());
}

/// The notes collected since [`begin`].
pub fn take() -> Vec<internal::ConfigNote> {
    NOTES.with(|n| std::mem::take(&mut *n.borrow_mut()))
}

fn push(key: String, message: String, retired: bool) {
    NOTES.with(|n| {
        let mut n = n.borrow_mut();
        // Once per key.
        if n.iter().any(|x| x.key == key) {
            return;
        }
        let mut note = internal::ConfigNote::new();
        note.key = key;
        note.message = message;
        note.retired = retired;
        n.push(note);
    });
}

/// `key` of `ctx` is not known: ignored.
pub fn unknown(ctx: &str, key: &str) {
    let key = format!("{ctx} {key}");
    let message = format!("{key}: unknown setting, ignored (a newer option or a typo)");
    push(key, message, false);
}

/// `key` of `ctx` has a bad value: `fallback` is used instead.
pub fn bad(ctx: &str, key: &str, value: &str, fallback: &str) {
    let key = format!("{ctx} {key}");
    let message = format!("{key}: {value} not valid, {fallback} used");
    push(key, message, false);
}

/// `v` (unset: `default`) within `min..=max`; clamped with a note.
pub fn clamp<T: PartialOrd + Copy + std::fmt::Display>(
    ctx: &str,
    key: &str,
    v: Option<T>,
    default: T,
    min: T,
    max: T,
) -> T {
    let Some(v) = v else { return default };
    let c = if v < min {
        min
    } else if v > max {
        max
    } else {
        return v;
    };
    let key = format!("{ctx} {key}");
    let message = format!("{key}: {v} out of range, {c} used");
    push(key, message, false);
    c
}

/// The current name of `key` (with a note if it is retired), or None if it
/// is no longer read.
pub fn current(ctx: &str, key: &str, retired: RetiredKeys) -> Option<String> {
    let Some((_, r)) = retired.iter().find(|(k, _)| *k == key) else {
        return Some(key.to_string());
    };
    let note = format!("{ctx} {key}");
    match r {
        Retired::Dropped => {
            push(note.clone(), format!("{note}: retired, ignored"), true);
            None
        }
        Retired::Renamed(to) => {
            push(note.clone(), format!("{note}: retired, read as {to}"), true);
            Some(to.to_string())
        }
    }
}

/// Logs the notes of a config load: each ignored or defaulted setting as a
/// warning, retired ones at debug, then one info line naming them all so
/// version skew between a conf and the app shows in the log.
pub fn log(notes: &[internal::ConfigNote]) {
    let mut keys = vec![];
    for n in notes {
        if n.retired {
            tracing::debug!("config: {}", n.message);
        } else {
            tracing::warn!("config: {}", n.message);
            keys.push(n.key.as_str());
        }
    }
    if !keys.is_empty() {
        tracing::info!(
            "config: {} kiri/standby setting(s) ignored or defaulted: {}",
            keys.len(),
            keys.join(", ")
        );
    }
}

/// The fields of a lenient JSON object, taken one by one.
pub struct Fields {
    ctx: &'static str,
    map: Map<String, Value>,
}

impl Fields {
    pub fn new<'de, D: Deserializer<'de>>(
        d: D,
        ctx: &'static str,
        retired: RetiredKeys,
    ) -> Result<Self, D::Error> {
        let mut map = Map::<String, Value>::deserialize(d)?;
        for (old, _) in retired {
            let v = match old.split_once('.') {
                Some((obj, field)) => match map.get_mut(obj) {
                    Some(Value::Object(o)) => o.remove(field),
                    _ => None,
                },
                None => map.remove(*old),
            };
            let Some(v) = v else { continue };
            let Some(new) = current(ctx, old, retired) else {
                continue;
            };
            map.entry(new).or_insert(v);
        }
        Ok(Self { ctx, map })
    }

    /// A tunable: a bad value is noted and left unset (the default).
    pub fn opt<T: DeserializeOwned>(&mut self, key: &str) -> Option<T> {
        match self.map.remove(key)? {
            Value::Null => None,
            v => match serde_json::from_value(v.clone()) {
                Ok(t) => Some(t),
                Err(_) => {
                    bad(self.ctx, key, &v.to_string(), "the default");
                    None
                }
            },
        }
    }

    /// An essential setting: a bad value fails the load.
    pub fn need<T: DeserializeOwned, E: serde::de::Error>(
        &mut self,
        key: &str,
    ) -> Result<Option<T>, E> {
        match self.map.remove(key) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => serde_json::from_value(v)
                .map(Some)
                .map_err(|e| E::custom(format!("{} {key}: {e}", self.ctx))),
        }
    }

    /// Notes the keys left over as unknown.
    pub fn finish(self) {
        for k in self.map.keys() {
            unknown(self.ctx, k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RETIRED: RetiredKeys = &[
        ("old-knob", Retired::Dropped),
        ("old-name", Retired::Renamed("new-name")),
    ];

    /// A retired key is dropped or renamed with a retired (debug-only) note;
    /// other keys pass unchanged without one; notes are once per key.
    #[test]
    fn retired_keys_are_dropped_or_renamed() {
        begin();
        assert_eq!(current("[X]", "old-knob", RETIRED), None);
        assert_eq!(
            current("[X]", "old-name", RETIRED).as_deref(),
            Some("new-name")
        );
        assert_eq!(current("[X]", "other", RETIRED).as_deref(), Some("other"));
        unknown("[X]", "zz");
        unknown("[X]", "zz");
        let n = take();
        assert_eq!(n.len(), 3, "{n:?}");
        assert!(n[0].retired && n[0].message == "[X] old-knob: retired, ignored");
        assert!(n[1].retired && n[1].message == "[X] old-name: retired, read as new-name");
        assert!(!n[2].retired && n[2].key == "[X] zz");
        assert!(take().is_empty());
    }

    #[test]
    fn clamp_notes_only_out_of_range() {
        begin();
        assert_eq!(clamp("c", "k", None, 4, 1, 8), 4);
        assert_eq!(clamp("c", "k", Some(5), 4, 1, 8), 5);
        assert!(take().is_empty());
        assert_eq!(clamp("c", "k", Some(0), 4, 1, 8), 1);
        assert_eq!(clamp("c", "j", Some(9), 4, 1, 8), 8);
        let n = take();
        assert_eq!(n[0].message, "c k: 0 out of range, 1 used");
        assert_eq!(n[1].message, "c j: 9 out of range, 8 used");
    }
}
