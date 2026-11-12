//! The `standby` group: many outbounds of which, on a given user's network,
//! some work and some do not; the group keeps finding one that works, with
//! real connections only (never a probe of its own), quickly and with as
//! little pattern as it can. List order is preference: put the costly or
//! conspicuous one (kiri) last, used only if nothing else works.
//!
//! *Judged by data.* A path works when response bytes come back, never
//! because a connect or handshake completed (censors let TCP/TLS through
//! and then reset, stay silent, or kill the connection a little later).
//! Failures: a connect error or timeout; a stream that was written to and
//! ended (reset, close) or stayed silent for `response-timeout` before its
//! first response byte; a stream that answered and then died abnormally
//! within `early-death`. Successes: answered and closed cleanly, or ran past
//! `early-death`. A connection closed because another actor won is no
//! verdict.
//!
//! *Discovery* (no actor known up: fresh start, new network, or all down).
//! A real connection tries actors in preference order, one more every
//! `discover-stagger`, at most `max-parallel` in flight (the last actor only
//! when nothing else is). Before the first response byte the client's first
//! flight (up to [`MAX_FLIGHT`]) is buffered: a TLS ClientHello goes to every
//! connected attempt (replaying it is harmless) and the first to answer
//! wins; other traffic goes to the first connected attempt only (no
//! duplicate requests). The winner becomes current. An actor that never
//! worked on this network is down after one failure.
//!
//! *Steady state.* One current actor (the first up one) carries the traffic;
//! a connection falls to the next up actor only if the current fails to
//! connect or stalls for `stagger`, and to discovery only if none is left.
//! Actors after the current are never touched while it works; actors before
//! it are retried, at most one per real connection, raced with the current
//! at the connect stage when their (damped, jittered) retry time is due. A
//! retry that connects is on *trial* (no other connection until it answers),
//! then on *probation* (race connections plus 1 in `probation-share` new
//! ones), preferred again after `stable` without a failure; any failure on
//! trial or probation puts it straight back down. A ClientHello connection
//! whose actor fails before answering is moved once to the next actor.
//!
//! *Flap damping* (as BGP route-flap dampening). Each down transition adds 1
//! to the actor's penalty; its retry wait is `retry_min * 4^(penalty-1) *
//! 2^(failed retries)`, at most `retry_max`, then ±30 % jitter. The penalty
//! decays with `half-life`, but only over a run of good service that lasted
//! `stable`: a short recovery relaxes nothing.
//!
//! *Per-network memory.* [`Group::switch_network`] (leaf `network_changed`)
//! keeps the state of up to [`MAX_NETWORKS`] networks (LRU; by the SHA-256
//! of their id only, [`net_key`]) and switches
//! to the one named, so a known network starts with its last good actor; an
//! empty id is an unknown network: fresh state, not kept. The state (tags,
//! status, penalty, retry times: no addresses) persists in
//! `standby-TAG.state` under the group's `state-dir`, else `CACHE_LOCATION`,
//! `KIRI_STATE_DIR`, `ASSET_LOCATION` ([`state_file`]); an unwritable place
//! costs persistence only. `shuffle=true` puts the actors before the last in
//! a random order, once per device (persisted), so users do not all walk the
//! list alike.
//!
//! *UDP.* The first up actor; a send error counts as a failure.
//! *Pre-warm* (`prewarm=true`): when the actors ahead of the last failed in
//! at least half of their recent connections, the last one is asked to get
//! ready ([`OutboundStreamHandler::prewarm`]: kiri starts its client).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::Rng;
use tracing::{debug, info, warn};

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

/// The first flight kept for replay; a longer one is not replayed.
pub const MAX_FLIGHT: usize = 16 * 1024;
/// Networks whose state is kept.
pub const MAX_NETWORKS: usize = 16;

/// Recent outcomes of the actors ahead of the last, for `prewarm`.
const SAMPLES: usize = 6;
/// Fewest samples before `prewarm` judges.
const MIN_SAMPLES: usize = 3;
/// At most one pre-warm per this.
const PREWARM_EVERY: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq)]
pub struct Params {
    pub stagger: Duration,
    pub timeout: Duration,
    pub down_after: u32,
    pub retry_min: Duration,
    pub retry_max: Duration,
    pub prewarm: bool,
    pub response_timeout: Duration,
    pub early_death: Duration,
    pub half_life: Duration,
    pub stable: Duration,
    pub discover_stagger: Duration,
    pub max_parallel: usize,
    pub shuffle: bool,
    /// Where the state file goes; empty: see [`state_file`].
    pub state_dir: String,
    /// ±this share of jitter on retry times.
    pub jitter: f64,
    /// In a retry race, a retry that connects this soon after the current
    /// actor still wins: kiri, say, "connects" at once over its running
    /// session, which would otherwise beat every retry of a nearby actor.
    pub retry_grace: Duration,
    /// An actor on probation gets one in this many new connections.
    pub probation_share: u32,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            stagger: Duration::from_millis(2500),
            timeout: Duration::from_secs(10),
            down_after: 3,
            retry_min: Duration::from_secs(60),
            retry_max: Duration::from_secs(1800),
            prewarm: false,
            response_timeout: Duration::from_secs(5),
            early_death: Duration::from_secs(30),
            half_life: Duration::from_secs(15 * 60),
            stable: Duration::from_secs(10 * 60),
            discover_stagger: Duration::from_millis(400),
            max_parallel: 3,
            shuffle: false,
            state_dir: String::new(),
            jitter: 0.3,
            retry_grace: Duration::from_millis(100),
            probation_share: 4,
        }
    }
}

/// The state file of group `tag`: under `explicit` (the group's
/// `state-dir`), else `CACHE_LOCATION`, else `KIRI_STATE_DIR`, else
/// `ASSET_LOCATION`.
pub fn state_file(tag: &str, explicit: &str) -> PathBuf {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let dir = if !explicit.is_empty() {
        PathBuf::from(explicit)
    } else if !crate::option::CACHE_LOCATION.is_empty() {
        PathBuf::from(&*crate::option::CACHE_LOCATION)
    } else if let Some(d) = env("KIRI_STATE_DIR") {
        PathBuf::from(d)
    } else {
        PathBuf::from(&*crate::option::ASSET_LOCATION)
    };
    let safe: String = tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    dir.join(format!("standby-{safe}.state"))
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Status {
    /// Not tried on this network (or lost a race without a verdict).
    Unknown,
    Up,
    Down,
    /// Won a retry; on trial until response bytes (`confirmed`), then on
    /// probation until `stable` after `since` (the confirmation).
    Probation {
        since: Instant,
        confirmed: bool,
    },
}

#[derive(Clone, Debug)]
struct Health {
    status: Status,
    fails: u32,
    /// When a down (or race-losing unknown) actor is next tried.
    retry_at: Option<Instant>,
    /// Failed retries since it went down.
    retries_failed: u32,
    penalty: f64,
    /// The start of the current run of good service.
    good_since: Option<Instant>,
    /// Decay already applied up to here within that run.
    decayed_to: Option<Instant>,
    /// Probation share counter.
    share: u32,
}

impl Health {
    fn fresh() -> Self {
        Self {
            status: Status::Unknown,
            fails: 0,
            retry_at: None,
            retries_failed: 0,
            penalty: 0.0,
            good_since: None,
            decayed_to: None,
            share: 0,
        }
    }

    fn is_down(&self) -> bool {
        self.status == Status::Down
    }

    fn on_trial(&self) -> bool {
        matches!(
            self.status,
            Status::Probation {
                confirmed: false,
                ..
            }
        )
    }

    fn on_probation(&self) -> bool {
        matches!(
            self.status,
            Status::Probation {
                confirmed: true,
                ..
            }
        )
    }

    fn due(&self, now: Instant) -> bool {
        self.retry_at.is_none_or(|t| t <= now)
    }

    /// Decays the penalty over a run of good service that has lasted
    /// `stable` (the whole run, once it qualifies).
    fn decay(&mut self, now: Instant, p: &Params) {
        let Some(start) = self.good_since else { return };
        if now.saturating_duration_since(start) < p.stable {
            return;
        }
        let from = self.decayed_to.unwrap_or(start);
        let dt = now.saturating_duration_since(from).as_secs_f64();
        let hl = p.half_life.as_secs_f64().max(0.001);
        self.penalty *= 0.5f64.powf(dt / hl);
        self.decayed_to = Some(now);
    }

    fn break_run(&mut self) {
        self.good_since = None;
        self.decayed_to = None;
    }

    /// The wait before the next retry (before jitter).
    fn backoff(&self, p: &Params) -> Duration {
        let exp = (self.penalty.max(1.0) - 1.0) * 2.0 + self.retries_failed as f64;
        let secs = p.retry_min.as_secs_f64() * 2f64.powf(exp.min(60.0));
        Duration::from_secs_f64(secs.min(p.retry_max.as_secs_f64()))
    }

    fn schedule(&mut self, now: Instant, p: &Params) -> Duration {
        let w = jitter(self.backoff(p), p.jitter);
        self.retry_at = Some(now + w);
        w
    }

    fn go_down(&mut self, now: Instant, p: &Params, relapse: bool) -> Duration {
        if relapse {
            self.penalty += 1.0;
            self.retries_failed = 0;
        } else {
            self.retries_failed += 1;
        }
        self.status = Status::Down;
        self.fails = 0;
        self.schedule(now, p)
    }
}

fn jitter(d: Duration, share: f64) -> Duration {
    if share <= 0.0 {
        return d;
    }
    d.mul_f64(rand::thread_rng().gen_range(1.0 - share..=1.0 + share))
}

/// Which actors a new connection tries.
#[derive(Debug, PartialEq)]
pub struct Plan {
    /// A down actor ahead of the current whose retry is due: raced with
    /// `known[0]` from the start.
    pub retry: Option<usize>,
    /// Known-good actors: the current one first, then the other up ones
    /// (and a probation one when its share comes), one `stagger` apart.
    pub known: Vec<usize>,
    /// Discovery candidates in preference order: tried when `known` is
    /// empty, or all of it failed for this connection.
    pub explore: Vec<usize>,
    /// The actor to pre-warm now.
    pub prewarm: Option<usize>,
}

#[derive(Clone, Debug)]
struct NetState {
    actors: Vec<Health>,
}

impl NetState {
    fn fresh(n: usize) -> Self {
        Self {
            actors: vec![Health::fresh(); n],
        }
    }
}

/// The shared health state of one `standby` group.
pub struct Group {
    tag: String,
    tags: Vec<String>,
    params: Params,
    file: Option<PathBuf>,
    inner: Mutex<Inner>,
    warned: std::sync::atomic::AtomicBool,
    /// Counts network switches: a connection reports only into the state of
    /// the network it started on.
    epoch: std::sync::atomic::AtomicU64,
}

struct Inner {
    net: String,
    cur: NetState,
    /// Other networks, most recently used first.
    others: Vec<(String, NetState)>,
    /// Preference order (indices into the actors).
    pref: Vec<usize>,
    samples: VecDeque<bool>,
    prewarmed_at: Option<Instant>,
}

impl Group {
    /// A group of actors `tags`, its state loaded from `file` if given.
    pub fn new(tag: String, tags: Vec<String>, params: Params, file: Option<PathBuf>) -> Self {
        let n = tags.len();
        let mut pref: Vec<usize> = (0..n).collect();
        if params.shuffle && n > 2 {
            use rand::seq::SliceRandom;
            pref[..n - 1].shuffle(&mut rand::thread_rng());
        }
        let g = Self {
            tag,
            tags,
            params,
            file,
            inner: Mutex::new(Inner {
                net: String::new(),
                cur: NetState::fresh(n),
                others: vec![],
                pref,
                samples: VecDeque::new(),
                prewarmed_at: None,
            }),
            warned: Default::default(),
            epoch: Default::default(),
        };
        g.load();
        g
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// The current network epoch (see [`Group::switch_network`]).
    pub fn epoch(&self) -> u64 {
        self.epoch.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn params(&self) -> &Params {
        &self.params
    }

    pub fn actor_count(&self) -> usize {
        self.tags.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The last actor in preference order: started in discovery only when
    /// nothing else is in flight.
    pub fn last(&self) -> usize {
        self.tags.len().saturating_sub(1)
    }

    /// Probation actors that held `stable` are preferred again.
    fn promote(&self, g: &mut Inner, now: Instant) -> bool {
        let mut changed = false;
        for (i, h) in g.cur.actors.iter_mut().enumerate() {
            if let Status::Probation {
                since,
                confirmed: true,
            } = h.status
            {
                if now.saturating_duration_since(since) >= self.params.stable {
                    h.decay(now, &self.params);
                    h.status = Status::Up;
                    h.fails = 0;
                    h.retries_failed = 0;
                    changed = true;
                    info!(
                        "standby [{}]: [{}] up (stable for {}s)",
                        self.tag,
                        self.tags[i],
                        self.params.stable.as_secs()
                    );
                }
            }
        }
        changed
    }

    /// The actors for a new TCP connection at `now`. Claims a due retry (its
    /// next retry time moves on), so concurrent connections do not all retry.
    pub fn plan(&self, now: Instant) -> Plan {
        let mut g = self.lock();
        if self.promote(&mut g, now) {
            self.save(&g);
        }
        let pref = g.pref.clone();
        let current = pref
            .iter()
            .position(|&i| g.cur.actors[i].status == Status::Up);
        let mut known = vec![];
        for (pos, &i) in pref.iter().enumerate() {
            let h = &mut g.cur.actors[i];
            match h.status {
                Status::Up => known.push(i),
                Status::Probation {
                    confirmed: true, ..
                } => match current {
                    Some(c) if pos > c => known.push(i),
                    Some(_) => {
                        h.share += 1;
                        if h.share % self.params.probation_share.max(1) == 0 {
                            known.push(i);
                        }
                    }
                    None => known.push(i),
                },
                _ => {}
            }
        }
        let retry = match known.first() {
            Some(first) => {
                let stop = pref.iter().position(|i| i == first).unwrap_or(0);
                pref[..stop].iter().copied().find(|&i| {
                    let h = &g.cur.actors[i];
                    matches!(h.status, Status::Down | Status::Unknown)
                        && h.retry_at.is_some_and(|t| t <= now)
                })
            }
            None => None,
        };
        let explore: Vec<usize> = pref
            .iter()
            .copied()
            .filter(|i| !known.contains(i) && Some(*i) != retry)
            .filter(|&i| {
                let h = &g.cur.actors[i];
                matches!(h.status, Status::Unknown | Status::Down) && h.due(now)
            })
            .collect();
        let explore = if known.is_empty() && explore.is_empty() {
            // Nothing due: the one due soonest, rather than nothing.
            pref.iter()
                .copied()
                .filter(|&i| !g.cur.actors[i].on_trial())
                .min_by_key(|&i| g.cur.actors[i].retry_at)
                .into_iter()
                .collect()
        } else {
            explore
        };
        if let Some(i) = retry {
            g.cur.actors[i].schedule(now, &self.params);
            debug!(
                "standby [{}]: retrying [{}] with a real connection",
                self.tag, self.tags[i]
            );
        }
        let prewarm = self.want_prewarm(&mut g, &known, now);
        Plan {
            retry,
            known,
            explore,
            prewarm,
        }
    }

    /// An explore attempt on `idx` starts: a down actor's retry is claimed.
    pub fn claim(&self, idx: usize, now: Instant) {
        let mut g = self.lock();
        let h = &mut g.cur.actors[idx];
        if h.is_down() {
            h.schedule(now, &self.params);
        }
    }

    fn want_prewarm(&self, g: &mut Inner, known: &[usize], now: Instant) -> Option<usize> {
        let last = self.last();
        if !self.params.prewarm || last == 0 || known.first() == Some(&last) {
            return None;
        }
        let n = g.samples.len();
        let failed = g.samples.iter().filter(|f| **f).count();
        if n < MIN_SAMPLES || failed * 2 < n {
            return None;
        }
        if g.prewarmed_at
            .is_some_and(|t| now.duration_since(t) < PREWARM_EVERY)
        {
            return None;
        }
        g.prewarmed_at = Some(now);
        info!(
            "standby [{}]: {} of {} recent connections failed, pre-warming [{}]",
            self.tag, failed, n, self.tags[last]
        );
        Some(last)
    }

    /// The actors for a new UDP session: the up ones, else those on
    /// probation, else all, in preference order.
    pub fn udp_order(&self) -> Vec<usize> {
        let mut g = self.lock();
        self.promote(&mut g, Instant::now());
        let pick = |f: &dyn Fn(&Health) -> bool| -> Vec<usize> {
            g.pref
                .iter()
                .copied()
                .filter(|&i| f(&g.cur.actors[i]))
                .collect()
        };
        let up = pick(&|h| h.status == Status::Up);
        if !up.is_empty() {
            return up;
        }
        let prob = pick(&|h| h.on_probation());
        if !prob.is_empty() {
            return prob;
        }
        g.pref.clone()
    }

    fn sample(&self, g: &mut Inner, idx: usize, failed: bool) {
        if idx == self.last() || g.cur.actors[idx].is_down() {
            return;
        }
        if g.samples.len() == SAMPLES {
            g.samples.pop_front();
        }
        g.samples.push_back(failed);
    }

    /// Actor `idx` connected. A down one goes on trial: it carries this
    /// connection only, until it answers.
    pub fn established(&self, idx: usize, now: Instant) {
        let mut g = self.lock();
        let h = &mut g.cur.actors[idx];
        if h.is_down() {
            h.status = Status::Probation {
                since: now,
                confirmed: false,
            };
            h.retry_at = None;
            info!(
                "standby [{}]: [{}] connected, on trial until it answers",
                self.tag, self.tags[idx]
            );
        }
    }

    /// The first response byte on a connection of actor `idx`: an unknown
    /// actor is up (current, if first), one on trial on probation.
    pub fn responded(&self, idx: usize, now: Instant) {
        let mut g = self.lock();
        let h = &mut g.cur.actors[idx];
        match h.status {
            Status::Unknown => {
                h.status = Status::Up;
                h.retry_at = None;
                h.good_since.get_or_insert(now);
                info!("standby [{}]: [{}] up (answered)", self.tag, self.tags[idx]);
            }
            Status::Probation {
                confirmed: false, ..
            } => {
                h.status = Status::Probation {
                    since: now,
                    confirmed: true,
                };
                h.share = 0;
                h.good_since.get_or_insert(now);
                info!(
                    "standby [{}]: [{}] answered, on probation",
                    self.tag, self.tags[idx]
                );
            }
            _ => return,
        }
        self.save(&g);
    }

    /// A connection of actor `idx` served well (answered and closed cleanly,
    /// or ran past `early-death`).
    pub fn success(&self, idx: usize, now: Instant) {
        let mut g = self.lock();
        self.sample(&mut g, idx, false);
        let p = &self.params;
        let h = &mut g.cur.actors[idx];
        match h.status {
            Status::Down => return, // from before it went down
            Status::Unknown => {
                h.status = Status::Up;
                h.retry_at = None;
            }
            Status::Probation {
                confirmed: false, ..
            } => {
                h.status = Status::Probation {
                    since: now,
                    confirmed: true,
                };
                h.share = 0;
            }
            _ => {}
        }
        h.decay(now, p);
        h.fails = 0;
        h.good_since.get_or_insert(now);
        self.promote(&mut g, now);
        self.save(&g);
    }

    /// Actor `idx` failed at `now`. `connect`: at the connect stage, which on
    /// a down actor is a failed retry; a late stream failure on a down actor
    /// changes nothing.
    pub fn failure(&self, idx: usize, now: Instant, connect: bool, reason: &str) {
        let mut g = self.lock();
        self.sample(&mut g, idx, true);
        let p = &self.params;
        let (tag, name) = (&self.tag, &self.tags[idx]);
        let h = &mut g.cur.actors[idx];
        h.decay(now, p);
        h.break_run();
        match h.status {
            Status::Unknown => {
                let w = h.go_down(now, p, true);
                info!(
                    "standby [{}]: [{}] down ({}), retry in {}s",
                    tag,
                    name,
                    reason,
                    w.as_secs()
                );
            }
            Status::Up => {
                h.fails += 1;
                debug!(
                    "standby [{}]: [{}] failed ({}), {} of {}",
                    tag, name, reason, h.fails, p.down_after
                );
                if h.fails < p.down_after {
                    return;
                }
                let w = h.go_down(now, p, true);
                info!(
                    "standby [{}]: [{}] down after {} failures ({}), retry in {}s",
                    tag,
                    name,
                    p.down_after,
                    reason,
                    w.as_secs()
                );
            }
            Status::Probation { confirmed, .. } => {
                // On trial: a failed retry. On probation: a relapse.
                let w = h.go_down(now, p, confirmed);
                info!(
                    "standby [{}]: [{}] down again on {} ({}), retry in {}s",
                    tag,
                    name,
                    if confirmed { "probation" } else { "trial" },
                    reason,
                    w.as_secs()
                );
            }
            Status::Down => {
                if !connect {
                    return;
                }
                h.retries_failed += 1;
                let w = h.schedule(now, p);
                debug!(
                    "standby [{}]: [{}] still down ({}), next retry in {}s",
                    tag,
                    name,
                    reason,
                    w.as_secs()
                );
            }
        }
        self.save(&g);
    }

    /// A connection of actor `idx` was closed without a verdict: another
    /// actor won, or the client left before the response timeout. An
    /// unknown actor waits `retry_min` before it is tried again (it may be
    /// slow but working: no penalty); one on trial goes back down with the
    /// same wait.
    pub fn lost(&self, idx: usize, now: Instant) {
        let mut g = self.lock();
        let p = &self.params;
        let h = &mut g.cur.actors[idx];
        match h.status {
            Status::Unknown => {
                h.schedule(now, p);
            }
            Status::Probation {
                confirmed: false, ..
            } => {
                h.status = Status::Down;
                h.schedule(now, p);
            }
            _ => {}
        }
    }

    /// Switches to network `id` (empty: unknown, a fresh state that is not
    /// kept). The state of the network left is kept (up to [`MAX_NETWORKS`]).
    /// Only the id's hash is kept ([`net_key`]). Returns whether the network
    /// was known.
    pub fn switch_network(&self, id: &str) -> bool {
        let id = net_key(id);
        let id = id.as_str();
        let mut g = self.lock();
        let n = self.tags.len();
        if !id.is_empty() && id == g.net {
            return true;
        }
        let old_net = std::mem::take(&mut g.net);
        let old = std::mem::replace(&mut g.cur, NetState::fresh(n));
        if !old_net.is_empty() {
            g.others.insert(0, (old_net, old));
        }
        let mut known = false;
        if !id.is_empty() {
            if let Some(pos) = g.others.iter().position(|(k, _)| k == id) {
                g.cur = g.others.remove(pos).1;
                known = true;
            }
        }
        g.others.truncate(MAX_NETWORKS - 1);
        g.net = id.to_string();
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        g.samples.clear();
        g.prewarmed_at = None;
        info!(
            "standby [{}]: network changed ({})",
            self.tag,
            if known {
                "known network"
            } else if id.is_empty() {
                "unknown network"
            } else {
                "new network"
            }
        );
        self.save(&g);
        known
    }

    /// The status of actor `idx`.
    pub fn status(&self, idx: usize) -> Status {
        self.lock().cur.actors[idx].status
    }

    /// True while actor `idx` is down.
    pub fn is_down(&self, idx: usize) -> bool {
        self.lock().cur.actors[idx].is_down()
    }

    /// The preference order.
    pub fn pref(&self) -> Vec<usize> {
        self.lock().pref.clone()
    }

    #[cfg(test)]
    fn health(&self, idx: usize) -> Health {
        self.lock().cur.actors[idx].clone()
    }

    // State file: one line per item; tags hex-encoded, networks by their
    // key (SHA-256 of the id, hex). Unknown lines are skipped, missing or bad
    // fields take their defaults; another version (1 kept raw ids) is not
    // read: a fresh start.
    //   leaf-standby 2
    //   saved UNIX_SECS
    //   tags HEX,HEX,...
    //   pref I,I,...
    //   last NETKEY
    //   net NETKEY
    //   a STATUS(u|d|n) PENALTY RETRY_IN_SECS|- RETRIES_FAILED   (per actor)

    fn render(&self, g: &Inner, now: Instant) -> String {
        let mut out = format!(
            "{STATE_VERSION}\nsaved {}\ntags {}\npref {}\nlast {}\n",
            unix_now(),
            self.tags
                .iter()
                .map(|t| hex(t.as_bytes()))
                .collect::<Vec<_>>()
                .join(","),
            g.pref
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(","),
            g.net
        );
        let nets = std::iter::once((&g.net, &g.cur)).chain(g.others.iter().map(|(k, v)| (k, v)));
        for (k, st) in nets.filter(|(k, _)| !k.is_empty()) {
            out += &format!("net {k}\n");
            for h in &st.actors {
                let s = match h.status {
                    Status::Up => "u",
                    Status::Unknown => "n",
                    // A probation actor restarts on trial at its next retry.
                    Status::Down | Status::Probation { .. } => "d",
                };
                let retry = match (h.status, h.retry_at) {
                    (Status::Probation { .. }, _) => "0".to_string(),
                    (_, Some(t)) => t.saturating_duration_since(now).as_secs().to_string(),
                    (_, None) => "-".to_string(),
                };
                out += &format!("a {} {:.4} {} {}\n", s, h.penalty, retry, h.retries_failed);
            }
        }
        out
    }

    fn save(&self, g: &Inner) {
        let Some(file) = &self.file else { return };
        let text = self.render(g, Instant::now());
        let tmp = file.with_extension("state.tmp");
        let res = file
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|_| std::fs::write(&tmp, text))
            .and_then(|_| std::fs::rename(&tmp, file));
        if let Err(e) = res {
            if !self.warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
                warn!(
                    "standby [{}]: state not saved to {} ({}), running without persisted state",
                    self.tag,
                    file.display(),
                    e
                );
            }
        }
    }

    fn load(&self) {
        let Some(file) = &self.file else { return };
        let Ok(text) = std::fs::read_to_string(file) else {
            return;
        };
        let mut g = self.lock();
        if let Err(e) = self.parse(&mut g, &text, Instant::now()) {
            info!(
                "standby [{}]: state file not read ({}), starting fresh",
                self.tag, e
            );
        }
    }

    fn parse(&self, g: &mut Inner, text: &str, now: Instant) -> Result<(), String> {
        let mut lines = text.lines();
        match lines.next() {
            Some(STATE_VERSION) => {}
            Some(v) if v.starts_with("leaf-standby ") => {
                return Err(format!("version {}", &v[13..]));
            }
            _ => return Err("unknown format".into()),
        }
        let n = self.tags.len();
        let mut saved = unix_now();
        let mut file_tags: Vec<String> = vec![];
        let mut pref = None;
        let mut last = String::new();
        // A bad network key: its actor lines are read and dropped.
        let mut nets: Vec<(String, NetState)> = vec![];
        let mut slot = 0usize;
        let key = |v: &str| Some(v.to_string()).filter(|k| is_net_key(k));
        for line in lines {
            let (k, v) = line.split_once(' ').unwrap_or((line, ""));
            match k {
                "saved" => saved = v.parse().unwrap_or(saved),
                "tags" => {
                    file_tags = v
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(unhex)
                        .collect::<Option<_>>()
                        .unwrap_or_default()
                }
                "pref" => {
                    pref = v
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.parse().ok())
                        .collect::<Option<Vec<usize>>>()
                }
                "last" => last = key(v).unwrap_or_default(),
                "net" => {
                    nets.push((key(v).unwrap_or_default(), NetState::fresh(n)));
                    slot = 0;
                }
                "a" => {
                    let f: Vec<&str> = v.split(' ').collect();
                    let Some((_, st)) = nets.last_mut() else {
                        continue;
                    };
                    let i = slot;
                    slot += 1;
                    // Map by tag: the conf may have changed.
                    let Some(tag) = file_tags.get(i) else {
                        continue;
                    };
                    let Some(j) = self.tags.iter().position(|t| t == tag) else {
                        continue;
                    };
                    let field = |i: usize| f.get(i).copied().unwrap_or("");
                    let mut h = Health::fresh();
                    h.status = match field(0) {
                        "u" => Status::Up,
                        "d" => Status::Down,
                        _ => Status::Unknown,
                    };
                    h.penalty = field(1)
                        .parse::<f64>()
                        .ok()
                        .filter(|p| p.is_finite() && *p >= 0.0)
                        .unwrap_or(h.penalty);
                    h.retry_at = field(2).parse::<u64>().ok().map(|secs| {
                        let gone = unix_now().saturating_sub(saved);
                        now + Duration::from_secs(secs.saturating_sub(gone))
                    });
                    h.retries_failed = field(3).parse().unwrap_or(0);
                    st.actors[j] = h;
                }
                _ => {}
            }
        }
        if file_tags == self.tags {
            if let Some(p) = pref {
                let mut s = p.clone();
                s.sort();
                if s == (0..n).collect::<Vec<_>>() && p.last() == Some(&(n - 1)) {
                    g.pref = p;
                }
            }
        }
        nets.retain(|(k, _)| !k.is_empty());
        if let Some(pos) = nets.iter().position(|(k, _)| *k == last) {
            g.cur = nets.remove(pos).1;
            g.net = last;
        }
        nets.truncate(MAX_NETWORKS - 1);
        g.others = nets;
        Ok(())
    }
}

/// The first line of the state file.
const STATE_VERSION: &str = "leaf-standby 2";

/// What is kept of network id `id`: its SHA-256 in hex, so neither memory
/// nor the state file holds an SSID or a carrier name even if the app passes
/// one raw; empty stays empty (the unknown network).
pub fn net_key(id: &str) -> String {
    use sha2::{Digest, Sha256};
    if id.is_empty() {
        return String::new();
    }
    hex(&Sha256::digest(id.as_bytes()))
}

fn is_net_key(k: &str) -> bool {
    k.len() == 64 && k.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<String> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect();
    String::from_utf8(bytes?).ok()
}

#[cfg(test)]
mod tests;
