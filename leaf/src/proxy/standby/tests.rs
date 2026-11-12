use super::*;

fn params() -> Params {
    Params {
        jitter: 0.0,
        ..Default::default()
    }
}

fn group_with(n: usize, p: Params, file: Option<PathBuf>) -> Group {
    Group::new(
        "G".into(),
        (0..n).map(|i| format!("a{i}")).collect(),
        p,
        file,
    )
}

fn group(n: usize, prewarm: bool) -> Group {
    group_with(
        n,
        Params {
            prewarm,
            ..params()
        },
        None,
    )
}

/// Every actor answered once: all up.
fn all_up(g: &Group, t: Instant) {
    for i in 0..g.actor_count() {
        g.responded(i, t);
    }
}

fn fail(g: &Group, idx: usize, now: Instant, times: u32) {
    for _ in 0..times {
        g.failure(idx, now, true, "test");
    }
}

fn secs(d: Duration) -> u64 {
    d.as_secs_f64().round() as u64
}

/// Lets down actor `idx`'s due retry win: on trial at the returned time.
fn retry_wins(g: &Group, idx: usize) -> Instant {
    let t = g.health(idx).retry_at.expect("retry time");
    assert_eq!(g.plan(t).retry, Some(idx), "retry due");
    g.established(idx, t);
    t
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("leaf-standby-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_fresh_group_discovers_in_preference_order() {
    let g = group(4, false);
    let t = Instant::now();
    let p = g.plan(t);
    assert_eq!(
        (p.known, p.explore, p.retry),
        (vec![], vec![0, 1, 2, 3], None)
    );
    // a1 answers first: current. Steady: a1 only; a0 (lost the race, no
    // verdict) waits retry_min, then is retried; a2, a3 never touched.
    g.lost(0, t);
    g.responded(1, t);
    g.lost(2, t);
    let p = g.plan(t);
    assert_eq!((p.known, p.retry), (vec![1], None));
    assert_eq!(p.explore, vec![3], "a2 waits, a3 is only for when a1 fails");
    let p = g.plan(t + Duration::from_secs(60));
    assert_eq!(
        p.retry,
        Some(0),
        "the slow-but-working a0 is retried, unpenalised"
    );
    assert_eq!(g.status(0), Status::Unknown);
    assert_eq!(g.health(0).penalty, 0.0);
}

#[test]
fn unknown_is_down_after_one_failure_up_after_down_after() {
    let g = group(3, false);
    let t = Instant::now();
    fail(&g, 0, t, 1);
    assert!(g.is_down(0), "never worked here: one strike");
    g.responded(1, t);
    fail(&g, 1, t, 2);
    assert!(!g.is_down(1));
    g.success(1, t);
    fail(&g, 1, t, 2);
    assert!(!g.is_down(1), "a success reset the count");
    fail(&g, 1, t, 1);
    assert!(g.is_down(1));
}

#[test]
fn failed_retries_double_the_wait_up_to_the_cap() {
    let g = group(2, false);
    let mut t = Instant::now();
    all_up(&g, t);
    fail(&g, 0, t, 3);
    let mut waits = vec![];
    for _ in 0..8 {
        let at = g.health(0).retry_at.unwrap();
        waits.push(secs(at - t));
        assert_eq!(g.plan(at - Duration::from_millis(1)).retry, None);
        t = at;
        let p = g.plan(t);
        assert_eq!((p.retry, p.known), (Some(0), vec![1]));
        assert_eq!(g.plan(t).retry, None, "claimed");
        g.failure(0, t, true, "retry failed");
    }
    // The first wait is set when it went down; then each claimed retry
    // moves on by the then-current wait before the failure doubles it.
    assert_eq!(waits, vec![60, 120, 240, 480, 960, 1800, 1800, 1800]);
    let before = g.health(0).retry_at;
    g.failure(0, t, false, "late");
    assert_eq!(
        g.health(0).retry_at,
        before,
        "a late stream failure changes nothing"
    );
}

#[test]
fn retry_times_are_jittered_by_thirty_percent() {
    let g = group_with(2, Params::default(), None);
    let t = Instant::now();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..20 {
        g.responded(0, t);
        g.failure(0, t, true, "x");
        g.failure(0, t, true, "x");
        g.failure(0, t, true, "x");
        let w = g.health(0).retry_at.unwrap() - t;
        let base = g.health(0).backoff(&g.params).as_secs_f64();
        assert!(w.as_secs_f64() >= base * 0.7 - 1e-6 && w.as_secs_f64() <= base * 1.3 + 1e-6);
        seen.insert(w.as_millis());
        g.switch_network("");
    }
    assert!(seen.len() > 10, "not random: {seen:?}");
}

#[test]
fn a_retry_that_connects_is_on_trial_until_it_answers() {
    let g = group(2, false);
    let t0 = Instant::now();
    all_up(&g, t0);
    fail(&g, 0, t0, 3);
    let t = retry_wins(&g, 0);
    assert!(matches!(
        g.status(0),
        Status::Probation {
            confirmed: false,
            ..
        }
    ));
    for _ in 0..8 {
        let p = g.plan(t);
        assert_eq!((p.known, p.retry), (vec![1], None), "no share on trial");
    }
    g.failure(0, t, false, "no response");
    assert!(g.is_down(0));
    assert_eq!(secs(g.health(0).backoff(&g.params)), 120, "a failed retry");
    assert!(
        (g.health(0).penalty - 1.0).abs() < 1e-9,
        "no penalty for a trial"
    );
    let t = retry_wins(&g, 0);
    g.lost(0, t);
    assert!(g.is_down(0));
    assert_eq!(
        secs(g.health(0).backoff(&g.params)),
        120,
        "no verdict: same wait"
    );
}

#[test]
fn probation_gets_a_share_then_is_preferred_after_stable() {
    let g = group(2, false);
    let t0 = Instant::now();
    all_up(&g, t0);
    fail(&g, 0, t0, 3);
    let t = retry_wins(&g, 0);
    g.responded(0, t);
    let firsts: Vec<usize> = (0..8).map(|_| g.plan(t).known[0]).collect();
    assert_eq!(
        firsts.iter().filter(|&&i| i == 0).count(),
        2,
        "1 in 4: {firsts:?}"
    );
    g.success(0, t);
    assert!(g.status(0) != Status::Up);
    assert_eq!(g.plan(t + Duration::from_secs(600)).known, vec![0, 1]);
    assert_eq!(g.status(0), Status::Up);
}

/// `probation-share` sets the share (before: the constant 4).
#[test]
fn probation_share_is_a_setting() {
    let p = Params {
        probation_share: 2,
        ..params()
    };
    let g = group_with(2, p, None);
    let t0 = Instant::now();
    all_up(&g, t0);
    fail(&g, 0, t0, 3);
    let t = retry_wins(&g, 0);
    g.responded(0, t);
    let firsts: Vec<usize> = (0..8).map(|_| g.plan(t).known[0]).collect();
    assert_eq!(
        firsts.iter().filter(|&&i| i == 0).count(),
        4,
        "1 in 2: {firsts:?}"
    );
}

#[test]
fn flapping_grows_the_wait_and_a_short_recovery_relaxes_nothing() {
    let g = group(2, false);
    let t0 = Instant::now();
    all_up(&g, t0);
    fail(&g, 0, t0, 3);
    let mut waits = vec![secs(g.health(0).backoff(&g.params))];
    for _ in 0..4 {
        let t = retry_wins(&g, 0);
        g.responded(0, t);
        let t = t + Duration::from_secs(60);
        g.success(0, t);
        g.failure(0, t, false, "reset mid-stream");
        assert!(g.is_down(0), "a relapse on probation is down at once");
        waits.push(secs(g.health(0).backoff(&g.params)));
    }
    assert_eq!(waits, vec![60, 240, 960, 1800, 1800]);
}

#[test]
fn sustained_good_service_decays_the_penalty() {
    let g = group(2, false);
    let t0 = Instant::now();
    all_up(&g, t0);
    fail(&g, 0, t0, 3);
    for _ in 0..2 {
        let t = retry_wins(&g, 0);
        g.responded(0, t);
        g.failure(0, t, false, "x");
    }
    assert!((g.health(0).penalty - 3.0).abs() < 1e-9);
    let start = retry_wins(&g, 0);
    g.responded(0, start);
    g.success(0, start + Duration::from_secs(300));
    assert!((g.health(0).penalty - 3.0).abs() < 1e-9, "not stable yet");
    g.success(0, start + Duration::from_secs(900));
    assert_eq!(g.status(0), Status::Up);
    assert!(
        (g.health(0).penalty - 1.5).abs() < 1e-6,
        "{}",
        g.health(0).penalty
    );
    let t = start + Duration::from_secs(2700);
    g.success(0, t);
    assert!((g.health(0).penalty - 0.375).abs() < 1e-6);
    fail(&g, 0, t, 3);
    assert!(g.health(0).backoff(&g.params) < Duration::from_secs(120));
    let p = g.health(0).penalty;
    g.failure(0, t + Duration::from_secs(5000), true, "x");
    assert!(
        (g.health(0).penalty - p).abs() < 1e-9,
        "no decay without a new run"
    );
}

#[test]
fn only_actors_ahead_of_the_current_are_retried() {
    let g = group(3, false);
    let t = Instant::now();
    all_up(&g, t);
    fail(&g, 2, t, 3);
    let late = t + Duration::from_secs(4000);
    let p = g.plan(late);
    assert_eq!(
        (p.retry, p.known.clone()),
        (None, vec![0, 1]),
        "a2 is behind the current"
    );
    fail(&g, 0, t, 3);
    let p = g.plan(late);
    assert_eq!((p.retry, p.known), (Some(0), vec![1]));
}

#[test]
fn discovery_skips_actors_not_due_and_falls_back_to_the_soonest() {
    let g = group(3, false);
    let t = Instant::now();
    fail(&g, 0, t, 1);
    fail(&g, 1, t, 1);
    let p = g.plan(t);
    assert_eq!((p.known, p.explore), (vec![], vec![2]));
    fail(&g, 2, t + Duration::from_secs(1), 1);
    let p = g.plan(t + Duration::from_secs(2));
    assert_eq!(p.explore.len(), 1, "nothing due: the soonest only");
    assert_eq!(p.explore, vec![0]);
    let p = g.plan(t + Duration::from_secs(61));
    assert_eq!(p.explore, vec![0, 1, 2], "all due again");
}

#[test]
fn networks_keep_their_own_state_lru() {
    let g = group(3, false);
    let t = Instant::now();
    assert!(!g.switch_network("A"));
    g.responded(0, t);
    assert!(!g.switch_network("B"));
    assert_eq!(g.plan(t).known, Vec::<usize>::new(), "B starts cold");
    fail(&g, 0, t, 1);
    g.responded(1, t);
    assert!(g.switch_network("A"));
    assert_eq!(
        g.plan(t).known,
        vec![0],
        "A remembered: a0 first, no discovery"
    );
    assert!(g.switch_network("B"));
    assert_eq!(g.plan(t).known, vec![1]);
    // Unknown network: fresh, not kept.
    assert!(!g.switch_network(""));
    assert_eq!(g.plan(t).known, Vec::<usize>::new());
    g.responded(2, t);
    assert!(!g.switch_network(""));
    assert_eq!(
        g.plan(t).known,
        Vec::<usize>::new(),
        "the unknown network was not kept"
    );
    // At most 16 networks.
    for i in 0..20 {
        g.switch_network(&format!("n{i}"));
    }
    assert!(!g.switch_network("A"), "A was evicted");
}

#[test]
fn state_persists_across_restarts_and_unwritable_is_tolerated() {
    let dir = tmp("persist");
    let file = dir.join("standby-G.state");
    let p = Params {
        shuffle: true,
        ..params()
    };
    let g = group_with(6, p.clone(), Some(file.clone()));
    let t = Instant::now();
    g.switch_network("home");
    fail(&g, 0, t, 1);
    g.responded(1, t);
    g.switch_network("cafe");
    g.responded(2, t);
    let pref = g.pref();
    assert_eq!(pref[5], 5, "the last actor stays last");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains("home"), "ids are hex-encoded");
    drop(g);
    // Restart: the last network (cafe) warm, home remembered, same order.
    let g = group_with(6, p.clone(), Some(file.clone()));
    assert_eq!(g.pref(), pref, "shuffle persisted");
    assert_eq!(g.plan(t).known, vec![2]);
    assert!(g.switch_network("home"));
    assert_eq!(g.status(0), Status::Down);
    assert!(g.health(0).retry_at.is_some());
    assert_eq!(g.plan(Instant::now()).known, vec![1]);
    // A changed conf: states map by tag, the order is drawn again.
    let g = Group::new(
        "G".into(),
        ["a1", "x", "a0", "a5"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        params(),
        Some(file.clone()),
    );
    g.switch_network("home");
    assert_eq!((g.status(0), g.status(2)), (Status::Up, Status::Down));
    assert_eq!(g.status(1), Status::Unknown);
    // Unwritable: works without persistence.
    let bad = dir.join("file");
    std::fs::write(&bad, b"").unwrap();
    let g = group_with(2, params(), Some(bad.join("standby-G.state")));
    g.switch_network("x");
    g.responded(0, t);
    assert_eq!(g.plan(t).known, vec![0]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn prewarm_when_half_of_the_recent_connections_failed() {
    let g = group(3, true);
    let t = Instant::now();
    all_up(&g, t);
    g.success(0, t);
    g.failure(0, t, false, "x");
    assert_eq!(g.plan(t).prewarm, None, "too few samples");
    g.success(1, t);
    g.failure(1, t, false, "x");
    g.success(2, t);
    assert_eq!(g.plan(t).prewarm, Some(2), "2 of 4 failed");
    assert_eq!(g.plan(t).prewarm, None, "once a minute");
    assert_eq!(g.plan(t + PREWARM_EVERY).prewarm, Some(2));
    let g = group(3, true);
    all_up(&g, t);
    for _ in 0..4 {
        g.success(0, t);
    }
    g.failure(0, t, false, "x");
    assert_eq!(g.plan(t).prewarm, None, "mostly good");
    let g = group(3, false);
    all_up(&g, t);
    fail(&g, 1, t, 2);
    g.failure(0, t, false, "x");
    assert_eq!(g.plan(t).prewarm, None, "off unless asked for");
}

/// Network ids are kept as their SHA-256 only: the state file holds neither
/// the raw id nor its hex encoding (before: hex of the raw id), and the same
/// raw id finds its state again after a restart.
#[test]
fn network_ids_are_hashed_and_found_again_after_restart() {
    let dir = tmp("hashed");
    let file = dir.join("standby-G.state");
    let g = group_with(3, params(), Some(file.clone()));
    let t = Instant::now();
    g.switch_network("Home WiFi");
    g.responded(1, t);
    g.switch_network("");
    g.responded(2, t);
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.starts_with("leaf-standby 2\n"), "{text}");
    assert!(
        !text.contains("Home WiFi") && !text.contains(&hex(b"Home WiFi")),
        "{text}"
    );
    assert!(
        text.contains(&format!("net {}\n", net_key("Home WiFi"))),
        "{text}"
    );
    assert_eq!(net_key("Home WiFi").len(), 64);
    assert_eq!(net_key(""), "", "empty stays the unknown network");
    drop(g);
    let g = group_with(3, params(), Some(file.clone()));
    assert!(g.switch_network("Home WiFi"), "same raw id, same state");
    assert_eq!(g.plan(t).known, vec![1]);
    assert!(!g.switch_network("Home Wifi"), "another id");
    let _ = std::fs::remove_dir_all(&dir);
}

/// An old (version 1, raw ids hex-encoded) or unknown-version state file is
/// not read: a fresh start, no crash, and the next save writes version 2.
/// A version-2 file with unknown lines, extra or missing fields and bad
/// values is read for what it holds (before: any bad line dropped the file).
#[test]
fn old_or_unknown_state_files_start_fresh_and_v2_is_tolerant() {
    let dir = tmp("versions");
    let file = dir.join("standby-G.state");
    let tags = "6130,6131,6132";
    for text in [
        format!("leaf-standby 1\nsaved 1\ntags {tags}\npref 0,1,2\nlast {h}\nnet {h}\na u 0 - 0\na d 1 5 0\na n 0 - 0\n", h = hex(b"home")),
        "leaf-standby 9\nwhatever\n".to_string(),
        "garbage".to_string(),
        String::new(),
    ] {
        std::fs::write(&file, &text).unwrap();
        let g = group_with(3, params(), Some(file.clone()));
        let t = Instant::now();
        assert_eq!(g.plan(t).known, Vec::<usize>::new(), "{text:?}: not fresh");
        assert!(!g.switch_network("home"), "{text:?}");
        g.responded(0, t);
        assert!(std::fs::read_to_string(&file).unwrap().starts_with("leaf-standby 2\n"));
    }
    let k = net_key("home");
    std::fs::write(
        &file,
        format!(
            "leaf-standby 2\nfuture line\nsaved soon\ntags {tags}\npref x\nlast {k}\nnet {k}\n\
             a u 0 - 0 extra-field\na d\na u nan nope zz\nnet not-a-key\na u 0 - 0\n"
        ),
    )
    .unwrap();
    let g = group_with(3, params(), Some(file.clone()));
    let t = Instant::now();
    assert_eq!(g.plan(t).known, vec![0, 2], "the last network warm");
    assert_eq!(g.status(1), Status::Down, "missing fields: defaults");
    assert_eq!(g.health(2).penalty, 0.0, "a bad penalty: the default");
    let _ = std::fs::remove_dir_all(&dir);
}
