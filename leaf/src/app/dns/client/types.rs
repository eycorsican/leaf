#[derive(Clone, Debug)]
struct CacheEntry {
    pub ips: Vec<IpAddr>,
    pub deadline: Instant,
}

#[derive(Clone, Debug)]
pub struct EchCacheEntry {
    pub ech_config_list: String,
    pub deadline: Instant,
}

#[derive(Clone, Debug)]
struct DohResolver {
    domain: String,
    bootstrap_ip: Option<IpAddr>,
    is_direct: bool,
}

#[derive(Clone, Debug)]
enum Resolver {
    Server(SocketAddr, bool),
    DoH(DohResolver),
    System(bool),
}

#[derive(Clone, Debug, Default)]
struct ServerRuntimeStats {
    avg_latency_ms: f64,
    samples: u64,
    successes: u64,
    failures: u64,
    timeouts: u64,
    consecutive_slow: u32,
    consecutive_failures: u32,
}

#[derive(Clone, Debug, Default)]
struct ServerSelectorState {
    primary_server: Option<String>,
    stats: HashMap<String, ServerRuntimeStats>,
    last_reselect_at: Option<Instant>,
}

impl fmt::Display for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Server(addr, direct) => {
                if *direct {
                    write!(f, "direct:{}", addr)
                } else {
                    write!(f, "{}", addr)
                }
            }
            Self::DoH(doh) => {
                if doh.is_direct {
                    write!(f, "direct:doh:{}", doh.domain)?;
                } else {
                    write!(f, "doh:{}", doh.domain)?;
                }
                if let Some(ip) = doh.bootstrap_ip {
                    write!(f, "@{}", ip)?;
                }
                Ok(())
            }
            Self::System(direct) => {
                if *direct {
                    write!(f, "direct:system")
                } else {
                    write!(f, "system")
                }
            }
        }
    }
}

impl ServerSelectorState {
    fn score_of(&self, server: &str) -> f64 {
        if let Some(stat) = self.stats.get(server) {
            let baseline = if stat.samples == 0 {
                (*option::DNS_SERVER_SLOW_RESPONSE_MS as f64) / 2.0
            } else {
                stat.avg_latency_ms
            };
            baseline
                + (stat.failures as f64 * 600.0)
                + (stat.timeouts as f64 * 900.0)
                + (stat.consecutive_failures as f64 * 1200.0)
                + (stat.consecutive_slow as f64 * 300.0)
        } else {
            (*option::DNS_SERVER_SLOW_RESPONSE_MS as f64) / 2.0
        }
    }

    fn is_degraded(&self, server: &str) -> bool {
        let switch_threshold = (*option::DNS_SERVER_SWITCH_THRESHOLD).max(1);
        if let Some(stat) = self.stats.get(server) {
            (stat.consecutive_failures as usize) >= switch_threshold
                || (stat.consecutive_slow as usize) >= switch_threshold
        } else {
            false
        }
    }

    fn ensure_candidates(&mut self, servers: &[&Resolver]) {
        for server in servers {
            self.stats.entry(server.to_string()).or_default();
        }
    }

    fn select_primary_index(&mut self, servers: &[&Resolver]) -> usize {
        if servers.len() <= 1 {
            if let Some(server) = servers.first() {
                self.primary_server = Some(server.to_string());
            }
            return 0;
        }
        self.ensure_candidates(servers);
        let now = Instant::now();
        let reselect_interval =
            Duration::from_secs((*option::DNS_SERVER_RESELECT_INTERVAL_SECS).max(1));
        let should_reselect = self
            .last_reselect_at
            .map(|last| now.saturating_duration_since(last) >= reselect_interval)
            .unwrap_or(true);

        let current_idx = self.primary_server.as_ref().and_then(|primary| {
            servers
                .iter()
                .position(|server| server.to_string() == *primary)
        });
        if let Some(idx) = current_idx {
            let current_key = servers[idx].to_string();
            if !should_reselect && !self.is_degraded(&current_key) {
                return idx;
            }
        }

        let mut best_idx = 0usize;
        let mut best_score = f64::MAX;
        for (idx, server) in servers.iter().enumerate() {
            let score = self.score_of(&server.to_string());
            if score < best_score {
                best_score = score;
                best_idx = idx;
            }
        }
        self.primary_server = Some(servers[best_idx].to_string());
        self.last_reselect_at = Some(now);
        best_idx
    }

    fn fallback_indices(&self, servers: &[&Resolver], preferred_idx: usize) -> Vec<usize> {
        let mut candidates: Vec<usize> = (0..servers.len())
            .filter(|idx| *idx != preferred_idx)
            .collect();
        candidates.sort_by(|a, b| {
            let sa = self.score_of(&servers[*a].to_string());
            let sb = self.score_of(&servers[*b].to_string());
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        });
        candidates
    }

    fn mark_success(&mut self, server: &str, elapsed: Duration) {
        let stat = self.stats.entry(server.to_owned()).or_default();
        let elapsed_ms = elapsed.as_millis() as f64;
        stat.successes = stat.successes.saturating_add(1);
        stat.samples = stat.samples.saturating_add(1);
        if stat.samples == 1 {
            stat.avg_latency_ms = elapsed_ms;
        } else {
            stat.avg_latency_ms = stat.avg_latency_ms * 0.8 + elapsed_ms * 0.2;
        }
        let slow_threshold = (*option::DNS_SERVER_SLOW_RESPONSE_MS).max(1) as f64;
        if elapsed_ms >= slow_threshold {
            stat.consecutive_slow = stat.consecutive_slow.saturating_add(1);
        } else {
            stat.consecutive_slow = 0;
        }
        stat.consecutive_failures = 0;
        if self.primary_server.is_none() {
            self.primary_server = Some(server.to_owned());
        }
    }

    fn mark_failure(&mut self, server: &str, is_timeout: bool) {
        let stat = self.stats.entry(server.to_owned()).or_default();
        stat.failures = stat.failures.saturating_add(1);
        if is_timeout {
            stat.timeouts = stat.timeouts.saturating_add(1);
        }
        stat.consecutive_failures = stat.consecutive_failures.saturating_add(1);
        let switch_threshold = (*option::DNS_SERVER_SWITCH_THRESHOLD).max(1);
        if self.primary_server.as_deref() == Some(server)
            && (stat.consecutive_failures as usize) >= switch_threshold
        {
            self.primary_server = None;
        }
    }

    fn set_primary(&mut self, server: &str) {
        self.primary_server = Some(server.to_owned());
        self.last_reselect_at = Some(Instant::now());
    }
}

pub struct DnsClient {
    dispatcher: Option<Weak<Dispatcher>>,
    servers: Vec<Resolver>,
    hosts: HashMap<String, Vec<IpAddr>>,
    ipv4_cache: Arc<TokioMutex<LruCache<String, CacheEntry>>>,
    ipv6_cache: Arc<TokioMutex<LruCache<String, CacheEntry>>>,
    ech_cache: Arc<TokioMutex<LruCache<String, EchCacheEntry>>>,
    ech_query_locks: Arc<TokioMutex<HashMap<String, Arc<TokioMutex<()>>>>>,
    selector_state: Arc<Mutex<ServerSelectorState>>,
}
