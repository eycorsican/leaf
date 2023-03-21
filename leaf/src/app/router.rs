use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Result;
use cidr::IpCidr;
use futures::TryFutureExt;
use log::*;
use maxminddb::geoip2::Country;
use memmap2::Mmap;

use crate::app::SyncDnsClient;
use crate::config;
use crate::session::{Network, Session, SocksAddr};

pub trait Condition: Send + Sync + Unpin {
    fn apply(&self, sess: &Session) -> bool;
}

struct Rule {
    target: String,
    condition: Box<dyn Condition>,
}

impl Rule {
    fn new(target: String, condition: Box<dyn Condition>) -> Self {
        Rule { target, condition }
    }
}

impl Condition for Rule {
    fn apply(&self, sess: &Session) -> bool {
        self.condition.apply(sess)
    }
}

struct MmdbMatcher {
    reader: Arc<maxminddb::Reader<Mmap>>,
    country_code: String,
}

impl MmdbMatcher {
    fn new(reader: Arc<maxminddb::Reader<Mmap>>, country_code: String) -> Self {
        MmdbMatcher {
            reader,
            country_code,
        }
    }
}

impl Condition for MmdbMatcher {
    fn apply(&self, sess: &Session) -> bool {
        if !sess.destination.is_domain() {
            if let Some(ip) = sess.destination.ip() {
                if let Ok(country) = self.reader.lookup::<Country>(ip) {
                    if let Some(country) = country.country {
                        if let Some(iso_code) = country.iso_code {
                            if iso_code.to_lowercase() == self.country_code.to_lowercase() {
                                debug!("[{}] matches geoip code [{}]", ip, &self.country_code);
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
}

struct IpCidrMatcher {
    values: Vec<IpCidr>,
}

impl IpCidrMatcher {
    fn new(ips: &mut Vec<String>) -> Self {
        let mut cidrs = Vec::new();
        for ip in ips.iter_mut() {
            let ip = std::mem::take(ip);
            match ip.parse::<IpCidr>() {
                Ok(cidr) => cidrs.push(cidr),
                Err(err) => {
                    debug!("parsing cidr {} failed: {}", ip, err);
                }
            }
            drop(ip);
        }
        IpCidrMatcher { values: cidrs }
    }
}

impl Condition for IpCidrMatcher {
    fn apply(&self, sess: &Session) -> bool {
        if !sess.destination.is_domain() {
            for cidr in &self.values {
                if let Some(ip) = sess.destination.ip() {
                    if cidr.contains(&ip) {
                        debug!("[{}] matches ip-cidr [{}]", ip, &cidr);
                        return true;
                    }
                }
            }
        }
        false
    }
}

struct InboundTagMatcher {
    values: Vec<String>,
}

impl InboundTagMatcher {
    fn new(tags: &mut Vec<String>) -> Self {
        let mut values = Vec::new();
        for t in tags.iter_mut() {
            values.push(std::mem::take(t));
        }
        Self { values }
    }
}

impl Condition for InboundTagMatcher {
    fn apply(&self, sess: &Session) -> bool {
        for v in &self.values {
            if v == &sess.inbound_tag {
                debug!("[{}] matches inbound tag [{}]", &sess.inbound_tag, v);
                return true;
            }
        }
        false
    }
}

struct NetworkMatcher {
    values: Vec<Network>,
}

impl NetworkMatcher {
    fn new(networks: &mut Vec<String>) -> Self {
        let mut values = Vec::new();
        for net in networks.iter_mut() {
            match std::mem::take(net).to_uppercase().as_str() {
                "TCP" => values.push(Network::Tcp),
                "UDP" => values.push(Network::Udp),
                _ => (),
            }
        }
        Self { values }
    }
}

impl Condition for NetworkMatcher {
    fn apply(&self, sess: &Session) -> bool {
        for v in &self.values {
            if v == &sess.network {
                debug!("[{}] matches network [{}]", &sess.network, v);
                return true;
            }
        }
        false
    }
}

struct PortMatcher {
    condition: Box<dyn Condition>,
}

impl PortMatcher {
    fn new(port_ranges: &Vec<String>) -> Self {
        let mut cond_or = ConditionOr::new();
        for pr in port_ranges.iter() {
            match PortRangeMatcher::new(pr) {
                Ok(m) => cond_or.add(Box::new(m)),
                Err(e) => warn!("failed to add port range matcher: {}", e),
            }
        }
        PortMatcher {
            condition: Box::new(cond_or),
        }
    }
}

impl Condition for PortMatcher {
    fn apply(&self, sess: &Session) -> bool {
        self.condition.apply(sess)
    }
}

struct PortRangeMatcher {
    start: u16,
    end: u16,
}

impl PortRangeMatcher {
    fn new(port_range: &str) -> Result<Self> {
        let parts: Vec<&str> = port_range.split('-').collect();
        if parts.len() != 2 {
            return Err(anyhow!("invalid port range"));
        }
        let start = if let Ok(v) = parts[0].parse::<u16>() {
            v
        } else {
            return Err(anyhow!("invalid port range"));
        };
        let end = if let Ok(v) = parts[1].parse::<u16>() {
            v
        } else {
            return Err(anyhow!("invalid port range"));
        };
        if start > end {
            return Err(anyhow!("invalid port range"));
        }
        Ok(PortRangeMatcher { start, end })
    }
}

impl Condition for PortRangeMatcher {
    fn apply(&self, sess: &Session) -> bool {
        let port = sess.destination.port();
        if port >= self.start && port <= self.end {
            debug!(
                "[{}] matches port range [{}-{}]",
                port, self.start, self.end
            );
            true
        } else {
            false
        }
    }
}

struct DomainKeywordMatcher {
    value: String,
}

impl DomainKeywordMatcher {
    fn new(value: String) -> Self {
        DomainKeywordMatcher { value }
    }
}

impl Condition for DomainKeywordMatcher {
    fn apply(&self, sess: &Session) -> bool {
        if sess.destination.is_domain() {
            if let Some(domain) = sess.destination.domain() {
                if domain.contains(&self.value) {
                    debug!("[{}] matches domain keyword [{}]", domain, &self.value);
                    return true;
                }
            }
        }
        false
    }
}

struct DomainSuffixMatcher {
    value: String,
}

impl DomainSuffixMatcher {
    fn new(value: String) -> Self {
        DomainSuffixMatcher { value }
    }
}

// test if domain1 is a subdomain of domain2
// examples:
//   video.google.com vs google.com -> true
//   video.google.com vs gle.com -> false
//   google.com vs video.google.com -> false
fn is_sub_domain(d1: &str, d2: &str) -> bool {
    let d1_parts: Vec<&str> = d1.split('.').rev().collect();
    let d2_parts: Vec<&str> = d2.split('.').rev().collect();
    if d1_parts.len() < d2_parts.len() {
        return false;
    }
    let d2_enum = d2_parts.iter().enumerate();
    for (i, v) in d2_enum {
        if &d1_parts[i] != v {
            return false;
        }
    }
    true
}

impl Condition for DomainSuffixMatcher {
    fn apply(&self, sess: &Session) -> bool {
        if sess.destination.is_domain() {
            if let Some(domain) = sess.destination.domain() {
                if is_sub_domain(domain, &self.value) {
                    debug!("[{}] matches domain suffix [{}]", domain, &self.value);
                    return true;
                }
            }
        }
        false
    }
}

struct DomainFullMatcher {
    value: String,
}

impl DomainFullMatcher {
    fn new(value: String) -> Self {
        DomainFullMatcher { value }
    }
}

impl Condition for DomainFullMatcher {
    fn apply(&self, sess: &Session) -> bool {
        if sess.destination.is_domain() {
            if let Some(domain) = sess.destination.domain() {
                if domain == &self.value {
                    debug!("{} matches domain [{}]", domain, &self.value);
                    return true;
                }
            }
        }
        false
    }
}

struct DomainMatcher {
    condition: Box<dyn Condition>,
}

impl DomainMatcher {
    fn new(domains: &mut Vec<config::router::rule::Domain>) -> Self {
        let mut cond_or = ConditionOr::new();
        for rr_domain in domains.iter_mut() {
            let filter = std::mem::take(&mut rr_domain.value);
            match rr_domain.type_.unwrap() {
                config::router::rule::domain::Type::PLAIN => {
                    cond_or.add(Box::new(DomainKeywordMatcher::new(filter)));
                }
                config::router::rule::domain::Type::DOMAIN => {
                    cond_or.add(Box::new(DomainSuffixMatcher::new(filter)));
                }
                config::router::rule::domain::Type::FULL => {
                    cond_or.add(Box::new(DomainFullMatcher::new(filter)));
                }
            }
        }
        DomainMatcher {
            condition: Box::new(cond_or),
        }
    }
}

impl Condition for DomainMatcher {
    fn apply(&self, sess: &Session) -> bool {
        self.condition.apply(sess)
    }
}

struct ConditionAnd {
    conditions: Vec<Box<dyn Condition>>,
}

impl ConditionAnd {
    fn new() -> Self {
        ConditionAnd {
            conditions: Vec::new(),
        }
    }

    fn add(&mut self, cond: Box<dyn Condition>) {
        self.conditions.push(cond)
    }

    fn is_empty(&self) -> bool {
        self.conditions.len() == 0
    }
}

impl Condition for ConditionAnd {
    fn apply(&self, sess: &Session) -> bool {
        for cond in &self.conditions {
            if !cond.apply(sess) {
                return false;
            }
        }
        true
    }
}

struct ConditionOr {
    conditions: Vec<Box<dyn Condition>>,
}

impl ConditionOr {
    fn new() -> Self {
        ConditionOr {
            conditions: Vec::new(),
        }
    }

    fn add(&mut self, cond: Box<dyn Condition>) {
        self.conditions.push(cond)
    }
}

impl Condition for ConditionOr {
    fn apply(&self, sess: &Session) -> bool {
        for cond in &self.conditions {
            if cond.apply(sess) {
                return true;
            }
        }
        false
    }
}

pub struct Router {
    rules: Vec<Rule>,
    domain_resolve: bool,
    dns_client: SyncDnsClient,
}

impl Router {
    fn load_rules(rules: &mut Vec<Rule>, routing_rules: &mut Vec<config::router::Rule>) {
        let mut mmdb_readers: HashMap<String, Arc<maxminddb::Reader<Mmap>>> = HashMap::new();
        for rr in routing_rules.iter_mut() {
            let mut cond_and = ConditionAnd::new();

            if rr.domains.len() > 0 {
                cond_and.add(Box::new(DomainMatcher::new(&mut rr.domains)));
            }

            if rr.ip_cidrs.len() > 0 {
                cond_and.add(Box::new(IpCidrMatcher::new(&mut rr.ip_cidrs)));
            }

            if rr.mmdbs.len() > 0 {
                for mmdb in rr.mmdbs.iter() {
                    let reader = match mmdb_readers.get(&mmdb.file) {
                        Some(r) => r.clone(),
                        None => match maxminddb::Reader::open_mmap(&mmdb.file) {
                            Ok(r) => {
                                let r = Arc::new(r);
                                mmdb_readers.insert((&mmdb.file).to_owned(), r.clone());
                                r
                            }
                            Err(e) => {
                                warn!("open mmdb file {} failed: {:?}", mmdb.file, e);
                                continue;
                            }
                        },
                    };
                    cond_and.add(Box::new(MmdbMatcher::new(
                        reader,
                        mmdb.country_code.clone(),
                    )));
                }
            }

            if rr.port_ranges.len() > 0 {
                cond_and.add(Box::new(PortMatcher::new(&rr.port_ranges)));
            }

            if rr.networks.len() > 0 {
                cond_and.add(Box::new(NetworkMatcher::new(&mut rr.networks)));
            }

            if rr.inbound_tags.len() > 0 {
                cond_and.add(Box::new(InboundTagMatcher::new(&mut rr.inbound_tags)));
            }

            if cond_and.is_empty() {
                warn!("empty rule at target {}", rr.target_tag);
                continue;
            }

            let tag = std::mem::take(&mut rr.target_tag);
            rules.push(Rule::new(tag, Box::new(cond_and)));
        }
    }

    pub fn new(
        router: &mut protobuf::MessageField<config::Router>,
        dns_client: SyncDnsClient,
    ) -> Self {
        let mut rules: Vec<Rule> = Vec::new();
        let mut domain_resolve = false;
        if let Some(router) = router.as_mut() {
            Self::load_rules(&mut rules, &mut router.rules);
            domain_resolve = router.domain_resolve;
        }
        Router {
            rules,
            domain_resolve,
            dns_client,
        }
    }

    pub fn reload(&mut self, router: &mut protobuf::MessageField<config::Router>) -> Result<()> {
        self.rules.clear();
        if let Some(router) = router.as_mut() {
            Self::load_rules(&mut self.rules, &mut router.rules);
            self.domain_resolve = router.domain_resolve;
        }
        Ok(())
    }

    pub async fn pick_route<'a>(&'a self, sess: &'a Session) -> Result<&'a String> {
        log::debug!("picking route for {}:{}", &sess.network, &sess.destination);
        for rule in &self.rules {
            if rule.apply(sess) {
                return Ok(&rule.target);
            }
        }
        if sess.destination.is_domain() && self.domain_resolve {
            let ips = {
                self.dns_client
                    .read()
                    .await
                    .lookup(
                        sess.destination
                            .domain()
                            .ok_or_else(|| anyhow!("illegal domain name"))?,
                    )
                    .map_err(|e| anyhow!("lookup {} failed: {}", sess.destination.host(), e))
                    .await?
            };
            if !ips.is_empty() {
                let mut new_sess = sess.clone();
                new_sess.destination = SocksAddr::from((ips[0], sess.destination.port()));
                log::trace!(
                    "re-matching with resolved ip [{}] for [{}]",
                    ips[0],
                    sess.destination.host()
                );
                for rule in &self.rules {
                    if rule.apply(&new_sess) {
                        return Ok(&rule.target);
                    }
                }
            }
        }
        Err(anyhow!("no matching rules"))
    }
}

#[cfg(test)]
mod tests {
    use crate::session::SocksAddr;

    use super::*;

    #[test]
    fn test_is_sub_domain() {
        let d1 = "video.google.com".to_string();
        let d2 = "google.com".to_string();
        assert!(is_sub_domain(&d1, &d2));

        let d1 = "video.google.com".to_string();
        let d2 = "gle.com".to_string();
        assert!(!is_sub_domain(&d1, &d2));
    }

    #[test]
    fn test_port_matcher() {
        let mut sess = Session {
            destination: SocksAddr::Domain("www.google.com".to_string(), 22),
            ..Default::default()
        };

        // test port range
        let m = PortMatcher::new(&vec!["1024-5000".to_string(), "6000-7000".to_string()]);
        sess.destination = SocksAddr::Domain("www.google.com".to_string(), 2000);
        assert!(m.apply(&sess));
        sess.destination = SocksAddr::Domain("www.google.com".to_string(), 5001);
        assert!(!m.apply(&sess));
        sess.destination = SocksAddr::Domain("www.google.com".to_string(), 6001);
        assert!(m.apply(&sess));

        // test single port range
        let m = PortMatcher::new(&vec!["22-22".to_string()]);
        sess.destination = SocksAddr::Domain("www.google.com".to_string(), 22);
        assert!(m.apply(&sess));

        // test invalid port ranges
        let m = PortRangeMatcher::new("22-21");
        assert!(m.is_err());
        let m = PortRangeMatcher::new("22");
        assert!(m.is_err());
        let m = PortRangeMatcher::new("22-");
        assert!(m.is_err());
        let m = PortRangeMatcher::new("-22");
        assert!(m.is_err());
        let m = PortRangeMatcher::new("22-abc");
        assert!(m.is_err());
        let m = PortRangeMatcher::new("22-23-24");
        assert!(m.is_err());
    }
}
