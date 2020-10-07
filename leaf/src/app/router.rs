use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Result;
use cidr::{Cidr, IpCidr};
use log::*;
use maxminddb::geoip2::Country;
use memmap::Mmap;

use crate::config::{self, RoutingRule};
use crate::session::Session;

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
                            if &iso_code.to_lowercase() == &self.country_code.to_lowercase() {
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
    fn new(ips: &protobuf::RepeatedField<String>) -> Self {
        let mut cidrs = Vec::new();
        for ip in ips {
            match ip.parse::<IpCidr>() {
                Ok(cidr) => cidrs.push(cidr),
                Err(err) => {
                    debug!("parsing cidr {} failed: {}", ip, err);
                }
            }
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
fn is_sub_domain(d1: &String, d2: &String) -> bool {
    let d1_parts: Vec<&str> = d1.split('.').rev().collect();
    let d2_parts: Vec<&str> = d2.split('.').rev().collect();
    if d1_parts.len() < d2_parts.len() {
        return false;
    }
    let mut d2_enum = d2_parts.iter().enumerate();
    while let Some((i, v)) = d2_enum.next() {
        if &d1_parts[i] != v {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
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
}

impl Condition for DomainSuffixMatcher {
    fn apply(&self, sess: &Session) -> bool {
        if sess.destination.is_domain() {
            if let Some(domain) = sess.destination.domain() {
                if is_sub_domain(&domain, &self.value) {
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
    fn new(domains: &protobuf::RepeatedField<config::RoutingRule_Domain>) -> Self {
        let mut cond_or = ConditionOr::new();
        for rr_domain in domains.iter() {
            match rr_domain.field_type {
                config::RoutingRule_Domain_Type::PLAIN => {
                    cond_or.add(Box::new(DomainKeywordMatcher::new(rr_domain.value.clone())));
                }
                config::RoutingRule_Domain_Type::DOMAIN => {
                    cond_or.add(Box::new(DomainSuffixMatcher::new(rr_domain.value.clone())));
                }
                config::RoutingRule_Domain_Type::FULL => {
                    cond_or.add(Box::new(DomainFullMatcher::new(rr_domain.value.clone())));
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
}

impl Router {
    pub fn new(routing_rules: &protobuf::RepeatedField<RoutingRule>) -> Self {
        let mut rules = Vec::new();
        let mut mmdb_readers: HashMap<String, Arc<maxminddb::Reader<Mmap>>> = HashMap::new();
        for rr in routing_rules.iter() {
            let mut cond_and = ConditionAnd::new();
            if rr.domains.len() > 0 {
                cond_and.add(Box::new(DomainMatcher::new(&rr.domains)));
            }
            if rr.ip_cidrs.len() > 0 {
                cond_and.add(Box::new(IpCidrMatcher::new(&rr.ip_cidrs)));
            }
            if rr.mmdbs.len() > 0 {
                for mmdb in rr.mmdbs.iter() {
                    let reader = match mmdb_readers.get(&mmdb.file) {
                        Some(r) => r.clone(),
                        None => {
                            if let Ok(r) = maxminddb::Reader::open_mmap(&mmdb.file) {
                                let r = Arc::new(r);
                                mmdb_readers.insert((&mmdb.file).to_owned(), r.clone());
                                r
                            } else {
                                warn!("open mmdb file {} failed", mmdb.file);
                                continue;
                            }
                        }
                    };
                    cond_and.add(Box::new(MmdbMatcher::new(
                        reader,
                        mmdb.country_code.clone(),
                    )));
                }
            }
            if cond_and.is_empty() {
                warn!("empty rule at target {}", rr.target_tag);
                continue;
            }
            rules.push(Rule::new(rr.target_tag.clone(), Box::new(cond_and)));
        }
        Router { rules }
    }

    pub fn pick_route(&self, sess: &Session) -> Result<&String> {
        for rule in &self.rules {
            if rule.apply(sess) {
                return Ok(&rule.target);
            }
        }
        Err(anyhow!("no matching rules"))
    }
}
