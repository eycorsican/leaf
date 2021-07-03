use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use futures::future::select_ok;
use log::*;
use lru::LruCache;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;
use trust_dns_proto::{
    op::{
        header::MessageType, op_code::OpCode, query::Query, response_code::ResponseCode, Message,
    },
    rr::{record_data::RData, record_type::RecordType, Name},
};

use crate::{option, proxy::UdpConnector};

#[derive(Clone, Debug)]
struct CacheEntry {
    pub ips: Vec<IpAddr>,
    // The deadline this entry should be considered expired.
    pub deadline: Instant,
}

pub struct DnsClient {
    servers: Vec<SocketAddr>,
    hosts: HashMap<String, Vec<IpAddr>>,
    ipv4_cache: Arc<TokioMutex<LruCache<String, CacheEntry>>>,
    ipv6_cache: Arc<TokioMutex<LruCache<String, CacheEntry>>>,
}

impl DnsClient {
    fn load_servers(dns: &crate::config::Dns) -> Result<Vec<SocketAddr>> {
        let mut servers = Vec::new();
        for server in dns.servers.iter() {
            servers.push(SocketAddr::new(server.parse::<IpAddr>()?, 53));
        }
        if servers.is_empty() {
            return Err(anyhow!("no dns servers"));
        }
        Ok(servers)
    }

    fn load_hosts(dns: &crate::config::Dns) -> HashMap<String, Vec<IpAddr>> {
        let mut hosts = HashMap::new();
        for (name, ips) in dns.hosts.iter() {
            hosts.insert(name.to_owned(), ips.values.to_vec());
        }
        let mut parsed_hosts = HashMap::new();
        for (name, static_ips) in hosts.iter() {
            let mut ips = Vec::new();
            for ip in static_ips {
                if let Ok(parsed_ip) = ip.parse::<IpAddr>() {
                    ips.push(parsed_ip);
                }
            }
            parsed_hosts.insert(name.to_owned(), ips);
        }
        parsed_hosts
    }

    pub fn new(dns: &protobuf::SingularPtrField<crate::config::Dns>) -> Result<Self> {
        let dns = if let Some(dns) = dns.as_ref() {
            dns
        } else {
            return Err(anyhow!("empty dns config"));
        };
        let servers = Self::load_servers(dns)?;
        let hosts = Self::load_hosts(dns);
        let ipv4_cache = Arc::new(TokioMutex::new(LruCache::<String, CacheEntry>::new(
            *option::DNS_CACHE_SIZE,
        )));
        let ipv6_cache = Arc::new(TokioMutex::new(LruCache::<String, CacheEntry>::new(
            *option::DNS_CACHE_SIZE,
        )));

        Ok(DnsClient {
            servers,
            hosts,
            ipv4_cache,
            ipv6_cache,
        })
    }

    pub fn reload(&mut self, dns: &protobuf::SingularPtrField<crate::config::Dns>) -> Result<()> {
        let dns = if let Some(dns) = dns.as_ref() {
            dns
        } else {
            return Err(anyhow!("empty dns config"));
        };
        let servers = Self::load_servers(dns)?;
        let hosts = Self::load_hosts(dns);
        self.servers = servers;
        self.hosts = hosts;
        Ok(())
    }

    async fn optimize_cache_ipv4(&self, address: String, connected_ip: IpAddr) {
        // Nothing to do if the target address is an IP address.
        if address.parse::<IpAddr>().is_ok() {
            return;
        }

        // If the connected IP is not in the first place, we should optimize it.
        let mut new_entry = if let Some(entry) = self.ipv4_cache.lock().await.get(&address) {
            if !entry.ips.starts_with(&[connected_ip]) && entry.ips.contains(&connected_ip) {
                entry.clone()
            } else {
                return;
            }
        } else {
            return;
        };

        // Move failed IPs to the end, the optimized vector starts with the connected IP.
        if let Ok(idx) = new_entry.ips.binary_search(&connected_ip) {
            trace!("updates DNS cache item from\n{:#?}", &new_entry);
            new_entry.ips.rotate_left(idx);
            trace!("to\n{:#?}", &new_entry);
            self.ipv4_cache.lock().await.put(address, new_entry);
            trace!("updated cache");
        }
    }

    async fn optimize_cache_ipv6(&self, address: String, connected_ip: IpAddr) {
        // Nothing to do if the target address is an IP address.
        if address.parse::<IpAddr>().is_ok() {
            return;
        }

        // If the connected IP is not in the first place, we should optimize it.
        let mut new_entry = if let Some(entry) = self.ipv6_cache.lock().await.get(&address) {
            if !entry.ips.starts_with(&[connected_ip]) && entry.ips.contains(&connected_ip) {
                entry.clone()
            } else {
                return;
            }
        } else {
            return;
        };

        // Move failed IPs to the end, the optimized vector starts with the connected IP.
        if let Ok(idx) = new_entry.ips.binary_search(&connected_ip) {
            trace!("updates DNS cache item from\n{:#?}", &new_entry);
            new_entry.ips.rotate_left(idx);
            trace!("to\n{:#?}", &new_entry);
            self.ipv6_cache.lock().await.put(address, new_entry);
            trace!("updated cache");
        }
    }

    /// Updates the cache according to the IP address successfully connected.
    pub async fn optimize_cache(&self, address: String, connected_ip: IpAddr) {
        match connected_ip {
            IpAddr::V4(..) => self.optimize_cache_ipv4(address, connected_ip).await,
            IpAddr::V6(..) => self.optimize_cache_ipv6(address, connected_ip).await,
        }
    }

    async fn query_task(
        &self,
        request: Vec<u8>,
        host: &str,
        server: &SocketAddr,
    ) -> Result<CacheEntry> {
        let socket = self.new_udp_socket(server).await?;
        let mut last_err = None;
        for _i in 0..*option::MAX_DNS_RETRIES {
            debug!("looking up host {} on {}", host, server);
            let start = tokio::time::Instant::now();
            match socket.send_to(&request, server).await {
                Ok(_) => {
                    let mut buf = vec![0u8; 512];
                    match timeout(
                        Duration::from_secs(*option::DNS_TIMEOUT),
                        socket.recv_from(&mut buf),
                    )
                    .await
                    {
                        Ok(res) => match res {
                            Ok((n, _)) => {
                                let resp = match Message::from_vec(&buf[..n]) {
                                    Ok(resp) => resp,
                                    Err(err) => {
                                        last_err = Some(anyhow!("parse message failed: {:?}", err));
                                        // broken response, no retry
                                        break;
                                    }
                                };
                                if resp.response_code() != ResponseCode::NoError {
                                    last_err =
                                        Some(anyhow!("response error {}", resp.response_code()));
                                    // error response, no retry
                                    //
                                    // TODO Needs more careful investigations, I'm not quite sure about
                                    // this.
                                    break;
                                }
                                let mut ips = Vec::new();
                                for ans in resp.answers() {
                                    // TODO checks?
                                    match ans.rdata() {
                                        RData::A(ip) => {
                                            ips.push(IpAddr::V4(ip.to_owned()));
                                        }
                                        RData::AAAA(ip) => {
                                            ips.push(IpAddr::V6(ip.to_owned()));
                                        }
                                        _ => (),
                                    }
                                }
                                if !ips.is_empty() {
                                    let elapsed = tokio::time::Instant::now().duration_since(start);
                                    let ttl = resp.answers().iter().next().unwrap().ttl();
                                    debug!(
                                        "return {} ips (ttl {}) for {} from {} in {}ms",
                                        ips.len(),
                                        ttl,
                                        host,
                                        server,
                                        elapsed.as_millis(),
                                    );
                                    let deadline = if let Some(d) =
                                        Instant::now().checked_add(Duration::from_secs(ttl.into()))
                                    {
                                        d
                                    } else {
                                        last_err = Some(anyhow!("invalid ttl"));
                                        break;
                                    };
                                    let entry = CacheEntry { ips, deadline };
                                    trace!("ips for {}:\n{:#?}", host, &entry);
                                    return Ok(entry);
                                } else {
                                    // response with 0 records
                                    //
                                    // TODO Not sure how to due with this.
                                    last_err = Some(anyhow!("no records"));
                                    break;
                                }
                            }
                            Err(err) => {
                                last_err = Some(anyhow!("recv failed: {:?}", err));
                                // socket recv_from error, retry
                            }
                        },
                        Err(e) => {
                            last_err = Some(anyhow!("recv timeout: {}", e));
                            // timeout, retry
                        }
                    }
                }
                Err(err) => {
                    last_err = Some(anyhow!("send failed: {:?}", err));
                    // socket send_to error, retry
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("all lookup attempts failed")))
    }

    fn new_query(name: Name, ty: RecordType) -> Message {
        let mut msg = Message::new();
        msg.add_query(Query::query(name, ty));
        let mut rng = StdRng::from_entropy();
        let id: u16 = rng.gen();
        msg.set_id(id);
        msg.set_op_code(OpCode::Query);
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(true);
        msg
    }

    async fn cache_insert(&self, host: &str, entry: CacheEntry) {
        if entry.ips.is_empty() {
            return;
        }
        match entry.ips[0] {
            IpAddr::V4(..) => self.ipv4_cache.lock().await.put(host.to_owned(), entry),
            IpAddr::V6(..) => self.ipv6_cache.lock().await.put(host.to_owned(), entry),
        };
    }

    async fn get_cached(&self, host: &String) -> Result<Vec<IpAddr>> {
        let mut cached_ips = Vec::new();

        // TODO reduce boilerplates
        match (*crate::option::ENABLE_IPV6, *crate::option::PREFER_IPV6) {
            (true, true) => {
                if let Some(entry) = self.ipv6_cache.lock().await.get(host) {
                    if entry
                        .deadline
                        .checked_duration_since(Instant::now())
                        .is_none()
                    {
                        return Err(anyhow!("entry expired"));
                    }
                    let mut ips = entry.ips.to_vec();
                    cached_ips.append(&mut ips);
                }
                if let Some(entry) = self.ipv4_cache.lock().await.get(host) {
                    if entry
                        .deadline
                        .checked_duration_since(Instant::now())
                        .is_none()
                    {
                        return Err(anyhow!("entry expired"));
                    }
                    let mut ips = entry.ips.to_vec();
                    cached_ips.append(&mut ips);
                }
            }
            (true, false) => {
                if let Some(entry) = self.ipv4_cache.lock().await.get(host) {
                    if entry
                        .deadline
                        .checked_duration_since(Instant::now())
                        .is_none()
                    {
                        return Err(anyhow!("entry expired"));
                    }
                    let mut ips = entry.ips.to_vec();
                    cached_ips.append(&mut ips);
                }
                if let Some(entry) = self.ipv6_cache.lock().await.get(host) {
                    if entry
                        .deadline
                        .checked_duration_since(Instant::now())
                        .is_none()
                    {
                        return Err(anyhow!("entry expired"));
                    }
                    let mut ips = entry.ips.to_vec();
                    cached_ips.append(&mut ips);
                }
            }
            _ => {
                if let Some(entry) = self.ipv4_cache.lock().await.get(host) {
                    if entry
                        .deadline
                        .checked_duration_since(Instant::now())
                        .is_none()
                    {
                        return Err(anyhow!("entry expired"));
                    }
                    let mut ips = entry.ips.to_vec();
                    cached_ips.append(&mut ips);
                }
            }
        }

        if !cached_ips.is_empty() {
            Ok(cached_ips)
        } else {
            Err(anyhow!("empty result"))
        }
    }

    pub async fn lookup(&self, host: &String) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        if let Ok(ips) = self.get_cached(host).await {
            return Ok(ips);
        }

        // Making cache lookup a priority rather than static hosts lookup
        // and insert the static IPs to the cache because there's a chance
        // for the IPs in the cache to be re-ordered.
        if !self.hosts.is_empty() {
            if let Some(ips) = self.hosts.get(host) {
                if !ips.is_empty() {
                    if ips.len() > 1 {
                        let deadline = Instant::now()
                            .checked_add(Duration::from_secs(6000))
                            .unwrap();
                        self.cache_insert(
                            host,
                            CacheEntry {
                                ips: ips.clone(),
                                deadline,
                            },
                        )
                        .await;
                    }
                    return Ok(ips.to_vec());
                }
            }
        }

        let mut fqdn = host.to_owned();
        fqdn.push('.');
        let name = match Name::from_str(&fqdn) {
            Ok(n) => n,
            Err(e) => return Err(anyhow!("invalid domain name [{}]: {}", host, e)),
        };

        let mut query_tasks = Vec::new();

        // TODO reduce boilerplates
        match (*crate::option::ENABLE_IPV6, *crate::option::PREFER_IPV6) {
            (true, true) => {
                let msg = Self::new_query(name.clone(), RecordType::AAAA);
                let msg_buf = match msg.to_vec() {
                    Ok(b) => b,
                    Err(e) => return Err(anyhow!("encode message to buffer failed: {}", e)),
                };
                let mut tasks = Vec::new();
                for server in &self.servers {
                    let t = self.query_task(msg_buf.clone(), host, server);
                    tasks.push(Box::pin(t));
                }
                let query_task = select_ok(tasks.into_iter());
                query_tasks.push(query_task);

                let msg = Self::new_query(name.clone(), RecordType::A);
                let msg_buf = match msg.to_vec() {
                    Ok(b) => b,
                    Err(e) => return Err(anyhow!("encode message to buffer failed: {}", e)),
                };
                let mut tasks = Vec::new();
                for server in &self.servers {
                    let t = self.query_task(msg_buf.clone(), host, server);
                    tasks.push(Box::pin(t));
                }
                let query_task = select_ok(tasks.into_iter());
                query_tasks.push(query_task);
            }
            (true, false) => {
                let msg = Self::new_query(name.clone(), RecordType::A);
                let msg_buf = match msg.to_vec() {
                    Ok(b) => b,
                    Err(e) => return Err(anyhow!("encode message to buffer failed: {}", e)),
                };
                let mut tasks = Vec::new();
                for server in &self.servers {
                    let t = self.query_task(msg_buf.clone(), host, server);
                    tasks.push(Box::pin(t));
                }
                let query_task = select_ok(tasks.into_iter());
                query_tasks.push(query_task);

                let msg = Self::new_query(name.clone(), RecordType::AAAA);
                let msg_buf = match msg.to_vec() {
                    Ok(b) => b,
                    Err(e) => return Err(anyhow!("encode message to buffer failed: {}", e)),
                };
                let mut tasks = Vec::new();
                for server in &self.servers {
                    let t = self.query_task(msg_buf.clone(), host, server);
                    tasks.push(Box::pin(t));
                }
                let query_task = select_ok(tasks.into_iter());
                query_tasks.push(query_task);
            }
            _ => {
                let msg = Self::new_query(name.clone(), RecordType::A);
                let msg_buf = match msg.to_vec() {
                    Ok(b) => b,
                    Err(e) => return Err(anyhow!("encode message to buffer failed: {}", e)),
                };
                let mut tasks = Vec::new();
                for server in &self.servers {
                    let t = self.query_task(msg_buf.clone(), host, server);
                    tasks.push(Box::pin(t));
                }
                let query_task = select_ok(tasks.into_iter());
                query_tasks.push(query_task);
            }
        }

        let mut ips = Vec::new();
        let mut last_err = None;

        for v in futures::future::join_all(query_tasks).await {
            match v {
                Ok(mut v) => {
                    self.cache_insert(host, v.0.clone()).await;
                    ips.append(&mut v.0.ips);
                }
                Err(e) => last_err = Some(anyhow!("all dns servers failed, last error: {}", e)),
            }
        }

        if !ips.is_empty() {
            return Ok(ips);
        }

        Err(last_err.unwrap_or_else(|| anyhow!("could not resolve to any address")))
    }
}

impl UdpConnector for DnsClient {}
