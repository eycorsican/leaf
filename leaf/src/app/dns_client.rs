use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

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

pub struct DnsClient {
    bind_addr: SocketAddr,
    servers: Vec<SocketAddr>,
    hosts: HashMap<String, Vec<IpAddr>>,
    // TODO apply ttl to cached entries
    ipv4_cache: Arc<TokioMutex<LruCache<String, Vec<IpAddr>>>>,
    ipv6_cache: Arc<TokioMutex<LruCache<String, Vec<IpAddr>>>>,
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
        let servers = Self::load_servers(&dns)?;
        let hosts = Self::load_hosts(&dns);
        let ipv4_cache = Arc::new(TokioMutex::new(LruCache::<String, Vec<IpAddr>>::new(
            *option::DNS_CACHE_SIZE,
        )));
        let ipv6_cache = Arc::new(TokioMutex::new(LruCache::<String, Vec<IpAddr>>::new(
            *option::DNS_CACHE_SIZE,
        )));

        Ok(DnsClient {
            servers,
            bind_addr: SocketAddr::new(dns.bind.parse::<IpAddr>()?, 0),
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
        let servers = Self::load_servers(&dns)?;
        let hosts = Self::load_hosts(&dns);
        self.servers = servers;
        self.hosts = hosts;
        self.bind_addr = SocketAddr::new(dns.bind.parse::<IpAddr>()?, 0);
        Ok(())
    }

    async fn optimize_cache_ipv4(&self, address: String, connected_ip: IpAddr) {
        // Nothing to do if the target address is an IP address.
        if address.parse::<IpAddr>().is_ok() {
            return;
        }

        // If the connected IP is not in the first place, we should optimize it.
        let mut new_ips = if let Some(ips) = self.ipv4_cache.lock().await.get(&address) {
            if !ips.starts_with(&[connected_ip]) && ips.contains(&connected_ip) {
                ips.to_vec()
            } else {
                return;
            }
        } else {
            return;
        };

        // Move failed IPs to the end, the optimized vector starts with the connected IP.
        if let Ok(idx) = new_ips.binary_search(&connected_ip) {
            trace!("updates DNS cache item from\n{:#?}", &new_ips);
            new_ips.rotate_left(idx);
            trace!("to\n{:#?}", &new_ips);
            self.ipv4_cache.lock().await.put(address, new_ips);
            trace!("updated cache");
        }
    }

    async fn optimize_cache_ipv6(&self, address: String, connected_ip: IpAddr) {
        // Nothing to do if the target address is an IP address.
        if address.parse::<IpAddr>().is_ok() {
            return;
        }

        // If the connected IP is not in the first place, we should optimize it.
        let mut new_ips = if let Some(ips) = self.ipv6_cache.lock().await.get(&address) {
            if !ips.starts_with(&[connected_ip]) && ips.contains(&connected_ip) {
                ips.to_vec()
            } else {
                return;
            }
        } else {
            return;
        };

        // Move failed IPs to the end, the optimized vector starts with the connected IP.
        if let Ok(idx) = new_ips.binary_search(&connected_ip) {
            trace!("updates DNS cache item from\n{:#?}", &new_ips);
            new_ips.rotate_left(idx);
            trace!("to\n{:#?}", &new_ips);
            self.ipv6_cache.lock().await.put(address, new_ips);
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
        bind_addr: &SocketAddr,
    ) -> Result<Vec<IpAddr>> {
        let socket = self.create_udp_socket(bind_addr, server).await?;
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
                                let mut addrs = Vec::new();
                                for ans in resp.answers() {
                                    // TODO checks?
                                    match ans.rdata() {
                                        RData::A(addr) => {
                                            addrs.push(IpAddr::V4(addr.to_owned()));
                                        }
                                        RData::AAAA(addr) => {
                                            addrs.push(IpAddr::V6(addr.to_owned()));
                                        }
                                        _ => (),
                                    }
                                }
                                if !addrs.is_empty() {
                                    let elapsed = tokio::time::Instant::now().duration_since(start);
                                    debug!(
                                        "return {} ips for {} from {} in {}ms",
                                        addrs.len(),
                                        host,
                                        server,
                                        elapsed.as_millis(),
                                    );
                                    trace!("ips for {}:\n{:#?}", host, &addrs);
                                    return Ok(addrs);
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

    async fn cache_insert(&self, host: &str, ips: &Vec<IpAddr>) {
        if ips.is_empty() {
            return;
        }
        match ips[0] {
            IpAddr::V4(..) => self
                .ipv4_cache
                .lock()
                .await
                .put(host.to_owned(), ips.clone()),
            IpAddr::V6(..) => self
                .ipv6_cache
                .lock()
                .await
                .put(host.to_owned(), ips.clone()),
        };
    }

    pub async fn lookup(&self, host: &String) -> Result<Vec<IpAddr>> {
        self.lookup_with_bind(host, &self.bind_addr).await
    }

    pub async fn lookup_with_bind(
        &self,
        host: &String,
        bind_addr: &SocketAddr,
    ) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let mut cached_ips = Vec::new();

        match (*crate::option::ENABLE_IPV6, *crate::option::PREFER_IPV6) {
            (true, true) => {
                if let Some(ips) = self.ipv6_cache.lock().await.get(host) {
                    let mut ips = ips.to_vec();
                    cached_ips.append(&mut ips);
                }
                if let Some(ips) = self.ipv4_cache.lock().await.get(host) {
                    let mut ips = ips.to_vec();
                    cached_ips.append(&mut ips);
                }
            }
            (true, false) => {
                if let Some(ips) = self.ipv4_cache.lock().await.get(host) {
                    let mut ips = ips.to_vec();
                    cached_ips.append(&mut ips);
                }
                if let Some(ips) = self.ipv6_cache.lock().await.get(host) {
                    let mut ips = ips.to_vec();
                    cached_ips.append(&mut ips);
                }
            }
            _ => {
                if let Some(ips) = self.ipv4_cache.lock().await.get(host) {
                    let mut ips = ips.to_vec();
                    cached_ips.append(&mut ips);
                }
            }
        }

        if !cached_ips.is_empty() {
            return Ok(cached_ips);
        }

        // Making cache lookup a priority rather than static hosts lookup
        // and insert the static IPs to the cache because there's a chance
        // for the IPs in the cache to be re-ordered.
        if !self.hosts.is_empty() {
            if let Some(ips) = self.hosts.get(host) {
                if !ips.is_empty() {
                    if ips.len() > 1 {
                        self.cache_insert(host, ips).await;
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

        match (*crate::option::ENABLE_IPV6, *crate::option::PREFER_IPV6) {
            (true, true) => {
                let msg = Self::new_query(name.clone(), RecordType::AAAA);
                let msg_buf = match msg.to_vec() {
                    Ok(b) => b,
                    Err(e) => return Err(anyhow!("encode message to buffer failed: {}", e)),
                };
                let mut tasks = Vec::new();
                for server in &self.servers {
                    let t = self.query_task(msg_buf.clone(), host, server, bind_addr);
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
                    let t = self.query_task(msg_buf.clone(), host, server, bind_addr);
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
                    let t = self.query_task(msg_buf.clone(), host, server, bind_addr);
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
                    let t = self.query_task(msg_buf.clone(), host, server, bind_addr);
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
                    let t = self.query_task(msg_buf.clone(), host, server, bind_addr);
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
                    self.cache_insert(host, &v.0).await;
                    ips.append(&mut v.0);
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
