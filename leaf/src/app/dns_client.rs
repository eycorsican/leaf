use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use futures::future::select_ok;
use hickory_proto::{
    op::{
        header::MessageType, op_code::OpCode, query::Query, response_code::ResponseCode, Message,
    },
    rr::{record_data::RData, record_type::RecordType, Name},
};
use lru::LruCache;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;
use tracing::{debug, trace, Instrument};

use crate::{app::dispatcher::Dispatcher, option, proxy::*, session::*};

#[derive(Clone, Debug)]
struct CacheEntry {
    pub ips: Vec<IpAddr>,
    // The deadline this entry should be considered expired.
    pub deadline: Instant,
}

#[derive(Debug)]
enum Resolver {
    Server(SocketAddr),
    System,
}

impl fmt::Display for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Server(addr) => addr.to_string(),
                Self::System => "system".to_string(),
            }
        )
    }
}

pub struct DnsClient {
    dispatcher: Option<Weak<Dispatcher>>,
    servers: Vec<Resolver>,
    hosts: HashMap<String, Vec<IpAddr>>,
    ipv4_cache: Arc<TokioMutex<LruCache<String, CacheEntry>>>,
    ipv6_cache: Arc<TokioMutex<LruCache<String, CacheEntry>>>,
}

impl DnsClient {
    fn load_servers(dns: &crate::config::Dns) -> Result<Vec<Resolver>> {
        let mut servers = Vec::new();
        for server in dns.servers.iter() {
            if server.to_lowercase() == "system" {
                servers.push(Resolver::System);
            } else {
                servers.push(Resolver::Server(SocketAddr::new(
                    server.parse::<IpAddr>()?,
                    53,
                )));
            }
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

    pub fn new(dns: &protobuf::MessageField<crate::config::Dns>) -> Result<Self> {
        let dns = if let Some(dns) = dns.as_ref() {
            dns
        } else {
            return Err(anyhow!("empty dns config"));
        };
        let servers = Self::load_servers(dns)?;
        let hosts = Self::load_hosts(dns);
        let ipv4_cache = Arc::new(TokioMutex::new(LruCache::<String, CacheEntry>::new(
            NonZeroUsize::new(*option::DNS_CACHE_SIZE).unwrap(),
        )));
        let ipv6_cache = Arc::new(TokioMutex::new(LruCache::<String, CacheEntry>::new(
            NonZeroUsize::new(*option::DNS_CACHE_SIZE).unwrap(),
        )));

        Ok(Self {
            dispatcher: None,
            servers,
            hosts,
            ipv4_cache,
            ipv6_cache,
        })
    }

    pub fn replace_dispatcher(&mut self, dispatcher: Weak<Dispatcher>) {
        self.dispatcher.replace(dispatcher);
    }

    pub fn reload(&mut self, dns: &protobuf::MessageField<crate::config::Dns>) -> Result<()> {
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

    async fn resolve_with_server(
        &self,
        is_direct: bool,
        request: Vec<u8>,
        host: &str,
        server: &SocketAddr,
    ) -> Result<CacheEntry> {
        let (socket, span) = if is_direct {
            debug!("direct lookup");
            let socket = self.new_udp_socket(server).await?;
            (
                Box::new(StdOutboundDatagram::new(socket)) as Box<dyn OutboundDatagram>,
                tracing::Span::current(),
            )
        } else {
            debug!("dispatched lookup");
            if let Some(dispatcher_weak) = self.dispatcher.as_ref() {
                // The source address will be used to determine which address the
                // underlying socket will bind.
                let source = match server {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                };
                let sess = Session {
                    network: Network::Udp,
                    source,
                    destination: SocksAddr::from(server),
                    inbound_tag: "internal".to_string(),
                    ..Default::default()
                };
                let span = sess.create_span();
                if let Some(dispatcher) = dispatcher_weak.upgrade() {
                    (dispatcher.dispatch_datagram(sess).await?, span)
                } else {
                    return Err(anyhow!("dispatcher is deallocated"));
                }
            } else {
                return Err(anyhow!("could not find a dispatcher"));
            }
        };

        async move {
            let (mut r, mut s) = socket.split();
            let server = SocksAddr::from(server);
            let mut last_err = None;
            for _i in 0..*option::MAX_DNS_RETRIES {
                debug!("looking up host {} on {}", host, server);
                let start = tokio::time::Instant::now();
                // 1) send DNS request
                if let Err(err) = s.send_to(&request, &server).await {
                    last_err = Some(anyhow!("send DNS request to {} failed: {}", server, err));
                    // socket send_to error, retry
                    continue;
                }
                // 2) wait response
                let mut buf = vec![0u8; 512];
                let recv_result = match timeout(
                    Duration::from_secs(*option::DNS_TIMEOUT),
                    r.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((n, _))) => Ok((n, ())),
                    Ok(Err(err)) => {
                        Err(anyhow!("recv DNS response from {} failed: {}", server, err))
                    } // socket recv_from error
                    Err(e) => Err(anyhow!("recv DNS response from {} timeout: {}", server, e)), // timeout
                };
                // retry
                if let Err(err) = recv_result {
                    last_err = Some(err);
                    continue;
                }
                // happy path !!
                let n: usize = recv_result.unwrap().0;
                // 3) parse resp
                let resp = match Message::from_vec(&buf[..n]) {
                    Ok(resp) => resp,
                    Err(err) => {
                        last_err =
                            Some(anyhow!("parse DNS message from {} failed: {}", server, err));
                        // broken response, no retry
                        break;
                    }
                };
                // 4) check resp code
                if resp.response_code() != ResponseCode::NoError {
                    last_err = Some(anyhow!(
                        "DNS response from {} for {} error: {}",
                        server,
                        host,
                        resp.response_code()
                    ));
                    // error response, no retry
                    //
                    // TODO Needs more careful investigations, I'm not quite sure about
                    // this.
                    break;
                }
                // 5) find address
                let mut ips = Vec::new();
                for ans in resp.answers() {
                    // TODO checks?
                    if let Some(data) = ans.data() {
                        match data {
                            RData::A(ip) => {
                                ips.push(IpAddr::V4(**ip));
                            }
                            RData::AAAA(ip) => {
                                ips.push(IpAddr::V6(**ip));
                            }
                            _ => (),
                        }
                    }
                }

                if ips.is_empty() {
                    // response with 0 records
                    //
                    // TODO Not sure how to due with this.
                    last_err = Some(anyhow!(
                        "no records in DNS response from {} for {}",
                        server,
                        host
                    ));
                    break;
                }
                // 6) return cache entry
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

                let Some(deadline) = Instant::now().checked_add(Duration::from_secs(ttl.into()))
                else {
                    last_err = Some(anyhow!("invalid ttl"));
                    break;
                };

                let entry = CacheEntry { ips, deadline };
                debug!("ips for {}: {:#?}", host, &entry);
                return Ok(entry);
            }
            Err(last_err.unwrap_or_else(|| anyhow!("all lookup attempts for {} failed", host)))
        }
        .instrument(span)
        .await
    }

    async fn resolve_with_system_resolver(&self, host: &str, ty: RecordType) -> Result<CacheEntry> {
        debug!("resolving {} using system resolver", host);
        use std::net::ToSocketAddrs;
        let addr = format!("{}:0", host);
        let start = std::time::Instant::now();
        let ips = tokio::task::spawn_blocking(move || addr.to_socket_addrs())
            .await
            .map_err(|e| anyhow!("spawn blocking failed: {}", e))?
            .map_err(|e| anyhow!("system resolver failed: {}", e))?
            .map(|x| x.ip())
            .filter(|ip| match ty {
                RecordType::A => ip.is_ipv4(),
                RecordType::AAAA => ip.is_ipv6(),
                _ => true,
            })
            .collect::<Vec<_>>();

        debug!(
            "resolved ips={:?} for domain={} from system resolver in {} ms",
            &ips,
            host,
            start.elapsed().as_millis(),
        );
        trace!("ips for {}:\n{:?}", host, &ips);

        if ips.is_empty() {
            return Err(anyhow!("no records"));
        }

        // System resolver result should be considered valid for some time,
        // but we don't have TTL. Using 60s as a fallback.
        let deadline = std::time::Instant::now() + Duration::from_secs(60);

        Ok(CacheEntry { ips, deadline })
    }

    async fn query_task(
        &self,
        is_direct: bool,
        request: Vec<u8>,
        host: &str,
        server: &Resolver,
        ty: RecordType,
    ) -> Result<CacheEntry> {
        match server {
            Resolver::System => self.resolve_with_system_resolver(host, ty).await,
            Resolver::Server(addr) => {
                self.resolve_with_server(is_direct, request, host, addr)
                    .await
            }
        }
    }

    async fn query_record_type(
        &self,
        is_direct: bool,
        name: &Name,
        host: &str,
        ty: RecordType,
    ) -> Result<CacheEntry> {
        let msg = Self::new_query(name.clone(), ty);
        let msg_buf = match msg.to_vec() {
            Ok(b) => b,
            Err(e) => return Err(anyhow!("encode message to buffer failed: {}", e)),
        };
        let mut tasks = Vec::new();
        for server in &self.servers {
            let t = self.query_task(is_direct, msg_buf.clone(), host, server, ty);
            tasks.push(Box::pin(t));
        }
        let (entry, _) = select_ok(tasks.into_iter()).await?;
        Ok(entry)
    }

    async fn dualstack_query<P, F>(
        &self,
        preferred: &mut P,
        fallback: &mut F,
        delay: Duration,
    ) -> Result<(CacheEntry, Option<CacheEntry>)>
    where
        P: std::future::Future<Output = Result<CacheEntry>> + Unpin,
        F: std::future::Future<Output = Result<CacheEntry>> + Unpin,
    {
        let delay_fut = tokio::time::sleep(delay);
        tokio::pin!(delay_fut);

        let first = tokio::select! {
            biased;
            r = &mut *preferred => Some((true, r)),
            _ = &mut delay_fut => None,
        };

        let (first_is_preferred, first_res) = match first {
            Some(v) => v,
            None => tokio::select! {
                r = &mut *preferred => (true, r),
                r = &mut *fallback => (false, r),
            },
        };

        match first_res {
            Ok(entry) => {
                let other = if first_is_preferred {
                    match timeout(Duration::from_millis(0), &mut *fallback).await {
                        Ok(Ok(e)) => Some(e),
                        _ => None,
                    }
                } else {
                    match timeout(Duration::from_millis(0), &mut *preferred).await {
                        Ok(Ok(e)) => Some(e),
                        _ => None,
                    }
                };
                Ok((entry, other))
            }
            Err(err1) => {
                let second_res = if first_is_preferred {
                    (&mut *fallback).await
                } else {
                    (&mut *preferred).await
                };
                match second_res {
                    Ok(entry) => Ok((entry, None)),
                    Err(err2) => Err(anyhow!("all dns queries failed: {}; {}", err1, err2)),
                }
            }
        }
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

        let fetch_order = match (*crate::option::ENABLE_IPV6, *crate::option::PREFER_IPV6) {
            (true, true) => vec![&self.ipv6_cache, &self.ipv4_cache],
            (true, false) => vec![&self.ipv4_cache, &self.ipv6_cache],
            _ => vec![&self.ipv4_cache],
        };

        // Query caches in priority order
        for cache in fetch_order {
            if let Some(entry) = cache.lock().await.get(host) {
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

        // Return results or error if no cached IPs found
        if !cached_ips.is_empty() {
            Ok(cached_ips)
        } else {
            Err(anyhow!("empty result"))
        }
    }

    pub async fn lookup(&self, host: &String) -> Result<Vec<IpAddr>> {
        self._lookup(host, false).await
    }

    pub async fn direct_lookup(&self, host: &String) -> Result<Vec<IpAddr>> {
        self._lookup(host, true).await
    }

    pub async fn _lookup(&self, host: &String, is_direct: bool) -> Result<Vec<IpAddr>> {
        let span = tracing::info_span!("dns_lookup", host = %host);
        self._lookup_inner(host, is_direct).instrument(span).await
    }

    async fn _lookup_inner(&self, host: &String, is_direct: bool) -> Result<Vec<IpAddr>> {
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

        if *crate::option::ENABLE_IPV6 {
            let delay = Duration::from_millis(*crate::option::DNS_DUALSTACK_DELAY_MS);
            let mut a_fut = Box::pin(self.query_record_type(is_direct, &name, host, RecordType::A));
            let mut aaaa_fut =
                Box::pin(self.query_record_type(is_direct, &name, host, RecordType::AAAA));

            let (first, second) = if *crate::option::PREFER_IPV6 {
                self.dualstack_query(&mut aaaa_fut, &mut a_fut, delay)
                    .await?
            } else {
                self.dualstack_query(&mut a_fut, &mut aaaa_fut, delay)
                    .await?
            };

            let mut ips = first.ips.clone();
            self.cache_insert(host, first).await;
            if let Some(second) = second {
                ips.extend_from_slice(&second.ips);
                self.cache_insert(host, second).await;
            }
            if !ips.is_empty() {
                return Ok(ips);
            }
            return Err(anyhow!("could not resolve to any address"));
        }

        let entry = self
            .query_record_type(is_direct, &name, host, RecordType::A)
            .await?;
        let ips = entry.ips.clone();
        self.cache_insert(host, entry).await;
        if !ips.is_empty() {
            return Ok(ips);
        }
        Err(anyhow!("could not resolve to any address"))
    }
}

impl UdpConnector for DnsClient {}
