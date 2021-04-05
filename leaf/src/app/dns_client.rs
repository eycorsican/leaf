use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
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
    cache: Arc<TokioMutex<LruCache<String, Vec<IpAddr>>>>,
}

impl Default for DnsClient {
    fn default() -> Self {
        let servers = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
        ];
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let cache = Arc::new(TokioMutex::new(LruCache::<String, Vec<IpAddr>>::new(
            option::DNS_CACHE_SIZE,
        )));
        DnsClient {
            servers,
            bind_addr,
            hosts: HashMap::new(),
            cache,
        }
    }
}

impl DnsClient {
    pub fn new(dns: &protobuf::SingularPtrField<crate::config::Dns>) -> Result<Self> {
        let dns = if let Some(dns) = dns.as_ref() {
            dns
        } else {
            return Err(anyhow!("empty dns config"));
        };
        let mut servers = Vec::new();
        let mut hosts = HashMap::new();
        for server in dns.servers.iter() {
            if let Ok(ip) = server.parse::<IpAddr>() {
                servers.push(SocketAddr::new(ip, 53));
            }
        }
        for (name, ips) in dns.hosts.iter() {
            hosts.insert(name.to_owned(), ips.values.to_vec());
        }
        if servers.is_empty() {
            return Err(anyhow!("no dns servers"));
        }
        let bind_addr = {
            let addr = format!("{}:0", &dns.bind);
            let addr = SocketAddrV4::from_str(&addr)
                .map_err(|e| anyhow!("invalid bind addr [{}] in dns: {}", &dns.bind, e))?;
            SocketAddr::from(addr)
        };

        let cache = Arc::new(TokioMutex::new(LruCache::<String, Vec<IpAddr>>::new(
            option::DNS_CACHE_SIZE,
        )));
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
        Ok(DnsClient {
            servers,
            bind_addr,
            hosts: parsed_hosts,
            cache,
        })
    }

    /// Updates the cache according to the IP address successfully connected.
    pub async fn optimize_cache(&self, address: String, connected_ip: IpAddr) {
        // Nothing to do if the target address is an IP address.
        if address.parse::<IpAddr>().is_ok() {
            return;
        }

        // If the connected IP is not in the first place, we should optimize it.
        let mut new_ips = if let Some(ips) = self.cache.lock().await.get(&address) {
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
            self.cache.lock().await.put(address, new_ips);
            trace!("updated cache");
        }
    }

    async fn query_task(
        &self,
        request: Box<[u8]>,
        domain: &str,
        server: &SocketAddr,
        bind_addr: &SocketAddr,
    ) -> Result<Vec<IpAddr>> {
        let socket = self.create_udp_socket(bind_addr).await?;
        let mut last_err = None;
        for _i in 0..option::MAX_DNS_RETRIES {
            debug!("looking up domain {} on {}", domain, server);
            let start = tokio::time::Instant::now();
            match socket.send_to(&request, server).await {
                Ok(_) => {
                    let mut buf = vec![0u8; 512];
                    match timeout(
                        Duration::from_secs(option::DNS_TIMEOUT),
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
                                    if let RData::A(addr) = ans.rdata() {
                                        addrs.push(IpAddr::V4(addr.to_owned()));
                                    }
                                }
                                if !addrs.is_empty() {
                                    let elapsed = tokio::time::Instant::now().duration_since(start);
                                    debug!(
                                        "return {} ips for {} from {} in {}ms",
                                        addrs.len(),
                                        domain,
                                        server,
                                        elapsed.as_millis(),
                                    );
                                    trace!("ips for {}:\n{:#?}:", domain, &addrs);
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
        Err(last_err.unwrap_or_else(|| anyhow!("could not resolve to any address")))
    }

    pub async fn lookup(&self, domain: String) -> Result<Vec<IpAddr>> {
        self.lookup_with_bind(domain, &self.bind_addr).await
    }

    pub async fn lookup_with_bind(
        &self,
        domain: String,
        bind_addr: &SocketAddr,
    ) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        if let Some(ips) = self.cache.lock().await.get(&domain) {
            return Ok(ips.to_vec());
        }

        // Making cache lookup a priority rather than static hosts lookup
        // and insert the static IPs to the cache because there's a chance
        // for the IPs in the cache to be re-ordered.
        if !self.hosts.is_empty() {
            if let Some(ips) = self.hosts.get(&domain) {
                if !ips.is_empty() {
                    if ips.len() > 1 {
                        self.cache.lock().await.put(domain.to_owned(), ips.to_vec());
                    }
                    return Ok(ips.to_vec());
                }
            }
        }

        let mut msg = Message::new();

        let mut fqdn = domain.clone();
        fqdn.push('.');
        let name = match Name::from_str(&fqdn) {
            Ok(n) => n,
            Err(e) => return Err(anyhow!("invalid domain name [{}]: {}", &domain, e)),
        };
        let query = Query::query(name, RecordType::A);
        msg.add_query(query);

        let mut rng = StdRng::from_entropy();
        let id: u16 = rng.gen();
        msg.set_id(id);

        msg.set_op_code(OpCode::Query);
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(true);

        let msg_buf = match msg.to_vec() {
            Ok(b) => b,
            Err(e) => return Err(anyhow!("encode message to buffer failed: {}", e)),
        };

        let mut tasks = Vec::new();
        for server in &self.servers {
            let t = self.query_task(
                msg_buf.clone().into_boxed_slice(),
                &domain,
                &server,
                bind_addr,
            );
            tasks.push(Box::pin(t));
        }
        match select_ok(tasks.into_iter()).await {
            Ok(v) => {
                self.cache.lock().await.put(domain.to_owned(), v.0.clone());
                Ok(v.0)
            }
            Err(e) => Err(anyhow!("all dns servers failed, last error: {}", e)),
        }
    }
}

impl UdpConnector for DnsClient {}
