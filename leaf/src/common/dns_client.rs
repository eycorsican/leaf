use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::future::select_ok;
use log::*;
use lru::LruCache;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::net::UdpSocket;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;
use trust_dns_proto::{
    op::{
        header::MessageType, op_code::OpCode, query::Query, response_code::ResponseCode, Message,
    },
    rr::{record_data::RData, record_type::RecordType, Name},
};

use crate::option;

pub struct DnsClient {
    bind_addr: SocketAddr,
    servers: Vec<SocketAddr>,
    cache: Arc<TokioMutex<LruCache<String, Vec<IpAddr>>>>,
}

impl Default for DnsClient {
    fn default() -> Self {
        let mut dns_servers = Vec::new();
        dns_servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
        dns_servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53));
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let cache = Arc::new(TokioMutex::new(LruCache::<String, Vec<IpAddr>>::new(
            option::DNS_CACHE_SIZE,
        )));
        DnsClient {
            servers: dns_servers,
            bind_addr,
            cache,
        }
    }
}

impl DnsClient {
    pub fn new(servers: Vec<SocketAddr>, bind_addr: SocketAddr) -> Self {
        let cache = Arc::new(TokioMutex::new(LruCache::<String, Vec<IpAddr>>::new(
            option::DNS_CACHE_SIZE,
        )));
        DnsClient {
            servers,
            bind_addr,
            cache,
        }
    }

    async fn query_task(
        request: Box<[u8]>,
        domain: &String,
        server: &SocketAddr,
        bind_addr: &SocketAddr,
    ) -> Result<Vec<IpAddr>> {
        let mut socket = UdpSocket::bind(bind_addr).await?;
        let mut last_err = None;
        for _i in 0..4 {
            debug!("looking up domain {} on {}", domain, server);
            let start = tokio::time::Instant::now();
            match socket.send_to(&request, server).await {
                Ok(_) => {
                    let mut buf = vec![0u8; 512];
                    match timeout(Duration::from_secs(4), socket.recv_from(&mut buf)).await {
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
                                        _ => (),
                                    }
                                }
                                if addrs.len() > 0 {
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

        let mut msg = Message::new();

        let mut fqdn = String::from(domain.clone());
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
            let t = Self::query_task(
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
