use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_recursion::async_recursion;
use futures::future::select_ok;
use hickory_proto::{
    op::{
        header::MessageType, op_code::OpCode, query::Query, response_code::ResponseCode, Message,
    },
    rr::{record_data::RData, record_type::RecordType, Name},
};
use lru::LruCache;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;
use tracing::{debug, trace, Instrument};

#[cfg(feature = "rustls-tls")]
use {
    std::sync::Arc as SyncArc,
    tokio_rustls::{
        rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
        TlsConnector,
    },
};

#[cfg(all(not(feature = "rustls-tls"), feature = "openssl-tls"))]
use {
    futures::TryFutureExt,
    openssl::ssl::{Ssl, SslConnector, SslMethod},
    std::pin::Pin,
    tokio_openssl::SslStream,
};

use crate::{app::dispatcher::Dispatcher, option, proxy::*, session::*};

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

pub struct DnsClient {
    dispatcher: Option<Weak<Dispatcher>>,
    servers: Vec<Resolver>,
    hosts: HashMap<String, Vec<IpAddr>>,
    ipv4_cache: Arc<TokioMutex<LruCache<String, CacheEntry>>>,
    ipv6_cache: Arc<TokioMutex<LruCache<String, CacheEntry>>>,
    ech_cache: Arc<TokioMutex<LruCache<String, EchCacheEntry>>>,
    ech_query_locks: Arc<TokioMutex<HashMap<String, Arc<TokioMutex<()>>>>>,
}

impl DnsClient {
    fn load_servers(dns: &crate::config::Dns) -> Result<Vec<Resolver>> {
        let mut servers = Vec::new();
        for server in dns.servers.iter() {
            servers.push(Self::parse_server(server)?);
        }
        for server in &servers {
            debug!("loaded dns server: {}", server);
        }
        if servers.is_empty() {
            return Err(anyhow!("no dns servers"));
        }
        Ok(servers)
    }

    fn parse_server(server: &str) -> Result<Resolver> {
        let server_lower = server.to_ascii_lowercase();
        let (server, is_direct) = if server_lower.starts_with("direct:") {
            (&server[7..], true)
        } else {
            (server, false)
        };
        if server.eq_ignore_ascii_case("system") {
            return Ok(Resolver::System(is_direct));
        }
        if server.to_ascii_lowercase().starts_with("doh:") {
            return Self::parse_doh_server(server, is_direct);
        }
        let ip = server
            .parse::<IpAddr>()
            .map_err(|e| anyhow!("invalid dns server [{}]: {}", server, e))?;
        Ok(Resolver::Server(SocketAddr::new(ip, 53), is_direct))
    }

    fn parse_doh_server(server: &str, is_direct: bool) -> Result<Resolver> {
        let server = &server[4..];
        let (domain, ip) = if let Some((domain, ip)) = server.split_once('@') {
            (domain, Some(ip))
        } else {
            (server, None)
        };
        if domain.is_empty() {
            return Err(anyhow!(
                "invalid dns server [doh:{}]: empty doh domain",
                server
            ));
        }
        let mut fqdn = domain.to_owned();
        fqdn.push('.');
        Name::from_str(&fqdn).map_err(|e| anyhow!("invalid dns server [doh:{}]: {}", server, e))?;
        let bootstrap_ip = if let Some(ip) = ip {
            if ip.is_empty() {
                return Err(anyhow!(
                    "invalid dns server [doh:{}]: empty bootstrap ip",
                    server
                ));
            }
            Some(
                ip.parse::<IpAddr>()
                    .map_err(|e| anyhow!("invalid dns server [doh:{}]: {}", server, e))?,
            )
        } else {
            None
        };
        Ok(Resolver::DoH(DohResolver {
            domain: domain.to_string(),
            bootstrap_ip,
            is_direct,
        }))
    }

    async fn resolve_doh_bootstrap_addr(
        &self,
        domain: &str,
        bootstrap_ip: Option<IpAddr>,
    ) -> Result<SocketAddr> {
        if let Some(ip) = bootstrap_ip {
            return Ok(SocketAddr::new(ip, 443));
        }
        let domain = domain.to_owned();
        let addr = tokio::task::spawn_blocking(move || {
            (domain.as_str(), 443)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
        })
        .await
        .map_err(|e| anyhow!("spawn blocking failed: {}", e))?
        .ok_or_else(|| anyhow!("bootstrap failed: no resolved address"))?;
        Ok(addr)
    }

    async fn connect_doh_tcp_stream(
        &self,
        doh: &DohResolver,
        bootstrap_addr: SocketAddr,
    ) -> Result<AnyStream> {
        if doh.is_direct {
            let stream = TcpStream::connect(bootstrap_addr).await?;
            return Ok(Box::new(stream));
        }
        if let Some(dispatcher_weak) = self.dispatcher.as_ref() {
            if let Some(dispatcher) = dispatcher_weak.upgrade() {
                let source = match bootstrap_addr {
                    SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                };
                let sess = Session {
                    network: Network::Tcp,
                    source,
                    destination: SocksAddr::from(bootstrap_addr),
                    inbound_tag: "dnsclient".to_string(),
                    ..Default::default()
                };
                return dispatcher
                    .dispatch_stream_outbound(sess)
                    .await
                    .map_err(|e| anyhow!("dispatch stream failed: {}", e));
            }
            return Err(anyhow!("dispatcher is gone"));
        }
        Err(anyhow!("no dispatcher"))
    }

    #[cfg(feature = "rustls-tls")]
    async fn wrap_doh_tls_stream(stream: AnyStream, server_name: &str) -> Result<AnyStream> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(SyncArc::new(config));
        let domain = ServerName::try_from(server_name.to_owned())
            .map_err(|e| anyhow!("invalid tls server name {}: {}", server_name, e))?;
        let tls_stream = connector
            .connect(domain, stream)
            .await
            .map_err(|e| anyhow!("connect tls failed: {}", e))?;
        Ok(Box::new(tls_stream))
    }

    #[cfg(all(not(feature = "rustls-tls"), feature = "openssl-tls"))]
    async fn wrap_doh_tls_stream(stream: AnyStream, server_name: &str) -> Result<AnyStream> {
        let ssl_connector = SslConnector::builder(SslMethod::tls())
            .map_err(|e| anyhow!("create ssl connector failed: {}", e))?
            .build();
        let mut ssl =
            Ssl::new(ssl_connector.context()).map_err(|e| anyhow!("new ssl failed: {}", e))?;
        ssl.set_hostname(server_name)
            .map_err(|e| anyhow!("set tls name failed: {}", e))?;
        let mut stream =
            SslStream::new(ssl, stream).map_err(|e| anyhow!("new ssl stream failed: {}", e))?;
        Pin::new(&mut stream)
            .connect()
            .map_err(|e| anyhow!("connect ssl stream failed: {}", e))
            .await?;
        Ok(Box::new(stream))
    }

    #[cfg(not(any(feature = "rustls-tls", feature = "openssl-tls")))]
    async fn wrap_doh_tls_stream(_stream: AnyStream, _server_name: &str) -> Result<AnyStream> {
        Err(anyhow!("no tls backend available"))
    }

    fn build_doh_http_request(domain: &str, body_len: usize) -> String {
        format!(
            "POST /dns-query HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            domain, body_len
        )
    }

    fn decode_chunked_body(mut data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let line_end = data
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or_else(|| anyhow!("invalid chunked response"))?;
            let size_line = std::str::from_utf8(&data[..line_end])
                .map_err(|e| anyhow!("invalid chunk size line: {}", e))?;
            let size_hex = size_line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_hex, 16)
                .map_err(|e| anyhow!("invalid chunk size: {}", e))?;
            data = &data[line_end + 2..];
            if size == 0 {
                return Ok(out);
            }
            if data.len() < size + 2 {
                return Err(anyhow!("incomplete chunked body"));
            }
            out.extend_from_slice(&data[..size]);
            if &data[size..size + 2] != b"\r\n" {
                return Err(anyhow!("invalid chunk terminator"));
            }
            data = &data[size + 2..];
        }
    }

    fn parse_doh_http_body(resp: &[u8]) -> Result<Vec<u8>> {
        let header_end = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| anyhow!("invalid http response"))?;
        let header_bytes = &resp[..header_end];
        let body = &resp[header_end + 4..];
        let header_text = std::str::from_utf8(header_bytes)
            .map_err(|e| anyhow!("invalid http headers: {}", e))?;
        let mut lines = header_text.split("\r\n");
        let status_line = lines.next().ok_or_else(|| anyhow!("missing status line"))?;
        let mut status_parts = status_line.split_whitespace();
        let _http = status_parts.next();
        let code = status_parts
            .next()
            .ok_or_else(|| anyhow!("invalid status line"))?
            .parse::<u16>()
            .map_err(|e| anyhow!("invalid status code: {}", e))?;
        if code != 200 {
            return Err(anyhow!("doh server returned http status {}", code));
        }
        let mut content_length = None;
        let mut chunked = false;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_ascii_lowercase();
                let value = v.trim().to_ascii_lowercase();
                if key == "content-length" {
                    let len = value
                        .parse::<usize>()
                        .map_err(|e| anyhow!("invalid content-length: {}", e))?;
                    content_length = Some(len);
                } else if key == "transfer-encoding" && value.contains("chunked") {
                    chunked = true;
                }
            }
        }
        if chunked {
            return Self::decode_chunked_body(body);
        }
        if let Some(len) = content_length {
            if body.len() < len {
                return Err(anyhow!("incomplete http body"));
            }
            return Ok(body[..len].to_vec());
        }
        Ok(body.to_vec())
    }

    async fn query_doh_message(
        &self,
        request: &[u8],
        host: &str,
        resolver: &Resolver,
        doh: &DohResolver,
    ) -> Result<(Message, Duration)> {
        for i in 0..*option::MAX_DNS_RETRIES {
            let start = tokio::time::Instant::now();
            debug!(
                "looking up host={} server={} ({}/{})",
                host,
                resolver,
                i + 1,
                *option::MAX_DNS_RETRIES
            );
            let bootstrap_addr = match self
                .resolve_doh_bootstrap_addr(&doh.domain, doh.bootstrap_ip)
                .await
            {
                Ok(addr) => addr,
                Err(err) => {
                    debug!("resolve doh bootstrap failed: {}", err);
                    continue;
                }
            };
            let stream = match self.connect_doh_tcp_stream(doh, bootstrap_addr).await {
                Ok(stream) => stream,
                Err(err) => {
                    debug!("connect doh stream failed: {}", err);
                    continue;
                }
            };
            let mut stream = match Self::wrap_doh_tls_stream(stream, &doh.domain).await {
                Ok(stream) => stream,
                Err(err) => {
                    debug!("connect doh tls failed: {}", err);
                    continue;
                }
            };
            let request_header = Self::build_doh_http_request(&doh.domain, request.len());
            if let Err(err) = stream.write_all(request_header.as_bytes()).await {
                debug!("write doh http header failed: {}", err);
                continue;
            }
            if let Err(err) = stream.write_all(request).await {
                debug!("write doh message body failed: {}", err);
                continue;
            }
            if let Err(err) = stream.flush().await {
                debug!("flush doh request failed: {}", err);
                continue;
            }
            let mut resp = Vec::new();
            if let Err(err) = stream.read_to_end(&mut resp).await {
                debug!("read doh response failed: {}", err);
                continue;
            }
            let dns_payload = match Self::parse_doh_http_body(&resp) {
                Ok(body) => body,
                Err(err) => {
                    debug!("parse doh http response failed: {}", err);
                    continue;
                }
            };
            let message = match Message::from_vec(&dns_payload) {
                Ok(message) => message,
                Err(err) => {
                    debug!("parse doh dns payload failed: {}", err);
                    continue;
                }
            };
            if message.response_code() != ResponseCode::NoError {
                debug!(
                    "error DNS response from {} for {}: {}",
                    resolver,
                    host,
                    message.response_code()
                );
                continue;
            }
            let elapsed = tokio::time::Instant::now().duration_since(start);
            return Ok((message, elapsed));
        }
        Err(anyhow!("all doh lookup attempts failed"))
    }

    async fn query_with_doh(
        &self,
        request: Vec<u8>,
        host: &str,
        resolver: &Resolver,
        doh: &DohResolver,
    ) -> Result<CacheEntry> {
        let (resp, elapsed) = self
            .query_doh_message(&request, host, resolver, doh)
            .await?;
        let mut ips = Vec::new();
        for ans in resp.answers() {
            if let Some(data) = ans.data() {
                match data {
                    RData::A(ip) => ips.push(IpAddr::V4(**ip)),
                    RData::AAAA(ip) => ips.push(IpAddr::V6(**ip)),
                    _ => (),
                }
            }
        }
        if ips.is_empty() {
            return Err(anyhow!(
                "no records in DNS response from {} for {}",
                resolver,
                host
            ));
        }
        let ttl = resp.answers().iter().next().unwrap().ttl();
        let Some(deadline) = Instant::now().checked_add(Duration::from_secs(ttl.into())) else {
            return Err(anyhow!("invalid ttl"));
        };
        debug!(
            "received from server={} ttl={} elapsed={}ms ips={:?}",
            resolver,
            ttl,
            elapsed.as_millis(),
            &ips,
        );
        Ok(CacheEntry { ips, deadline })
    }

    async fn query_ech_with_doh(
        &self,
        request: Vec<u8>,
        host: &str,
        resolver: &Resolver,
        doh: &DohResolver,
        ty: RecordType,
    ) -> Result<EchCacheEntry> {
        let (resp, elapsed) = self
            .query_doh_message(&request, host, resolver, doh)
            .await?;
        let mut last_ttl = None;
        for ans in resp.answers() {
            if ans.record_type() != ty {
                continue;
            }
            if let Some(data) = ans.data() {
                last_ttl = Some(ans.ttl());
                let value = data.to_string();
                if let Some(ech_config_list) = Self::extract_ech_config_list(&value) {
                    let ttl = ans.ttl();
                    let Some(deadline) =
                        Instant::now().checked_add(Duration::from_secs(ttl.into()))
                    else {
                        return Err(anyhow!("invalid ttl"));
                    };
                    debug!(
                        "received ech from server={} type={} ttl={} elapsed={}ms len={}",
                        resolver,
                        ty,
                        ttl,
                        elapsed.as_millis(),
                        ech_config_list.len()
                    );
                    return Ok(EchCacheEntry {
                        ech_config_list,
                        deadline,
                    });
                }
            }
        }
        if last_ttl.is_some() {
            return Err(anyhow!(
                "missing ech parameter in {} record for {} from {}",
                ty,
                host,
                resolver
            ));
        }
        Err(anyhow!("no {} records for {} from {}", ty, host, resolver))
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
        let ech_cache = Arc::new(TokioMutex::new(LruCache::<String, EchCacheEntry>::new(
            NonZeroUsize::new(*option::DNS_CACHE_SIZE).unwrap(),
        )));

        Ok(Self {
            dispatcher: None,
            servers,
            hosts,
            ipv4_cache,
            ipv6_cache,
            ech_cache,
            ech_query_locks: Arc::new(TokioMutex::new(HashMap::new())),
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

    async fn query_with_socket(
        &self,
        socket: Box<dyn OutboundDatagram>,
        request: Vec<u8>,
        span: tracing::Span,
        host: &str,
        resolver: &Resolver,
    ) -> Result<CacheEntry> {
        let resolver_addr = match resolver {
            Resolver::Server(addr, _) => SocksAddr::from(*addr),
            _ => SocksAddr::any_ipv4(),
        };
        async move {
            let (mut r, mut s) = socket.split();
            for i in 0..*option::MAX_DNS_RETRIES {
                debug!(
                    "looking up host={} server={} ({}/{})",
                    host,
                    resolver,
                    i + 1,
                    *option::MAX_DNS_RETRIES
                );
                let start = tokio::time::Instant::now();

                if let Err(err) = s.send_to(&request, &resolver_addr).await {
                    debug!("send DNS query failed: {}", err);
                    continue;
                }

                let mut buf = vec![0u8; 512];
                let n = match timeout(
                    Duration::from_secs(*option::DNS_TIMEOUT),
                    r.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((n, _))) => n,
                    Ok(Err(e)) => {
                        debug!("recv DNS response from {} failed: {}", resolver, e);
                        continue;
                    }
                    Err(e) => {
                        debug!("recv DNS response from {} failed: {}", resolver, e);
                        continue;
                    }
                };

                let resp = match Message::from_vec(&buf[..n]) {
                    Ok(resp) => resp,
                    Err(err) => {
                        debug!("parse DNS message from {} failed: {}", resolver, err);
                        break;
                    }
                };

                if resp.response_code() != ResponseCode::NoError {
                    debug!(
                        "error DNS response from {} for {}: {}",
                        resolver,
                        host,
                        resp.response_code()
                    );
                    break;
                }

                let mut ips = Vec::new();
                for ans in resp.answers() {
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
                    debug!("no records in DNS response from {} for {}", resolver, host);
                    break;
                }

                let elapsed = tokio::time::Instant::now().duration_since(start);
                let ttl = resp.answers().iter().next().unwrap().ttl();
                debug!(
                    "received from server={} ttl={} elapsed={}ms ips={:?}",
                    resolver,
                    ttl,
                    elapsed.as_millis(),
                    &ips,
                );

                let Some(deadline) = Instant::now().checked_add(Duration::from_secs(ttl.into()))
                else {
                    debug!("invalid ttl");
                    break;
                };

                let entry = CacheEntry { ips, deadline };
                return Ok(entry);
            }
            Err(anyhow!("all lookup attempts failed"))
        }
        .instrument(span)
        .await
    }

    fn extract_ech_config_list(rdata: &str) -> Option<String> {
        fn extract_quoted(haystack: &str, key: &str) -> Option<String> {
            let start = haystack.find(key)?;
            let value_start = start + key.len();
            let rest = &haystack[value_start..];
            let end = rest.find('"')?;
            let value = rest[..end].trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }

        fn extract_plain(haystack: &str, key: &str) -> Option<String> {
            let start = haystack.find(key)?;
            let value_start = start + key.len();
            let rest = &haystack[value_start..];
            let end = rest
                .find(|c: char| c.is_ascii_whitespace() || c == ',')
                .unwrap_or(rest.len());
            let value = rest[..end].trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }

        extract_quoted(rdata, "echconfig=\"")
            .or_else(|| extract_quoted(rdata, "ech=\""))
            .or_else(|| extract_plain(rdata, "echconfig="))
            .or_else(|| extract_plain(rdata, "ech="))
    }

    async fn query_ech_with_socket(
        &self,
        socket: Box<dyn OutboundDatagram>,
        request: Vec<u8>,
        span: tracing::Span,
        host: &str,
        resolver: &Resolver,
        ty: RecordType,
    ) -> Result<EchCacheEntry> {
        let resolver_addr = match resolver {
            Resolver::Server(addr, _) => SocksAddr::from(*addr),
            _ => SocksAddr::any_ipv4(),
        };
        async move {
            let (mut r, mut s) = socket.split();
            for i in 0..*option::MAX_DNS_RETRIES {
                debug!(
                    "fetching ech host={} type={} server={} ({}/{})",
                    host,
                    ty,
                    resolver,
                    i + 1,
                    *option::MAX_DNS_RETRIES
                );
                let start = tokio::time::Instant::now();

                if let Err(err) = s.send_to(&request, &resolver_addr).await {
                    debug!("send DNS ech query failed: {}", err);
                    continue;
                }

                let mut buf = vec![0u8; 2048];
                let n = match timeout(
                    Duration::from_secs(*option::DNS_TIMEOUT),
                    r.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((n, _))) => n,
                    Ok(Err(e)) => {
                        debug!("recv DNS ech response from {} failed: {}", resolver, e);
                        continue;
                    }
                    Err(e) => {
                        debug!("recv DNS ech response from {} failed: {}", resolver, e);
                        continue;
                    }
                };

                let resp = match Message::from_vec(&buf[..n]) {
                    Ok(resp) => resp,
                    Err(err) => {
                        debug!("parse DNS ech message from {} failed: {}", resolver, err);
                        break;
                    }
                };

                if resp.response_code() != ResponseCode::NoError {
                    debug!(
                        "error DNS ech response from {} for {}: {}",
                        resolver,
                        host,
                        resp.response_code()
                    );
                    break;
                }

                let mut last_ttl = None;
                for ans in resp.answers() {
                    if ans.record_type() != ty {
                        continue;
                    }
                    if let Some(data) = ans.data() {
                        last_ttl = Some(ans.ttl());
                        let value = data.to_string();
                        if let Some(ech_config_list) = Self::extract_ech_config_list(&value) {
                            let ttl = ans.ttl();
                            let elapsed = tokio::time::Instant::now().duration_since(start);
                            debug!(
                                "received ech from server={} type={} ttl={} elapsed={}ms len={}",
                                resolver,
                                ty,
                                ttl,
                                elapsed.as_millis(),
                                ech_config_list.len()
                            );
                            let Some(deadline) =
                                Instant::now().checked_add(Duration::from_secs(ttl.into()))
                            else {
                                break;
                            };
                            return Ok(EchCacheEntry {
                                ech_config_list,
                                deadline,
                            });
                        }
                    }
                }

                if last_ttl.is_some() {
                    trace!(
                        "ech parameter missing in record host={} type={} server={}",
                        host,
                        ty,
                        resolver
                    );
                    return Err(anyhow!(
                        "missing ech parameter in {} record for {} from {}",
                        ty,
                        host,
                        resolver
                    ));
                }
                return Err(anyhow!("no {} records for {} from {}", ty, host, resolver));
            }
            Err(anyhow!("all ech lookup attempts failed"))
        }
        .instrument(span)
        .await
    }

    async fn resolve_with_server(
        &self,
        is_direct: bool,
        request: Vec<u8>,
        host: &str,
        resolver: &Resolver,
    ) -> Result<CacheEntry> {
        let (socket, span) = match resolver {
            Resolver::Server(server, _) if is_direct => {
                debug!("direct lookup");
                let socket = self.new_udp_socket(server).await?;
                (
                    Box::new(StdOutboundDatagram::new(socket)) as Box<dyn OutboundDatagram>,
                    tracing::Span::current(),
                )
            }
            Resolver::Server(server, _) => {
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
                        inbound_tag: "dnsclient".to_string(),
                        ..Default::default()
                    };
                    let span = sess.span();
                    if let Some(dispatcher) = dispatcher_weak.upgrade() {
                        (
                            dispatcher
                                .dispatch_datagram(sess)
                                .instrument(span.clone())
                                .await?,
                            span,
                        )
                    } else {
                        return Err(anyhow!("dispatcher is gone"));
                    }
                } else {
                    return Err(anyhow!("no dispatcher"));
                }
            }
            Resolver::System(_) => {
                debug!("resolving {} using system resolver", host);
                use std::net::ToSocketAddrs;
                let addr = format!("{}:0", host);
                let start = std::time::Instant::now();
                let ips = tokio::task::spawn_blocking(move || {
                    addr.to_socket_addrs()
                        .map(|iter| iter.map(|x| x.ip()).collect::<Vec<_>>())
                })
                .await
                .map_err(|e| anyhow!("spawn blocking failed: {}", e))?
                .map_err(|e| anyhow!("system resolver failed: {}", e))?;

                debug!(
                    "resolved ips={:?} for domain={} from system resolver in {} ms",
                    &ips,
                    host,
                    start.elapsed().as_millis(),
                );

                if ips.is_empty() {
                    return Err(anyhow!("no records from system resolver"));
                }

                return Ok(CacheEntry {
                    ips,
                    deadline: Instant::now() + Duration::from_secs(60),
                });
            }
            Resolver::DoH(doh) => {
                return self.query_with_doh(request, host, resolver, doh).await;
            }
        };

        self.query_with_socket(socket, request, span, host, resolver)
            .await
    }

    async fn resolve_ech_with_server(
        &self,
        is_direct: bool,
        request: Vec<u8>,
        host: &str,
        resolver: &Resolver,
        ty: RecordType,
    ) -> Result<EchCacheEntry> {
        let (socket, span) = match resolver {
            Resolver::Server(server, _) if is_direct => {
                let socket = self.new_udp_socket(server).await?;
                (
                    Box::new(StdOutboundDatagram::new(socket)) as Box<dyn OutboundDatagram>,
                    tracing::Span::current(),
                )
            }
            Resolver::Server(server, _) => {
                if let Some(dispatcher_weak) = self.dispatcher.as_ref() {
                    let source = match server {
                        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                    };
                    let sess = Session {
                        network: Network::Udp,
                        source,
                        destination: SocksAddr::from(server),
                        inbound_tag: "dnsclient".to_string(),
                        ..Default::default()
                    };
                    let span = sess.span();
                    if let Some(dispatcher) = dispatcher_weak.upgrade() {
                        (
                            dispatcher
                                .dispatch_datagram(sess)
                                .instrument(span.clone())
                                .await?,
                            span,
                        )
                    } else {
                        return Err(anyhow!("dispatcher is gone"));
                    }
                } else {
                    return Err(anyhow!("no dispatcher"));
                }
            }
            Resolver::System(_) => {
                return Err(anyhow!("system resolver does not support {} query", ty));
            }
            Resolver::DoH(doh) => {
                return self
                    .query_ech_with_doh(request, host, resolver, doh, ty)
                    .await;
            }
        };

        self.query_ech_with_socket(socket, request, span, host, resolver, ty)
            .await
    }

    async fn query_task(
        &self,
        is_direct: bool,
        request: Vec<u8>,
        host: &str,
        resolver: &Resolver,
        ty: RecordType,
    ) -> Result<CacheEntry> {
        let res = match timeout(
            Duration::from_secs(*option::DNS_TIMEOUT),
            self.resolve_with_server(is_direct, request, host, resolver),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err(anyhow!("query {} {} timeout", host, ty)),
        };
        match res {
            Ok(entry) => {
                trace!("query {} {} success with server {}", host, ty, resolver);
                Ok(entry)
            }
            Err(e) => {
                debug!(
                    "query {} {} failed with server {}: {}",
                    host, ty, resolver, e
                );
                Err(e)
            }
        }
    }

    async fn query_ech_task(
        &self,
        is_direct: bool,
        request: Vec<u8>,
        host: &str,
        resolver: &Resolver,
        ty: RecordType,
    ) -> Result<EchCacheEntry> {
        let res = match timeout(
            Duration::from_secs(*option::DNS_TIMEOUT),
            self.resolve_ech_with_server(is_direct, request, host, resolver, ty),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err(anyhow!("query {} {} timeout", host, ty)),
        };
        match res {
            Ok(entry) => Ok(entry),
            Err(e) => {
                debug!(
                    "query ech {} {} failed with server {}: {}",
                    host, ty, resolver, e
                );
                Err(e)
            }
        }
    }

    async fn is_direct_outbound(&self, host: &str) -> Result<bool> {
        let mut is_direct_outbound = false;
        if let Some(dispatcher_weak) = self.dispatcher.as_ref() {
            if let Some(dispatcher) = dispatcher_weak.upgrade() {
                let dest = match SocksAddr::try_from((host.to_owned(), 0)) {
                    Ok(d) => d,
                    Err(e) => return Err(anyhow!("invalid host {}: {}", host, e)),
                };
                let sess = Session {
                    destination: dest,
                    skip_resolve: true,
                    ..Default::default()
                };
                if let Ok(Some(tag)) = dispatcher.router.read().await.pick_route(&sess).await {
                    is_direct_outbound = dispatcher.is_direct_outbound(tag).await;
                }
            }
        }
        Ok(is_direct_outbound)
    }

    fn collect_servers(&self, is_direct_outbound: bool) -> Vec<&Resolver> {
        let mut servers = Vec::new();
        if is_direct_outbound {
            for server in &self.servers {
                match server {
                    Resolver::Server(_, true) | Resolver::System(true) => {
                        servers.push(server);
                    }
                    Resolver::DoH(doh) if doh.is_direct => {
                        servers.push(server);
                    }
                    _ => (),
                }
            }
            if servers.is_empty() {
                debug!("no direct dns servers for direct outbound, fallback to normal servers");
                for server in &self.servers {
                    match server {
                        Resolver::Server(_, false) | Resolver::System(false) => {
                            servers.push(server);
                        }
                        Resolver::DoH(doh) if !doh.is_direct => {
                            servers.push(server);
                        }
                        _ => (),
                    }
                }
            }
        } else {
            for server in &self.servers {
                match server {
                    Resolver::Server(_, false) | Resolver::System(false) => {
                        servers.push(server);
                    }
                    Resolver::DoH(doh) if !doh.is_direct => {
                        servers.push(server);
                    }
                    _ => (),
                }
            }
        }
        if servers.is_empty() {
            for server in &self.servers {
                servers.push(server);
            }
        }
        servers
    }

    #[async_recursion]
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

        let is_direct_outbound = self.is_direct_outbound(host).await?;
        let mut tasks = Vec::new();
        let servers = self.collect_servers(is_direct_outbound);
        for server in servers {
            let t = self.query_task(is_direct, msg_buf.clone(), host, server, ty);
            tasks.push(Box::pin(t));
        }

        if tasks.is_empty() {
            return Err(anyhow!("no dns servers available for query"));
        }

        let (entry, _) = select_ok(tasks.into_iter()).await?;
        Ok(entry)
    }

    async fn query_ech_record_type(
        &self,
        is_direct: bool,
        name: &Name,
        host: &str,
        ty: RecordType,
    ) -> Result<EchCacheEntry> {
        let msg = Self::new_query(name.clone(), ty);
        let msg_buf = match msg.to_vec() {
            Ok(b) => b,
            Err(e) => return Err(anyhow!("encode message to buffer failed: {}", e)),
        };
        let is_direct_outbound = self.is_direct_outbound(host).await?;
        let mut tasks = Vec::new();
        let servers = self.collect_servers(is_direct_outbound);
        for server in servers {
            let t = self.query_ech_task(is_direct, msg_buf.clone(), host, server, ty);
            tasks.push(Box::pin(t));
        }
        if tasks.is_empty() {
            return Err(anyhow!("no dns servers available for query"));
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

    async fn get_cached_ech(&self, host: &str) -> Option<String> {
        let mut cache = self.ech_cache.lock().await;
        if let Some(entry) = cache.get(host) {
            if entry
                .deadline
                .checked_duration_since(Instant::now())
                .is_some()
            {
                return Some(entry.ech_config_list.clone());
            }
        }
        cache.pop(host);
        None
    }

    async fn query_ech(&self, host: &str, is_direct: bool) -> Result<EchCacheEntry> {
        let mut fqdn = host.to_owned();
        fqdn.push('.');
        let name = match Name::from_str(&fqdn) {
            Ok(n) => n,
            Err(e) => return Err(anyhow!("invalid domain name [{}]: {}", host, e)),
        };
        let https_res = self
            .query_ech_record_type(is_direct, &name, host, RecordType::HTTPS)
            .await;
        match https_res {
            Ok(entry) => Ok(entry),
            Err(https_err) => {
                let svcb_res = self
                    .query_ech_record_type(is_direct, &name, host, RecordType::SVCB)
                    .await;
                match svcb_res {
                    Ok(entry) => Ok(entry),
                    Err(svcb_err) => Err(anyhow!(
                        "ech query failed for {} with HTTPS ({}) and SVCB ({})",
                        host,
                        https_err,
                        svcb_err
                    )),
                }
            }
        }
    }

    pub async fn lookup_ech_config_list(&self, host: &str) -> Result<String> {
        if let Some(cached) = self.get_cached_ech(host).await {
            return Ok(cached);
        }
        let host_lock = {
            let mut locks = self.ech_query_locks.lock().await;
            locks
                .entry(host.to_owned())
                .or_insert_with(|| Arc::new(TokioMutex::new(())))
                .clone()
        };
        let _query_guard = host_lock.lock().await;
        let result = if let Some(cached) = self.get_cached_ech(host).await {
            Ok(cached)
        } else {
            let entry = self.query_ech(host, true).await?;
            let ech_config_list = entry.ech_config_list.clone();
            self.ech_cache.lock().await.put(host.to_owned(), entry);
            Ok(ech_config_list)
        };
        {
            let mut locks = self.ech_query_locks.lock().await;
            if let Some(current) = locks.get(host) {
                if Arc::ptr_eq(current, &host_lock) {
                    locks.remove(host);
                }
            }
        }
        result
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

    #[async_recursion]
    pub async fn _lookup(&self, host: &String, is_direct: bool) -> Result<Vec<IpAddr>> {
        self._lookup_inner(host, is_direct).await
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{DnsClient, Resolver};

    fn new_client(servers: Vec<&str>) -> DnsClient {
        let mut dns = crate::config::Dns::new();
        dns.servers = servers.into_iter().map(|s| s.to_string()).collect();
        DnsClient::new(&protobuf::MessageField::some(dns)).unwrap()
    }

    fn collect_server_strings(client: &DnsClient, is_direct_outbound: bool) -> Vec<String> {
        client
            .collect_servers(is_direct_outbound)
            .into_iter()
            .map(|server| server.to_string())
            .collect()
    }

    #[test]
    fn load_servers_supports_legacy_and_doh_with_ip() {
        let mut dns = crate::config::Dns::new();
        dns.servers = vec![
            "1.1.1.1".to_string(),
            "direct:system".to_string(),
            "doh:example.com@9.9.9.9".to_string(),
            "direct:doh:example.com@8.8.8.8".to_string(),
            "doh:example.net".to_string(),
        ];
        let servers = DnsClient::load_servers(&dns).unwrap();

        match &servers[0] {
            Resolver::Server(addr, false) => assert_eq!(
                *addr,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
            ),
            _ => panic!("unexpected resolver"),
        }
        match &servers[1] {
            Resolver::System(true) => {}
            _ => panic!("unexpected resolver"),
        }
        match &servers[2] {
            Resolver::DoH(doh) => {
                assert_eq!(doh.domain, "example.com");
                assert_eq!(
                    doh.bootstrap_ip,
                    Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
                );
                assert!(!doh.is_direct);
            }
            _ => panic!("unexpected resolver"),
        }
        match &servers[3] {
            Resolver::DoH(doh) => {
                assert_eq!(doh.domain, "example.com");
                assert_eq!(
                    doh.bootstrap_ip,
                    Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
                );
                assert!(doh.is_direct);
            }
            _ => panic!("unexpected resolver"),
        }
        match &servers[4] {
            Resolver::DoH(doh) => {
                assert_eq!(doh.domain, "example.net");
                assert_eq!(doh.bootstrap_ip, None);
                assert!(!doh.is_direct);
            }
            _ => panic!("unexpected resolver"),
        }
    }

    #[test]
    fn load_servers_rejects_invalid_doh_value() {
        let mut dns = crate::config::Dns::new();
        dns.servers = vec!["doh:@1.1.1.1".to_string()];
        let err = DnsClient::load_servers(&dns).unwrap_err();
        assert!(err.to_string().contains("invalid dns server"));

        dns.servers = vec!["direct:doh:example.com@not-an-ip".to_string()];
        let err = DnsClient::load_servers(&dns).unwrap_err();
        assert!(err.to_string().contains("invalid dns server"));

        dns.servers = vec!["doh:example.com#8.8.8.8".to_string()];
        let err = DnsClient::load_servers(&dns).unwrap_err();
        assert!(err.to_string().contains("invalid dns server"));
    }

    #[test]
    fn collect_servers_includes_direct_doh_for_direct_outbound() {
        let client = new_client(vec![
            "1.1.1.1",
            "doh:normal.example",
            "direct:doh:direct.example@8.8.8.8",
        ]);
        let selected = collect_server_strings(&client, true);
        assert_eq!(selected, vec!["direct:doh:direct.example@8.8.8.8"]);
    }

    #[test]
    fn collect_servers_fallback_to_normal_keeps_non_direct_doh() {
        let client = new_client(vec!["doh:normal.example", "1.1.1.1", "system"]);
        let selected = collect_server_strings(&client, true);
        assert_eq!(
            selected,
            vec![
                "doh:normal.example".to_string(),
                "1.1.1.1:53".to_string(),
                "system".to_string()
            ]
        );
    }

    #[test]
    fn parse_doh_http_body_supports_content_length() {
        let body = b"\x01\x02\x03\x04";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut raw = response.into_bytes();
        raw.extend_from_slice(body);

        let parsed = DnsClient::parse_doh_http_body(&raw).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn parse_doh_http_body_supports_chunked() {
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nABCD\r\n2\r\nEF\r\n0\r\n\r\n";
        let parsed = DnsClient::parse_doh_http_body(response).unwrap();
        assert_eq!(parsed, b"ABCDEF");
    }

    #[test]
    fn parse_doh_http_body_rejects_non_200() {
        let response = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 3\r\n\r\nbad".to_vec();
        let err = DnsClient::parse_doh_http_body(&response).unwrap_err();
        assert!(err
            .to_string()
            .contains("doh server returned http status 503"));
    }
}
