use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::LazyLock;
use std::sync::atomic::AtomicBool;

// Gets an environment variable by a key and parses as type `T` or returns
// the provided default value.
fn get_env_var_or<T>(key: &str, default: T) -> T
where
    T: FromStr,
{
    if let Ok(v) = env::var(key) {
        if let Ok(v) = v.parse::<T>() {
            return v;
        }
    }
    default
}

fn get_env_var_or_else<T, F>(key: &str, f: F) -> T
where
    T: FromStr,
    F: FnOnce() -> T,
{
    if let Ok(v) = env::var(key) {
        if let Ok(v) = v.parse::<T>() {
            return v;
        }
    }
    f()
}

#[cfg(target_os = "ios")]
/// Maximum number of proxy outbound TCP connections allowed at the same time.
pub static ENDPOINT_TCP_CONCURRENCY: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("ENDPOINT_TCP_CONCURRENCY", 45));
#[cfg(target_os = "ios")]
/// Maximum number of direct outbound TCP connections allowed at the same time.
pub static DIRECT_TCP_CONCURRENCY: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("DIRECT_TCP_CONCURRENCY", 64));
#[cfg(target_os = "ios")]
/// DNS cache size in the built-in DNS client.
pub static DNS_CACHE_SIZE: LazyLock<usize> = LazyLock::new(|| get_env_var_or("DNS_CACHE_SIZE", 64));

#[cfg(not(target_os = "ios"))]
/// Maximum number of proxy outbound TCP connections allowed at the same time.
pub static ENDPOINT_TCP_CONCURRENCY: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("ENDPOINT_TCP_CONCURRENCY", 1024));
#[cfg(not(target_os = "ios"))]
/// Maximum number of direct outbound TCP connections allowed at the same time.
pub static DIRECT_TCP_CONCURRENCY: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("DIRECT_TCP_CONCURRENCY", 1024));
#[cfg(not(target_os = "ios"))]
/// DNS cache size in the built-in DNS client.
pub static DNS_CACHE_SIZE: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("DNS_CACHE_SIZE", 512));

/// Maximum number of recent connections stored in StatManager.
pub static MAX_RECENT_CONNECTIONS: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("MAX_RECENT_CONNECTIONS", 0));

pub static HTTP_USER_AGENT: LazyLock<String> = LazyLock::new(|| {
    get_env_var_or_else(
        "HTTP_USER_AGENT",
        || get_env_var_or("USER_AGENT", "".to_string()), // legacy support
    )
});

// The purpose is not to propagate the header, but to extract the forwarded
// source IP. Expects only comma separated IP list and only the first IP is
// taken as the forwarded source. Having this value customizable would benefit
// in case you don't trust the X-Forwarded-For header but there is another header
// which you can trust, for example the CF-Connecting-IP provided by Cloudflare.
pub static HTTP_FORWARDED_HEADER: LazyLock<String> =
    LazyLock::new(|| get_env_var_or("HTTP_FORWARDED_HEADER", "X-Forwarded-For".to_string()));

pub static LOG_CONSOLE_OUT: LazyLock<bool> =
    LazyLock::new(|| get_env_var_or("LOG_CONSOLE_OUT", false));

/// Turn on TLS SNI sniffing, the sniffed SNI would override the original
/// destination address, by default the sniffing would perform only on
/// connections with destination port 443, set also TLS_DOMAIN_SNIFFING_ALL
/// to make the sniffing work on all connections.
pub static TLS_DOMAIN_SNIFFING: LazyLock<AtomicBool> = LazyLock::new(|| {
    let v: bool = get_env_var_or_else(
        "TLS_DOMAIN_SNIFFING",
        || get_env_var_or("DOMAIN_SNIFFING", false), // deprecated env var
    );
    AtomicBool::new(v)
});

/// Turn on TLS SNI sniffing for all TCP connections, this may slow down the
/// connections a little bit, depending on whether the sniff can make an early
/// return.
pub static TLS_DOMAIN_SNIFFING_ALL: LazyLock<AtomicBool> = LazyLock::new(|| {
    let v: bool = get_env_var_or("TLS_DOMAIN_SNIFFING_ALL", false);
    AtomicBool::new(v)
});

/// Turn on HTTP host sniffing, by default only perform on connections with
/// destination port 80.
pub static HTTP_DOMAIN_SNIFFING: LazyLock<AtomicBool> = LazyLock::new(|| {
    let v: bool = get_env_var_or("HTTP_DOMAIN_SNIFFING", false);
    AtomicBool::new(v)
});

/// Turn on HTTP host sniffing for all TCP connections, this may slow down the
/// connections a little bit, depending on whether the sniff can make an early
/// return.
pub static HTTP_DOMAIN_SNIFFING_ALL: LazyLock<AtomicBool> = LazyLock::new(|| {
    let v: bool = get_env_var_or("HTTP_DOMAIN_SNIFFING_ALL", false);
    AtomicBool::new(v)
});

/// Override the original destination with the sniffed domain.
pub static DOMAIN_OVERRIDE: LazyLock<AtomicBool> = LazyLock::new(|| {
    let v: bool = get_env_var_or("DOMAIN_OVERRIDE", false);
    AtomicBool::new(v)
});

/// Turn on DNS sniffing, if the destination is an IP, we try to find the
/// domain from the DNS cache.
pub static DNS_DOMAIN_SNIFFING: LazyLock<AtomicBool> = LazyLock::new(|| {
    let v: bool = get_env_var_or("DNS_DOMAIN_SNIFFING", false);
    AtomicBool::new(v)
});

/// Uplink timeout after downlink EOF.
pub static TCP_UPLINK_TIMEOUT: LazyLock<u64> =
    LazyLock::new(|| get_env_var_or("TCP_UPLINK_TIMEOUT", 10));

/// Downlink timeout after uplink EOF.
pub static TCP_DOWNLINK_TIMEOUT: LazyLock<u64> =
    LazyLock::new(|| get_env_var_or("TCP_DOWNLINK_TIMEOUT", 10));

/// Buffer size for uplink and downlink connections, in KB.
pub static LINK_BUFFER_SIZE: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("LINK_BUFFER_SIZE", 2));

pub static NETSTACK_OUTPUT_CHANNEL_SIZE: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("NETSTACK_OUTPUT_CHANNEL_SIZE", 512));

pub static NETSTACK_UDP_UPLINK_CHANNEL_SIZE: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("NETSTACK_UDP_UPLINK_CHANNEL_SIZE", 256));

pub static UDP_UPLINK_CHANNEL_SIZE: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("UDP_UPLINK_CHANNEL_SIZE", 256));

pub static UDP_DOWNLINK_CHANNEL_SIZE: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("UDP_DOWNLINK_CHANNEL_SIZE", 256));

pub static QUIC_ACCEPT_CHANNEL_SIZE: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("QUIC_ACCEPT_CHANNEL_SIZE", 1024));

pub static AMUX_ACCEPT_CHANNEL_SIZE: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("AMUX_ACCEPT_CHANNEL_SIZE", 1024));

pub static AMUX_STREAM_CHANNEL_SIZE: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("AMUX_STREAM_CHANNEL_SIZE", 16));

pub static AMUX_FRAME_CHANNEL_SIZE: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("AMUX_FRAME_CHANNEL_SIZE", 32));

/// Buffer size for UDP datagrams receiving/sending, in KB.
pub static DATAGRAM_BUFFER_SIZE: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("DATAGRAM_BUFFER_SIZE", 2));

/// The timeout for an accepted inbound TCP connection to finish the proxy
/// protocol handshake.
pub static INBOUND_ACCEPT_TIMEOUT: LazyLock<u64> =
    LazyLock::new(|| get_env_var_or("INBOUND_ACCEPT_TIMEOUT", 60));

pub static OUTBOUND_DIAL_TIMEOUT: LazyLock<u64> =
    LazyLock::new(|| get_env_var_or("OUTBOUND_DIAL_TIMEOUT", 4));

pub static OUTBOUND_DIAL_ORDER: LazyLock<crate::proxy::DialOrder> =
    LazyLock::new(
        || match get_env_var_or("OUTBOUND_DIAL_ORDER", "ordered".to_string()).as_str() {
            "random" => crate::proxy::DialOrder::Random,
            "partial-random" => crate::proxy::DialOrder::PartialRandom,
            _ => crate::proxy::DialOrder::Ordered,
        },
    );

/// Maximum outbound dial concurrency.
pub static OUTBOUND_DIAL_CONCURRENCY: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("OUTBOUND_DIAL_CONCURRENCY", 1));

pub static ASSET_LOCATION: LazyLock<String> = LazyLock::new(|| {
    get_env_var_or_else("ASSET_LOCATION", || {
        let mut file = std::env::current_exe().unwrap();
        file.pop();
        file.to_str().unwrap().to_string()
    })
});

pub static CACHE_LOCATION: LazyLock<String> =
    LazyLock::new(|| get_env_var_or("CACHE_LOCATION", "".to_string()));

pub static API_LISTEN: LazyLock<String> =
    LazyLock::new(|| get_env_var_or("API_LISTEN", "".to_string()));

pub static ENABLE_IPV6: LazyLock<bool> = LazyLock::new(|| get_env_var_or("ENABLE_IPV6", false));

pub static PREFER_IPV6: LazyLock<bool> = LazyLock::new(|| get_env_var_or("PREFER_IPV6", false));

pub static UNSPECIFIED_BIND_ADDR: LazyLock<SocketAddr> = LazyLock::new(|| {
    get_env_var_or_else("UNSPECIFIED_BIND_ADDR", || {
        if *ENABLE_IPV6 {
            "[::]:0".to_string().parse().unwrap()
        } else {
            "0.0.0.0:0".to_string().parse().unwrap()
        }
    })
});

pub static OUTBOUND_BINDS: LazyLock<Vec<crate::proxy::OutboundBind>> = LazyLock::new(|| {
    let binds = get_env_var_or("OUTBOUND_INTERFACE", "".to_string());
    if binds.is_empty() {
        return Vec::new();
    }
    let mut outbound_binds = Vec::new();
    for item in binds.split(',').map(str::trim) {
        if let Ok(addr) = crate::common::net::parse_bind_addr(item) {
            outbound_binds.push(crate::proxy::OutboundBind::Ip(addr));
        } else {
            outbound_binds.push(crate::proxy::OutboundBind::Interface(item.to_owned()));
        }
    }
    outbound_binds
});

/// Sets the RPC service endpoint for protecting outbound sockets on Android to
/// avoid infinite loop. The `path` is treated as a Unix domain socket endpoint.
/// The RPC service simply listens for incoming connections, reads an int32 on
/// each connection, treats it as the file descriptor to protect, writes back 0
/// on success.
pub static SOCKET_PROTECT_PATH: LazyLock<String> =
    LazyLock::new(|| get_env_var_or("SOCKET_PROTECT_PATH", "".to_string()));

pub static SOCKET_PROTECT_SERVER: LazyLock<Option<SocketAddr>> = LazyLock::new(|| {
    get_env_var_or("SOCKET_PROTECT_SERVER", "".to_string())
        .parse()
        .ok()
});

pub static GATEWAY_MODE: LazyLock<bool> = LazyLock::new(|| get_env_var_or("GATEWAY_MODE", false));

/// UDP session timeout. A UDP session shall be terminated if there are no
/// activities in this period. The timeouts are observed only when a check
/// is happened.
pub static UDP_SESSION_TIMEOUT: LazyLock<u64> =
    LazyLock::new(|| get_env_var_or("UDP_SESSION_TIMEOUT", 30));

/// UDP session timeout check interval. The interval to check for UDP session
/// timeouts.
pub static UDP_SESSION_TIMEOUT_CHECK_INTERVAL: LazyLock<u64> =
    LazyLock::new(|| get_env_var_or("UDP_SESSION_TIMEOUT_CHECK_INTERVAL", 10));

/// Maximum retries for a specific DNS query for the built-in DNS client.
pub static MAX_DNS_RETRIES: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("MAX_DNS_RETRIES", 4));

/// Timeout for a DNS query for the built-in DNS client.
pub static DNS_TIMEOUT: LazyLock<u64> = LazyLock::new(|| get_env_var_or("DNS_TIMEOUT", 4));

pub static DNS_SERVER_RESELECT_INTERVAL_SECS: LazyLock<u64> =
    LazyLock::new(|| get_env_var_or("DNS_SERVER_RESELECT_INTERVAL_SECS", 30));

pub static DNS_SERVER_SLOW_RESPONSE_MS: LazyLock<u64> =
    LazyLock::new(|| get_env_var_or("DNS_SERVER_SLOW_RESPONSE_MS", 800));

pub static DNS_SERVER_SWITCH_THRESHOLD: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("DNS_SERVER_SWITCH_THRESHOLD", 3));

pub static DNS_SERVER_FALLBACK_CONCURRENCY: LazyLock<usize> =
    LazyLock::new(|| get_env_var_or("DNS_SERVER_FALLBACK_CONCURRENCY", 1));

pub static DNS_DUALSTACK_DELAY_MS: LazyLock<u64> =
    LazyLock::new(|| get_env_var_or("DNS_DUALSTACK_DELAY_MS", 250));

pub static DEFAULT_TUN_NAME: LazyLock<String> =
    LazyLock::new(|| get_env_var_or("DEFAULT_TUN_NAME", "utun233".to_string()));

pub static DEFAULT_TUN_IPV4_ADDR: LazyLock<String> = LazyLock::new(|| {
    #[cfg(windows)]
    {
        get_env_var_or("DEFAULT_TUN_IPV4_ADDR", "10.7.7.2".to_string())
    }
    #[cfg(not(windows))]
    {
        get_env_var_or("DEFAULT_TUN_IPV4_ADDR", "192.168.233.2".to_string())
    }
});

pub static DEFAULT_TUN_IPV4_GW: LazyLock<String> = LazyLock::new(|| {
    #[cfg(windows)]
    {
        get_env_var_or("DEFAULT_TUN_IPV4_GW", "10.7.7.1".to_string())
    }
    #[cfg(not(windows))]
    {
        get_env_var_or("DEFAULT_TUN_IPV4_GW", "192.168.233.1".to_string())
    }
});

pub static DEFAULT_TUN_IPV4_MASK: LazyLock<String> =
    LazyLock::new(|| get_env_var_or("DEFAULT_TUN_IPV4_MASK", "255.255.255.0".to_string()));

pub static DEFAULT_TUN_IPV6_ADDR: LazyLock<String> =
    LazyLock::new(|| get_env_var_or("DEFAULT_TUN_IPV6_ADDR", "2001:2::2".to_string()));

pub static DEFAULT_TUN_IPV6_GW: LazyLock<String> =
    LazyLock::new(|| get_env_var_or("DEFAULT_TUN_IPV6_GW", "2001:2::1".to_string()));

pub static DEFAULT_TUN_IPV6_PREFIXLEN: LazyLock<i32> =
    LazyLock::new(|| get_env_var_or("DEFAULT_TUN_IPV6_PREFIXLEN", 64));
