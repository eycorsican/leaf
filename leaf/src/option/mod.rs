use std::env;
use std::net::SocketAddr;
use std::str::FromStr;

use lazy_static::lazy_static;

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
lazy_static! {
    /// Maximum number of proxy outbound TCP connections allowed at the same time.
    pub static ref ENDPOINT_TCP_CONCURRENCY: usize = {
        get_env_var_or("ENDPOINT_TCP_CONCURRENCY", 45)
    };

    /// Maximum number of direct outbound TCP connections allowed at the same time.
    pub static ref DIRECT_TCP_CONCURRENCY: usize = {
        get_env_var_or("DIRECT_TCP_CONCURRENCY", 64)
    };

    /// DNS cache size in the built-in DNS client.
    pub static ref DNS_CACHE_SIZE: usize = {
        get_env_var_or("DNS_CACHE_SIZE", 64)
    };
}

#[cfg(not(target_os = "ios"))]
lazy_static! {
    /// Maximum number of proxy outbound TCP connections allowed at the same time.
    pub static ref ENDPOINT_TCP_CONCURRENCY: usize = {
        get_env_var_or("ENDPOINT_TCP_CONCURRENCY", 1024)
    };

    /// Maximum number of direct outbound TCP connections allowed at the same time.
    pub static ref DIRECT_TCP_CONCURRENCY: usize = {
        get_env_var_or("DIRECT_TCP_CONCURRENCY", 1024)
    };

    /// DNS cache size in the built-in DNS client.
    pub static ref DNS_CACHE_SIZE: usize = {
        get_env_var_or("DNS_CACHE_SIZE", 512)
    };
}

#[cfg(feature = "stat")]
lazy_static! {
    pub static ref ENABLE_STATS: bool = get_env_var_or("ENABLE_STATS", false);
}

lazy_static! {
    pub static ref HTTP_USER_AGENT: String = {
        get_env_var_or_else(
            "HTTP_USER_AGENT",
            || get_env_var_or("USER_AGENT", "".to_string()), // legacy support
        )
    };

    // The purpose is not to propagate the header, but to extract the forwarded
    // source IP. Expects only comma separated IP list and only the first IP is
    // taken as the forwarded source. Having this value customizable would benefit
    // in case you don't trust the X-Forwarded-For header but there is another header
    // which you can trust, for example the CF-Connecting-IP provided by Cloudflare.
    pub static ref HTTP_FORWARDED_HEADER: String = {
        get_env_var_or("HTTP_FORWARDED_HEADER", "X-Forwarded-For".to_string())
    };

    pub static ref LOG_CONSOLE_OUT: bool = {
        get_env_var_or("LOG_CONSOLE_OUT", false)
    };

    pub static ref LOG_NO_COLOR: bool = {
        get_env_var_or("LOG_NO_COLOR", false)
    };

    /// Turn on TLS SNI sniffing, the sniffed SNI would override the original
    /// destination address, by default the sniffing would perform only on
    /// connections with destination port 443, set also TLS_DOMAIN_SNIFFING_ALL
    /// to make the sniffing work on all connections.
    pub static ref TLS_DOMAIN_SNIFFING: bool = {
        get_env_var_or_else(
            "TLS_DOMAIN_SNIFFING",
            || get_env_var_or("DOMAIN_SNIFFING", false), // deprecated env var
        )
    };

    /// Turn on TLS SNI sniffing for all TCP connections, this may slow down the
    /// connections a little bit, depending on whether the sniff can make an early
    /// return.
    pub static ref TLS_DOMAIN_SNIFFING_ALL: bool = {
        get_env_var_or("TLS_DOMAIN_SNIFFING_ALL", false)
    };

    /// Turn on HTTP host sniffing, by default only perform on connections with
    /// destination port 80.
    pub static ref HTTP_DOMAIN_SNIFFING: bool = {
        get_env_var_or("HTTP_DOMAIN_SNIFFING", false)
    };

    /// Turn on HTTP host sniffing for all TCP connections, this may slow down the
    /// connections a little bit, depending on whether the sniff can make an early
    /// return.
    pub static ref HTTP_DOMAIN_SNIFFING_ALL: bool = {
        get_env_var_or("HTTP_DOMAIN_SNIFFING_ALL", false)
    };

    /// Uplink timeout after downlink EOF.
    pub static ref TCP_UPLINK_TIMEOUT: u64 = {
        get_env_var_or("TCP_UPLINK_TIMEOUT", 10)
    };

    /// Downlink timeout after uplink EOF.
    pub static ref TCP_DOWNLINK_TIMEOUT: u64 = {
        get_env_var_or("TCP_DOWNLINK_TIMEOUT", 10)
    };

    /// Buffer size for uplink and downlink connections, in KB.
    pub static ref LINK_BUFFER_SIZE: usize = {
        get_env_var_or("LINK_BUFFER_SIZE", 2)
    };

    pub static ref NETSTACK_OUTPUT_CHANNEL_SIZE: usize = {
        get_env_var_or("NETSTACK_OUTPUT_CHANNEL_SIZE", 512)
    };

    pub static ref NETSTACK_UDP_UPLINK_CHANNEL_SIZE: usize = {
        get_env_var_or("NETSTACK_UDP_UPLINK_CHANNEL_SIZE", 256)
    };

    pub static ref UDP_UPLINK_CHANNEL_SIZE: usize = {
        get_env_var_or("UDP_UPLINK_CHANNEL_SIZE", 256)
    };

    pub static ref UDP_DOWNLINK_CHANNEL_SIZE: usize = {
        get_env_var_or("UDP_DOWNLINK_CHANNEL_SIZE", 256)
    };

    pub static ref QUIC_ACCEPT_CHANNEL_SIZE: usize = {
        get_env_var_or("QUIC_ACCEPT_CHANNEL_SIZE", 1024)
    };

    pub static ref AMUX_ACCEPT_CHANNEL_SIZE: usize = {
        get_env_var_or("AMUX_ACCEPT_CHANNEL_SIZE", 1024)
    };

    pub static ref AMUX_STREAM_CHANNEL_SIZE: usize = {
        get_env_var_or("AMUX_STREAM_CHANNEL_SIZE", 16)
    };

    pub static ref AMUX_FRAME_CHANNEL_SIZE: usize = {
        get_env_var_or("AMUX_FRAME_CHANNEL_SIZE", 32)
    };

    /// Buffer size for UDP datagrams receiving/sending, in KB.
    pub static ref DATAGRAM_BUFFER_SIZE: usize = {
        get_env_var_or("DATAGRAM_BUFFER_SIZE", 2)
    };

    /// The timeout for an accepted inbound TCP connection to finish the proxy
    /// protocol handshake.
    pub static ref INBOUND_ACCEPT_TIMEOUT: u64 = {
        get_env_var_or("INBOUND_ACCEPT_TIMEOUT", 60)
    };

    pub static ref OUTBOUND_DIAL_TIMEOUT: u64 = {
        get_env_var_or("OUTBOUND_DIAL_TIMEOUT", 4)
    };

    pub static ref OUTBOUND_DIAL_ORDER: crate::proxy::DialOrder = {
        match get_env_var_or("OUTBOUND_DIAL_ORDER", "ordered".to_string()).as_str() {
            "random" => crate::proxy::DialOrder::Random,
            "partial-random" => crate::proxy::DialOrder::PartialRandom,
            _ => crate::proxy::DialOrder::Ordered,
        }
    };

    /// Maximum outbound dial concurrency.
    pub static ref OUTBOUND_DIAL_CONCURRENCY: usize = {
        get_env_var_or("OUTBOUND_DIAL_CONCURRENCY", 1)
    };

    pub static ref ASSET_LOCATION: String = {
        get_env_var_or_else("ASSET_LOCATION", || {
            let mut file = std::env::current_exe().unwrap();
            file.pop();
            file.to_str().unwrap().to_string()
        })
    };

    pub static ref CACHE_LOCATION: String = {
        get_env_var_or("CACHE_LOCATION", "".to_string())
    };

    pub static ref API_LISTEN: String = {
        get_env_var_or("API_LISTEN", "".to_string())
    };

    pub static ref ENABLE_IPV6: bool = {
        get_env_var_or("ENABLE_IPV6", false)
    };

    pub static ref PREFER_IPV6: bool = {
        get_env_var_or("PREFER_IPV6", false)
    };

    pub static ref UNSPECIFIED_BIND_ADDR: SocketAddr = {
        get_env_var_or_else("UNSPECIFIED_BIND_ADDR", || {
            if *ENABLE_IPV6 {
                "[::]:0".to_string().parse().unwrap()
            } else {
                "0.0.0.0:0".to_string().parse().unwrap()
            }
        })
    };

    pub static ref OUTBOUND_BINDS: Vec<crate::proxy::OutboundBind> = {
        let binds = get_env_var_or("OUTBOUND_INTERFACE", "0.0.0.0,::".to_string());
        let mut outbound_binds = Vec::new();
        for item in binds.split(',').map(str::trim) {
            if let Ok(addr) = crate::common::net::parse_bind_addr(item) {
                outbound_binds.push(crate::proxy::OutboundBind::Ip(addr));
            } else {
                outbound_binds.push(crate::proxy::OutboundBind::Interface(item.to_owned()));
            }
        }
        outbound_binds
    };

    /// Sets the RPC service endpoint for protecting outbound sockets on Android to
    /// avoid infinite loop. The `path` is treated as a Unix domain socket endpoint.
    /// The RPC service simply listens for incoming connections, reads an int32 on
    /// each connection, treats it as the file descriptor to protect, writes back 0
    /// on success.
    pub static ref SOCKET_PROTECT_PATH: String = {
        get_env_var_or("SOCKET_PROTECT_PATH", "".to_string())
    };

    pub static ref SOCKET_PROTECT_SERVER: Option<SocketAddr> = {
        get_env_var_or("SOCKET_PROTECT_SERVER", "".to_string()).parse().ok()
    };

    pub static ref GATEWAY_MODE: bool = {
        get_env_var_or("GATEWAY_MODE", false)
    };

    /// UDP session timeout. A UDP session shall be terminated if there are no
    /// activities in this period. The timeouts are observed only when a check
    /// is happened.
    pub static ref UDP_SESSION_TIMEOUT: u64 = {
        get_env_var_or("UDP_SESSION_TIMEOUT", 30)
    };

    /// UDP session timeout check interval. The interval to check for UDP session
    /// timeouts.
    pub static ref UDP_SESSION_TIMEOUT_CHECK_INTERVAL: u64 = {
        get_env_var_or("UDP_SESSION_TIMEOUT_CHECK_INTERVAL", 10)
    };

    /// Maximum retries for a specific DNS query for the built-in DNS client.
    pub static ref MAX_DNS_RETRIES: usize = {
        get_env_var_or("MAX_DNS_RETRIES", 4)
    };

    /// Timeout for a DNS query for the built-in DNS client.
    pub static ref DNS_TIMEOUT: u64 = {
        get_env_var_or("DNS_TIMEOUT", 4)
    };

    pub static ref DEFAULT_TUN_NAME: String = {
        get_env_var_or("DEFAULT_TUN_NAME", "utun233".to_string())
    };

    pub static ref DEFAULT_TUN_IPV4_ADDR: String = {
        get_env_var_or("DEFAULT_TUN_IPV4_ADDR", "192.168.233.2".to_string())
    };

    pub static ref DEFAULT_TUN_IPV4_GW: String = {
        get_env_var_or("DEFAULT_TUN_IPV4_GW", "192.168.233.1".to_string())
    };

    pub static ref DEFAULT_TUN_IPV4_MASK: String = {
        get_env_var_or("DEFAULT_TUN_IPV4_MASK", "255.255.255.0".to_string())
    };

    pub static ref DEFAULT_TUN_IPV6_ADDR: String = {
        get_env_var_or("DEFAULT_TUN_IPV6_ADDR", "2001:2::2".to_string())
    };

    pub static ref DEFAULT_TUN_IPV6_GW: String = {
        get_env_var_or("DEFAULT_TUN_IPV6_GW", "2001:2::1".to_string())
    };

    pub static ref DEFAULT_TUN_IPV6_PREFIXLEN: i32 = {
        get_env_var_or("DEFAULT_TUN_IPV6_PREFIXLEN", 64)
    };
}
