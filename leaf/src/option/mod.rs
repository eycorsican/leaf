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

lazy_static! {
    pub static ref USER_AGENT: String = {
        get_env_var_or("USER_AGENT", "".to_string())
    };

    pub static ref LOG_CONSOLE_OUT: bool = {
        get_env_var_or("LOG_CONSOLE_OUT", false)
    };

    pub static ref LOG_NO_COLOR: bool = {
        get_env_var_or("LOG_NO_COLOR", false)
    };

    /// Uplink timeout after downlink EOF.
    pub static ref TCP_UPLINK_TIMEOUT: u64 = {
        get_env_var_or("TCP_UPLINK_TIMEOUT", 2)
    };

    /// Downlink timeout after uplink EOF.
    pub static ref TCP_DOWNLINK_TIMEOUT: u64 = {
        get_env_var_or("TCP_DOWNLINK_TIMEOUT", 4)
    };

    /// Buffer size for uplink and downlink connections, in KB.
    pub static ref LINK_BUFFER_SIZE: usize = {
        get_env_var_or("LINK_BUFFER_SIZE", 2)
    };

    pub static ref OUTBOUND_DIAL_TIMEOUT: u64 = {
        get_env_var_or("OUTBOUND_DIAL_TIMEOUT", 4)
    };

    /// Maximum outbound dial concurrency.
    pub static ref OUTBOUND_DIAL_CONCURRENCY: usize = {
        get_env_var_or("OUTBOUND_DIAL_CONCURRENCY", 1)
    };

    pub static ref ASSET_LOCATION: String = {
        let mut file = std::env::current_exe().unwrap();
        file.pop();
        get_env_var_or("ASSET_LOCATION", file.to_str().unwrap().to_string())
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
        let default =  if *ENABLE_IPV6 {
            "[::]:0".to_string().parse().unwrap()
        } else {
            "0.0.0.0:0".to_string().parse().unwrap()
        };
        get_env_var_or("UNSPECIFIED_BIND_ADDR", default)
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
        get_env_var_or("DEFAULT_TUN_IPV4_ADDR", "240.255.0.2".to_string())
    };

    pub static ref DEFAULT_TUN_IPV4_GW: String = {
        get_env_var_or("DEFAULT_TUN_IPV4_GW", "240.255.0.1".to_string())
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
