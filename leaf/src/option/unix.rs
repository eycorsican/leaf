/// Maximum number of proxy outbound TCP connections allowed at the same time.
pub static ENDPOINT_TCP_CONCURRENCY: usize = 1024;

/// Maximum number of direct outbound TCP connections allowed at the same time.
pub static DIRECT_TCP_CONCURRENCY: usize = 1024;

/// DNS cache size in the built-in DNS client.
pub static DNS_CACHE_SIZE: usize = 32;
