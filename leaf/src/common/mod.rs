pub mod crypto;
pub mod dns_client;
pub mod log;
pub mod mutex;
pub mod resolver;

#[cfg(any(target_os = "ios", target_os = "macos", target_os = "linux"))]
pub mod fake_dns;
