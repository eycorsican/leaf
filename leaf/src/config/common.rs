use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use protobuf::Message;
use serde_derive::{Deserialize, Serialize};

use crate::config::{external_rule, internal};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Dns {
    pub servers: Option<Vec<String>>,
    pub hosts: Option<HashMap<String, Vec<String>>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Log {
    pub level: Option<String>,
    pub output: Option<String>,
    pub format: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CatInboundSettings {
    pub network: Option<String>,
    pub address: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NfInboundSettings {
    #[serde(rename = "driverName")]
    pub driver_name: String,
    pub nfapi: Option<String>,
    #[serde(rename = "fakeDnsExclude")]
    pub fake_dns_exclude: Option<Vec<String>>,
    #[serde(rename = "fakeDnsInclude")]
    pub fake_dns_include: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksInboundSettings {
    pub method: Option<String>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrojanInboundSettings {
    pub passwords: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct WebSocketInboundSettings {
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HcInboundSettings {
    pub path: String,
    #[serde(default)]
    pub request: Option<String>,
    pub response: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct AMuxInboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuicInboundSettings {
    pub certificate: Option<String>,
    #[serde(rename = "certificateKey")]
    pub certificate_key: Option<String>,
    pub alpn: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsInboundSettings {
    pub certificate: Option<String>,
    #[serde(rename = "certificateKey")]
    pub certificate_key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ChainInboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TunInboundSettings {
    pub auto: Option<bool>,
    pub fd: Option<i32>,
    pub name: Option<String>,
    pub address: Option<String>,
    pub gateway: Option<String>,
    pub netmask: Option<String>,
    pub mtu: Option<i32>,
    #[serde(rename = "fakeDnsExclude")]
    pub fake_dns_exclude: Option<Vec<String>>,
    #[serde(rename = "fakeDnsInclude")]
    pub fake_dns_include: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RedirectOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocksOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShadowsocksOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub method: Option<String>,
    pub password: Option<String>,
    pub prefix: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ObfsOutboundSettings {
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrojanOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VMessOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub uuid: Option<String>,
    pub security: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TryAllOutboundSettings {
    pub actors: Option<Vec<String>>,
    #[serde(rename = "delayBase")]
    pub delay_base: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StaticOutboundSettings {
    pub actors: Option<Vec<String>>,
    pub method: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsOutboundSettings {
    #[serde(rename = "serverName")]
    pub server_name: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub certificate: Option<String>,
    pub insecure: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebSocketOutboundSettings {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AMuxOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub actors: Option<Vec<String>>,
    #[serde(rename = "maxAccepts")]
    pub max_accepts: Option<u32>,
    pub concurrency: Option<u32>,
    pub max_recv_bytes: Option<u64>,
    pub max_lifetime: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuicOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    #[serde(rename = "serverName")]
    pub server_name: Option<String>,
    pub certificate: Option<String>,
    pub alpn: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ChainOutboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FailOverOutboundSettings {
    pub actors: Option<Vec<String>>,
    #[serde(rename = "failTimeout")]
    pub fail_timeout: Option<u32>,
    #[serde(rename = "healthCheck")]
    pub health_check: Option<bool>,
    #[serde(rename = "healthCheckTimeout")]
    pub health_check_timeout: Option<u32>,
    #[serde(rename = "healthCheckDelay")]
    pub health_check_delay: Option<u32>,
    #[serde(rename = "healthCheckActive")]
    pub health_check_active: Option<u32>,
    #[serde(rename = "healthCheckPrefers")]
    pub health_check_prefers: Option<Vec<String>>,
    #[serde(rename = "checkInterval")]
    pub check_interval: Option<u32>,
    #[serde(rename = "healthCheckOnStart")]
    pub health_check_on_start: Option<bool>,
    #[serde(rename = "healthCheckWait")]
    pub health_check_wait: Option<bool>,
    #[serde(rename = "healthCheckAttempts")]
    pub health_check_attempts: Option<u32>,
    #[serde(rename = "healthCheckSuccessPercentage")]
    pub health_check_success_percentage: Option<u32>,
    pub failover: Option<bool>,
    #[serde(rename = "fallbackCache")]
    pub fallback_cache: Option<bool>,
    #[serde(rename = "cacheSize")]
    pub cache_size: Option<u32>,
    #[serde(rename = "cacheTimeout")]
    pub cache_timeout: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SelectOutboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PluginOutboundSettings {
    pub path: Option<String>,
    pub args: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Inbound {
    pub tag: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    #[serde(flatten)]
    pub settings: InboundSettings,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum InboundSettings {
    Cat {
        #[serde(default)]
        settings: Option<CatInboundSettings>,
    },
    Nf {
        #[serde(default)]
        settings: Option<NfInboundSettings>,
    },
    Shadowsocks {
        #[serde(default)]
        settings: Option<ShadowsocksInboundSettings>,
    },
    Trojan {
        #[serde(default)]
        settings: Option<TrojanInboundSettings>,
    },
    #[serde(rename = "websocket", alias = "ws")]
    WebSocket {
        #[serde(default)]
        settings: Option<WebSocketInboundSettings>,
    },
    Hc {
        #[serde(default)]
        settings: Option<HcInboundSettings>,
    },
    AMux {
        #[serde(default)]
        settings: Option<AMuxInboundSettings>,
    },
    Quic {
        #[serde(default)]
        settings: Option<QuicInboundSettings>,
    },
    Tls {
        #[serde(default)]
        settings: Option<TlsInboundSettings>,
    },
    Chain {
        #[serde(default)]
        settings: Option<ChainInboundSettings>,
    },
    Tun {
        #[serde(default)]
        settings: Option<TunInboundSettings>,
    },
    Socks,
    Http,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Outbound {
    pub tag: Option<String>,
    #[serde(flatten)]
    pub settings: OutboundSettings,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum OutboundSettings {
    Redirect {
        #[serde(default)]
        settings: Option<RedirectOutboundSettings>,
    },
    Socks {
        #[serde(default)]
        settings: Option<SocksOutboundSettings>,
    },
    Shadowsocks {
        #[serde(default)]
        settings: Option<ShadowsocksOutboundSettings>,
    },
    Obfs {
        #[serde(default)]
        settings: Option<ObfsOutboundSettings>,
    },
    Trojan {
        #[serde(default)]
        settings: Option<TrojanOutboundSettings>,
    },
    VMess {
        #[serde(default)]
        settings: Option<VMessOutboundSettings>,
    },
    TryAll {
        #[serde(default)]
        settings: Option<TryAllOutboundSettings>,
    },
    Static {
        #[serde(default)]
        settings: Option<StaticOutboundSettings>,
    },
    Tls {
        #[serde(default)]
        settings: Option<TlsOutboundSettings>,
    },
    #[serde(rename = "websocket", alias = "ws")]
    WebSocket {
        #[serde(default)]
        settings: Option<WebSocketOutboundSettings>,
    },
    AMux {
        #[serde(default)]
        settings: Option<AMuxOutboundSettings>,
    },
    Quic {
        #[serde(default)]
        settings: Option<QuicOutboundSettings>,
    },
    Chain {
        #[serde(default)]
        settings: Option<ChainOutboundSettings>,
    },
    FailOver {
        #[serde(default)]
        settings: Option<FailOverOutboundSettings>,
    },
    Select {
        #[serde(default)]
        settings: Option<SelectOutboundSettings>,
    },
    Plugin {
        #[serde(default)]
        settings: Option<PluginOutboundSettings>,
    },
    Direct,
    Drop,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Rule {
    #[serde(rename = "type")]
    pub type_field: Option<String>,
    pub ip: Option<Vec<String>>,
    pub domain: Option<Vec<String>>,
    #[serde(rename = "domainKeyword")]
    pub domain_keyword: Option<Vec<String>>,
    #[serde(rename = "domainSuffix")]
    pub domain_suffix: Option<Vec<String>>,
    pub geoip: Option<Vec<String>>,
    pub external: Option<Vec<String>>,
    #[serde(rename = "portRange")]
    pub port_range: Option<Vec<String>>,
    pub network: Option<Vec<String>>,
    #[serde(rename = "inboundTag")]
    pub inbound_tag: Option<Vec<String>>,
    #[serde(rename = "processName")]
    pub process_name: Option<Vec<String>>,
    pub target: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Router {
    pub rules: Option<Vec<Rule>>,
    #[serde(rename = "domainResolve")]
    pub domain_resolve: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Config {
    pub log: Option<Log>,
    pub inbounds: Option<Vec<Inbound>>,
    pub outbounds: Option<Vec<Outbound>>,
    pub router: Option<Router>,
    pub dns: Option<Dns>,
}

fn is_inline_certificate(certificate: &str) -> bool {
    certificate.contains("-----BEGIN")
}

pub fn to_internal(mut config: Config) -> Result<internal::Config> {
    let mut log = internal::Log::new();
    if let Some(ext_log) = &config.log {
        if let Some(ext_level) = &ext_log.level {
            match ext_level.to_lowercase().as_str() {
                "trace" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::TRACE),
                "debug" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::DEBUG),
                "info" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::INFO),
                "warn" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::WARN),
                "error" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::ERROR),
                "none" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::NONE),
                _ => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::WARN),
            }
        }

        if let Some(ext_output) = &ext_log.output {
            match ext_output.as_str() {
                "console" => {
                    log.output = protobuf::EnumOrUnknown::new(internal::log::Output::CONSOLE)
                }
                _ => {
                    log.output = protobuf::EnumOrUnknown::new(internal::log::Output::FILE);
                    log.output_file = ext_output.clone();
                }
            }
        }

        if let Some(ext_format) = &ext_log.format {
            match ext_format.to_lowercase().as_str() {
                "compact" => {
                    log.format = protobuf::EnumOrUnknown::new(internal::log::Format::COMPACT)
                }
                _ => log.format = protobuf::EnumOrUnknown::new(internal::log::Format::FULL),
            }
        }
    }

    let mut inbounds = Vec::new();
    if let Some(ext_inbounds) = &config.inbounds {
        for ext_inbound in ext_inbounds {
            let mut inbound = internal::Inbound::new();
            if let Some(ext_tag) = &ext_inbound.tag {
                inbound.tag = ext_tag.clone();
            }
            if let Some(ext_address) = &ext_inbound.address {
                inbound.address = ext_address.to_owned();
            } else {
                inbound.address = "127.0.0.1".to_string();
            }
            if let Some(ext_port) = ext_inbound.port {
                inbound.port = ext_port as u32;
            }

            match &ext_inbound.settings {
                #[cfg(any(
                    target_os = "ios",
                    target_os = "android",
                    target_os = "macos",
                    target_os = "linux"
                ))]
                InboundSettings::Tun {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "tun".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::TunInboundSettings::new();
                        let mut fake_dns_exclude = Vec::new();
                        if let Some(ext_excludes) = &ext_settings.fake_dns_exclude {
                            for ext_exclude in ext_excludes {
                                fake_dns_exclude.push(ext_exclude.clone());
                            }
                        }
                        if !fake_dns_exclude.is_empty() {
                            settings.fake_dns_exclude = fake_dns_exclude;
                        }

                        let mut fake_dns_include = Vec::new();
                        if let Some(ext_includes) = &ext_settings.fake_dns_include {
                            for ext_include in ext_includes {
                                fake_dns_include.push(ext_include.clone());
                            }
                        }
                        if !fake_dns_include.is_empty() {
                            settings.fake_dns_include = fake_dns_include;
                        }

                        let fd = ext_settings.fd.unwrap_or(-1);
                        if fd >= 0 {
                            settings.fd = fd;
                        } else {
                            settings.fd = -1; // disable fd option
                            if let Some(ext_name) = &ext_settings.name {
                                settings.name = ext_name.clone();
                            }
                            if let Some(ext_address) = &ext_settings.address {
                                settings.address = ext_address.clone();
                            }
                            if let Some(ext_gateway) = &ext_settings.gateway {
                                settings.gateway = ext_gateway.clone();
                            }
                            if let Some(ext_netmask) = &ext_settings.netmask {
                                settings.netmask = ext_netmask.clone();
                            }
                            if let Some(ext_auto) = ext_settings.auto {
                                settings.auto = ext_auto;
                            }
                            if let Some(ext_mtu) = ext_settings.mtu {
                                settings.mtu = ext_mtu;
                            } else {
                                settings.mtu = 1500;
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                #[cfg(not(any(
                    target_os = "ios",
                    target_os = "android",
                    target_os = "macos",
                    target_os = "linux"
                )))]
                InboundSettings::Tun { .. } => {
                    return Err(anyhow::anyhow!(
                        "tun inbound is not supported on this platform"
                    ));
                }
                InboundSettings::Cat {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "cat".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::CatInboundSettings::new();
                        settings.network =
                            ext_settings.network.clone().unwrap_or("tcp".to_string());
                        settings.address = ext_settings.address.clone();
                        settings.port = ext_settings.port as u32;
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Nf {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "nf".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::NfInboundSettings::new();
                        let mut fake_dns_exclude = Vec::new();
                        if let Some(ext_excludes) = &ext_settings.fake_dns_exclude {
                            for ext_exclude in ext_excludes {
                                fake_dns_exclude.push(ext_exclude.clone());
                            }
                        }
                        if !fake_dns_exclude.is_empty() {
                            settings.fake_dns_exclude = fake_dns_exclude;
                        }

                        let mut fake_dns_include = Vec::new();
                        if let Some(ext_includes) = &ext_settings.fake_dns_include {
                            for ext_include in ext_includes {
                                fake_dns_include.push(ext_include.clone());
                            }
                        }
                        if !fake_dns_include.is_empty() {
                            settings.fake_dns_include = fake_dns_include;
                        }

                        settings.driver_name = ext_settings.driver_name.clone();
                        settings.nfapi = ext_settings
                            .nfapi
                            .clone()
                            .unwrap_or("nfapi.dll".to_string());
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Hc {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "hc".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::HcInboundSettings::new();
                        settings.path = ext_settings.path.clone();
                        settings.request = ext_settings.request.clone().unwrap_or_default();
                        settings.response = ext_settings.response.clone();
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Socks => {
                    inbound.protocol = "socks".to_string();
                    inbounds.push(inbound);
                }
                InboundSettings::Http => {
                    inbound.protocol = "http".to_string();
                    inbounds.push(inbound);
                }
                InboundSettings::Shadowsocks {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "shadowsocks".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ShadowsocksInboundSettings::new();
                        if let Some(ext_method) = &ext_settings.method {
                            settings.method = ext_method.clone();
                        }
                        if let Some(ext_password) = &ext_settings.password {
                            settings.password = ext_password.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Trojan {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "trojan".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::TrojanInboundSettings::new();
                        if let Some(ext_passwords) = &ext_settings.passwords {
                            for ext_pass in ext_passwords {
                                settings.passwords.push(ext_pass.clone());
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::WebSocket {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "ws".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::WebSocketInboundSettings::new();
                        match &ext_settings.path {
                            Some(ext_path) if !ext_path.is_empty() => {
                                settings.path = ext_path.clone();
                            }
                            _ => {
                                settings.path = "/".to_string();
                            }
                        };
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::AMux {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "amux".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::AMuxInboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Quic {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "quic".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::QuicInboundSettings::new();
                        if let Some(ext_certificate) = &ext_settings.certificate {
                            if is_inline_certificate(ext_certificate) {
                                settings.certificate = ext_certificate.clone();
                            } else {
                                let cert = Path::new(&ext_certificate);
                                if cert.is_absolute() {
                                    settings.certificate = cert.to_string_lossy().to_string();
                                } else {
                                    let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                                    let path = asset_loc.join(cert).to_string_lossy().to_string();
                                    settings.certificate = path;
                                }
                            }
                        }
                        if let Some(ext_certificate_key) = &ext_settings.certificate_key {
                            let key = Path::new(&ext_certificate_key);
                            if key.is_absolute() {
                                settings.certificate_key = key.to_string_lossy().to_string();
                            } else {
                                let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                                let path = asset_loc.join(key).to_string_lossy().to_string();
                                settings.certificate_key = path;
                            }
                        }
                        if let Some(ext_alpns) = &ext_settings.alpn {
                            for ext_alpn in ext_alpns {
                                settings.alpn.push(ext_alpn.clone());
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Tls {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "tls".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::TlsInboundSettings::new();
                        if let Some(ext_certificate) = &ext_settings.certificate {
                            if is_inline_certificate(ext_certificate) {
                                settings.certificate = ext_certificate.clone();
                            } else {
                                let cert = Path::new(&ext_certificate);
                                if cert.is_absolute() {
                                    settings.certificate = cert.to_string_lossy().to_string();
                                } else {
                                    let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                                    let path = asset_loc.join(cert).to_string_lossy().to_string();
                                    settings.certificate = path;
                                }
                            }
                        }
                        if let Some(ext_certificate_key) = &ext_settings.certificate_key {
                            let key = Path::new(&ext_certificate_key);
                            if key.is_absolute() {
                                settings.certificate_key = key.to_string_lossy().to_string();
                            } else {
                                let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                                let path = asset_loc.join(key).to_string_lossy().to_string();
                                settings.certificate_key = path;
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Chain {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "chain".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ChainInboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
            }
        }
    }

    let mut outbounds = Vec::new();
    if let Some(ext_outbounds) = &config.outbounds {
        for ext_outbound in ext_outbounds {
            let mut outbound = internal::Outbound::new();
            if let Some(ext_tag) = &ext_outbound.tag {
                outbound.tag = ext_tag.clone();
            }
            match &ext_outbound.settings {
                OutboundSettings::Direct => {
                    outbound.protocol = "direct".to_string();
                    outbounds.push(outbound);
                }
                OutboundSettings::Drop => {
                    outbound.protocol = "drop".to_string();
                    outbounds.push(outbound);
                }
                OutboundSettings::Redirect {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "redirect".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::RedirectOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Socks {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "socks".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::SocksOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_username) = &ext_settings.username {
                            settings.username = ext_username.clone();
                        }
                        if let Some(ext_password) = &ext_settings.password {
                            settings.password = ext_password.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Shadowsocks {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "shadowsocks".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ShadowsocksOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_method) = &ext_settings.method {
                            settings.method = ext_method.clone();
                        } else {
                            settings.method = "chacha20-ietf-poly1305".to_string();
                        }
                        if let Some(ext_password) = &ext_settings.password {
                            settings.password = ext_password.clone();
                        }
                        if let Some(ext_prefix) = &ext_settings.prefix {
                            settings.prefix = Some(ext_prefix.clone());
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Obfs {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "obfs".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ObfsOutboundSettings::new();
                        if let Some(ext_method) = &ext_settings.method {
                            settings.method = ext_method.clone();
                        }
                        if let Some(ext_host) = &ext_settings.host {
                            settings.host = ext_host.clone();
                        }
                        if let Some(ext_path) = &ext_settings.path {
                            settings.path = ext_path.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Trojan {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "trojan".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::TrojanOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_password) = &ext_settings.password {
                            settings.password = ext_password.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::VMess {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "vmess".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::VMessOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_uuid) = &ext_settings.uuid {
                            settings.uuid = ext_uuid.clone();
                        }
                        if let Some(ext_security) = &ext_settings.security {
                            settings.security = ext_security.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Tls {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "tls".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::TlsOutboundSettings::new();
                        if let Some(ext_server_name) = &ext_settings.server_name {
                            settings.server_name = ext_server_name.clone();
                        }
                        if let Some(ext_alpn) = &ext_settings.alpn {
                            settings.alpn = ext_alpn.clone();
                        }
                        if let Some(ext_certificate) = &ext_settings.certificate {
                            if is_inline_certificate(ext_certificate) {
                                settings.certificate = ext_certificate.clone();
                            } else {
                                let cert = Path::new(&ext_certificate);
                                if cert.is_absolute() {
                                    settings.certificate = cert.to_string_lossy().to_string();
                                } else {
                                    let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                                    let path = asset_loc.join(cert).to_string_lossy().to_string();
                                    settings.certificate = path;
                                }
                            }
                        }
                        if let Some(ext_insecure) = ext_settings.insecure {
                            settings.insecure = ext_insecure;
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::WebSocket {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "ws".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::WebSocketOutboundSettings::new();
                        if let Some(ext_path) = &ext_settings.path {
                            settings.path = ext_path.clone();
                        }
                        if let Some(ext_headers) = &ext_settings.headers {
                            settings.headers = ext_headers.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::TryAll {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "tryall".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::TryAllOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        if let Some(ext_delay_base) = ext_settings.delay_base {
                            settings.delay_base = ext_delay_base;
                        } else {
                            settings.delay_base = 0;
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Static {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "static".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::StaticOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        if let Some(ext_method) = &ext_settings.method {
                            settings.method = ext_method.clone();
                        } else {
                            settings.method = "random".to_string();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::FailOver {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "failover".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::FailOverOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            settings.actors.extend_from_slice(ext_actors);
                        }
                        settings.fail_timeout = ext_settings.fail_timeout.unwrap_or(4); // 4 secs
                        settings.health_check = ext_settings.health_check.unwrap_or(true);
                        settings.health_check_timeout =
                            ext_settings.health_check_timeout.unwrap_or(6); // 6 secs
                        settings.health_check_delay =
                            ext_settings.health_check_delay.unwrap_or(200); // 200ms
                        settings.health_check_active =
                            ext_settings.health_check_active.unwrap_or(15 * 60); // 15 mins
                        if let Some(ext_health_check_prefers) = &ext_settings.health_check_prefers {
                            settings
                                .health_check_prefers
                                .extend_from_slice(ext_health_check_prefers);
                        }
                        settings.health_check_on_start =
                            ext_settings.health_check_on_start.unwrap_or(false);
                        settings.health_check_wait =
                            ext_settings.health_check_wait.unwrap_or(false);
                        settings.health_check_attempts =
                            ext_settings.health_check_attempts.unwrap_or(1);
                        settings.health_check_success_percentage =
                            ext_settings.health_check_success_percentage.unwrap_or(50);
                        settings.check_interval = ext_settings.check_interval.unwrap_or(300); // 300 secs
                        settings.failover = ext_settings.failover.unwrap_or(true);
                        settings.fallback_cache = ext_settings.fallback_cache.unwrap_or(false);
                        settings.cache_size = ext_settings.cache_size.unwrap_or(256);
                        settings.cache_timeout = ext_settings.cache_timeout.unwrap_or(60); // 60 mins
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::AMux {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "amux".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::AMuxOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        settings.max_accepts = ext_settings.max_accepts.unwrap_or(8);
                        settings.concurrency = ext_settings.concurrency.unwrap_or(2);
                        settings.max_recv_bytes = ext_settings.max_recv_bytes.unwrap_or_default();
                        settings.max_lifetime = ext_settings.max_lifetime.unwrap_or_default();
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Quic {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "quic".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::QuicOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_server_name) = &ext_settings.server_name {
                            settings.server_name = ext_server_name.clone();
                        }
                        if let Some(ext_certificate) = &ext_settings.certificate {
                            if is_inline_certificate(ext_certificate) {
                                settings.certificate = ext_certificate.clone();
                            } else {
                                let cert = Path::new(&ext_certificate);
                                if cert.is_absolute() {
                                    settings.certificate = cert.to_string_lossy().to_string();
                                } else {
                                    let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                                    let path = asset_loc.join(cert).to_string_lossy().to_string();
                                    settings.certificate = path;
                                }
                            }
                        }
                        if let Some(ext_alpns) = &ext_settings.alpn {
                            settings.alpn = ext_alpns.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Chain {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "chain".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ChainOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Select {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "select".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::SelectOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Plugin {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "plugin".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::PluginOutboundSettings::new();
                        if let Some(ext_path) = &ext_settings.path {
                            settings.path = ext_path.clone();
                        }
                        if let Some(ext_args) = &ext_settings.args {
                            settings.args = ext_args.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
            }
        }
    }

    let mut router = protobuf::MessageField::none();
    if let Some(ext_router) = config.router.as_mut() {
        let mut int_router = internal::Router::new();
        let mut rules = Vec::new();
        if let Some(ext_rules) = ext_router.rules.as_mut() {
            for ext_rule in ext_rules.iter_mut() {
                let mut rule = internal::router::Rule::new();
                let target_tag = std::mem::take(&mut ext_rule.target);
                rule.target_tag = target_tag;

                // handle FINAL rule first
                if let Some(type_field) = &ext_rule.type_field {
                    if type_field == "FINAL" {
                        // reorder outbounds to make the FINAL one first
                        let mut idx = None;
                        for (i, v) in outbounds.iter().enumerate() {
                            if v.tag == rule.target_tag {
                                idx = Some(i);
                            }
                        }
                        if let Some(idx) = idx {
                            let final_ob = outbounds.remove(idx);
                            outbounds.insert(0, final_ob);
                        }
                        continue;
                    }
                }

                if let Some(ext_ips) = ext_rule.ip.as_mut() {
                    for ext_ip in ext_ips.drain(0..) {
                        rule.ip_cidrs.push(ext_ip);
                    }
                }
                if let Some(ext_domains) = ext_rule.domain.as_mut() {
                    for ext_domain in ext_domains.drain(0..) {
                        let mut domain = internal::router::rule::Domain::new();
                        domain.type_ = protobuf::EnumOrUnknown::new(
                            internal::router::rule::domain::Type::FULL,
                        );
                        domain.value = ext_domain;
                        rule.domains.push(domain);
                    }
                }
                if let Some(ext_domain_keywords) = ext_rule.domain_keyword.as_mut() {
                    for ext_domain_keyword in ext_domain_keywords.drain(0..) {
                        let mut domain = internal::router::rule::Domain::new();
                        domain.type_ = protobuf::EnumOrUnknown::new(
                            internal::router::rule::domain::Type::PLAIN,
                        );
                        domain.value = ext_domain_keyword;
                        rule.domains.push(domain);
                    }
                }
                if let Some(ext_domain_suffixes) = ext_rule.domain_suffix.as_mut() {
                    for ext_domain_suffix in ext_domain_suffixes.drain(0..) {
                        let mut domain = internal::router::rule::Domain::new();
                        domain.type_ = protobuf::EnumOrUnknown::new(
                            internal::router::rule::domain::Type::DOMAIN,
                        );
                        domain.value = ext_domain_suffix;
                        rule.domains.push(domain);
                    }
                }
                if let Some(ext_geoips) = ext_rule.geoip.as_mut() {
                    for ext_geoip in ext_geoips.drain(0..) {
                        let mut mmdb = internal::router::rule::Mmdb::new();
                        let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                        mmdb.file = asset_loc.join("geo.mmdb").to_string_lossy().to_string();
                        mmdb.country_code = ext_geoip;
                        rule.mmdbs.push(mmdb)
                    }
                }
                if let Some(ext_externals) = ext_rule.external.as_mut() {
                    for ext_external in ext_externals.drain(0..) {
                        match external_rule::add_external_rule(&mut rule, &ext_external) {
                            Ok(_) => (),
                            Err(e) => {
                                println!("load external rule failed: {}", e);
                            }
                        }
                    }
                }
                if let Some(ext_port_ranges) = ext_rule.port_range.as_mut() {
                    for ext_port_range in ext_port_ranges.drain(0..) {
                        rule.port_ranges.push(ext_port_range);
                    }
                }
                if let Some(ext_networks) = ext_rule.network.as_mut() {
                    for ext_network in ext_networks.drain(0..) {
                        rule.networks.push(ext_network);
                    }
                }
                if let Some(ext_its) = ext_rule.inbound_tag.as_mut() {
                    for it in ext_its.drain(0..) {
                        rule.inbound_tags.push(it);
                    }
                }
                #[cfg(feature = "rule-process-name")]
                if let Some(ext_process_names) = ext_rule.process_name.as_mut() {
                    for process_name in ext_process_names.drain(0..) {
                        rule.process_names.push(process_name);
                    }
                }
                rules.push(rule);
            }
        }
        int_router.rules = rules;
        if let Some(ext_domain_resolve) = ext_router.domain_resolve {
            int_router.domain_resolve = ext_domain_resolve;
        }
        router = protobuf::MessageField::some(int_router);
    }

    let mut dns = internal::Dns::new();
    let mut servers = Vec::new();
    let mut hosts = HashMap::new();
    if let Some(ext_dns) = &config.dns {
        if let Some(ext_servers) = ext_dns.servers.as_ref() {
            for ext_server in ext_servers {
                servers.push(ext_server.to_owned());
            }
        }
        if let Some(ext_hosts) = ext_dns.hosts.as_ref() {
            for (name, static_ips) in ext_hosts.iter() {
                let mut ips = internal::dns::Ips::new();
                let mut ip_vals = Vec::new();
                for ip in static_ips {
                    ip_vals.push(ip.to_owned());
                }
                ips.values = ip_vals;
                hosts.insert(name.to_owned(), ips);
            }
        }
    }
    if servers.is_empty() {
        servers.push("1.1.1.1".to_string());
    }
    dns.servers = servers;
    if !hosts.is_empty() {
        dns.hosts = hosts;
    }

    let mut config = internal::Config::new();
    config.log = protobuf::MessageField::some(log);
    config.inbounds = inbounds;
    config.outbounds = outbounds;
    config.router = router;
    config.dns = protobuf::MessageField::some(dns);
    Ok(config)
}
