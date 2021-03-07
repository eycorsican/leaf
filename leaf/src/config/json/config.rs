use std::collections::HashMap;
use std::path::Path;

use anyhow::anyhow;
use anyhow::Result;
use protobuf::Message;
use serde_derive::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::config::{external_rule, geosite, internal};

#[derive(Serialize, Deserialize, Debug)]
pub struct Dns {
    pub servers: Option<Vec<String>>,
    pub bind: Option<String>,
    pub hosts: Option<HashMap<String, Vec<String>>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Log {
    pub level: Option<String>,
    pub output: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ShadowsocksInboundSettings {
    pub method: Option<String>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TrojanInboundSettings {
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WebSocketInboundSettings {
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AMuxInboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChainInboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TunInboundSettings {
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

#[derive(Serialize, Deserialize, Debug)]
pub struct Inbound {
    pub protocol: String,
    pub tag: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub settings: Option<Box<RawValue>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RedirectOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SocksOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ShadowsocksOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub method: Option<String>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TrojanOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VMessOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub uuid: Option<String>,
    pub security: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VLessOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub uuid: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TryAllOutboundSettings {
    pub actors: Option<Vec<String>>,
    #[serde(rename = "delayBase")]
    pub delay_base: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RandomOutboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TlsOutboundSettings {
    #[serde(rename = "serverName")]
    pub server_name: Option<String>,
    pub alpn: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WebSocketOutboundSettings {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HTTP2OutboundSettings {
    pub path: Option<String>,
    pub host: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AMuxOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub actors: Option<Vec<String>>,
    #[serde(rename = "maxAccepts")]
    pub max_accepts: Option<u32>,
    pub concurrency: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChainOutboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RetryOutboundSettings {
    pub actors: Option<Vec<String>>,
    pub attempts: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FailOverOutboundSettings {
    pub actors: Option<Vec<String>>,
    #[serde(rename = "failTimeout")]
    pub fail_timeout: Option<u32>,
    #[serde(rename = "healthCheck")]
    pub health_check: Option<bool>,
    #[serde(rename = "checkInterval")]
    pub check_interval: Option<u32>,
    pub failover: Option<bool>,
    #[serde(rename = "fallbackCache")]
    pub fallback_cache: Option<bool>,
    #[serde(rename = "cacheSize")]
    pub cache_size: Option<u32>,
    #[serde(rename = "cacheTimeout")]
    pub cache_timeout: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Outbound {
    pub protocol: String,
    pub tag: Option<String>,
    pub bind: Option<String>,
    pub settings: Option<Box<RawValue>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Rule {
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
    pub target: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub log: Option<Log>,
    pub inbounds: Option<Vec<Inbound>>,
    pub outbounds: Option<Vec<Outbound>>,
    pub rules: Option<Vec<Rule>>,
    pub dns: Option<Dns>,
}

pub fn to_internal(json: Config) -> Result<internal::Config> {
    let mut log = internal::Log::new();
    if let Some(ext_log) = json.log {
        if let Some(ext_level) = ext_log.level {
            match ext_level.as_str() {
                "trace" => log.level = internal::Log_Level::TRACE,
                "debug" => log.level = internal::Log_Level::DEBUG,
                "info" => log.level = internal::Log_Level::INFO,
                "warn" => log.level = internal::Log_Level::WARN,
                "error" => log.level = internal::Log_Level::ERROR,
                _ => log.level = internal::Log_Level::WARN,
            }
        } else {
            log.level = internal::Log_Level::INFO;
        }

        if let Some(ext_output) = ext_log.output {
            match ext_output.as_str() {
                "console" => log.output = internal::Log_Output::CONSOLE,
                _ => {
                    log.output = internal::Log_Output::FILE;
                    log.output_file = ext_output;
                }
            }
        } else {
            log.output = internal::Log_Output::CONSOLE;
        }
    } else {
        log.level = internal::Log_Level::INFO;
        log.output = internal::Log_Output::CONSOLE;
    }

    let mut inbounds = protobuf::RepeatedField::new();
    if let Some(ext_inbounds) = json.inbounds {
        for ext_inbound in ext_inbounds {
            let mut inbound = internal::Inbound::new();
            inbound.protocol = ext_inbound.protocol;
            if let Some(ext_tag) = ext_inbound.tag {
                inbound.tag = ext_tag;
            }
            if let Some(ext_address) = ext_inbound.address {
                inbound.address = ext_address;
            } else {
                inbound.address = "127.0.0.1".to_string();
            }
            if let Some(ext_port) = ext_inbound.port {
                inbound.port = ext_port as u32;
            }
            match inbound.protocol.as_str() {
                #[cfg(any(target_os = "ios", target_os = "macos", target_os = "linux"))]
                "tun" => {
                    if ext_inbound.settings.is_none() {
                        return Err(anyhow!("invalid tun inbound settings"));
                    }
                    let mut settings = internal::TunInboundSettings::new();
                    let ext_settings: TunInboundSettings =
                        serde_json::from_str(ext_inbound.settings.unwrap().get()).unwrap();

                    let mut fake_dns_exclude = protobuf::RepeatedField::new();
                    if let Some(ext_excludes) = ext_settings.fake_dns_exclude {
                        for ext_exclude in ext_excludes {
                            fake_dns_exclude.push(ext_exclude);
                        }
                    }
                    if fake_dns_exclude.len() > 0 {
                        settings.fake_dns_exclude = fake_dns_exclude;
                    }

                    let mut fake_dns_include = protobuf::RepeatedField::new();
                    if let Some(ext_includes) = ext_settings.fake_dns_include {
                        for ext_include in ext_includes {
                            fake_dns_include.push(ext_include);
                        }
                    }
                    if fake_dns_include.len() > 0 {
                        settings.fake_dns_include = fake_dns_include;
                    }

                    if let Some(ext_fd) = ext_settings.fd {
                        settings.fd = ext_fd;
                    } else {
                        settings.fd = -1; // disable fd option
                        if let Some(ext_name) = ext_settings.name {
                            settings.name = ext_name;
                        }
                        if let Some(ext_address) = ext_settings.address {
                            settings.address = ext_address;
                        }
                        if let Some(ext_gateway) = ext_settings.gateway {
                            settings.gateway = ext_gateway;
                        }
                        if let Some(ext_netmask) = ext_settings.netmask {
                            settings.netmask = ext_netmask;
                        }
                        if let Some(ext_mtu) = ext_settings.mtu {
                            settings.mtu = ext_mtu;
                        } else {
                            settings.mtu = 1500;
                        }
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    inbound.settings = settings;
                    inbounds.push(inbound);
                }
                "http" => {
                    inbounds.push(inbound);
                }
                "socks" => {
                    inbounds.push(inbound);
                }
                "shadowsocks" => {
                    let mut settings = internal::ShadowsocksInboundSettings::new();
                    let ext_settings: ShadowsocksInboundSettings =
                        serde_json::from_str(ext_inbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_method) = ext_settings.method {
                        settings.method = ext_method;
                    } else {
                        settings.method = "chacha20-ietf-poly1305".to_string();
                    }
                    if let Some(ext_password) = ext_settings.password {
                        settings.password = ext_password;
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    inbound.settings = settings;
                    inbounds.push(inbound);
                }
                "trojan" => {
                    let mut settings = internal::TrojanInboundSettings::new();
                    let ext_settings: TrojanInboundSettings =
                        serde_json::from_str(ext_inbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_password) = ext_settings.password {
                        settings.password = ext_password;
                    } else {
                        settings.password = "".to_string(); // FIXME warns?
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    inbound.settings = settings;
                    inbounds.push(inbound);
                }
                "ws" => {
                    let mut settings = internal::WebSocketInboundSettings::new();
                    let ext_settings: WebSocketInboundSettings =
                        serde_json::from_str(ext_inbound.settings.unwrap().get()).unwrap();
                    match ext_settings.path {
                        Some(ext_path) if !ext_path.is_empty() => {
                            settings.path = ext_path;
                        }
                        _ => {
                            settings.path = "/".to_string();
                        }
                    };
                    let settings = settings.write_to_bytes().unwrap();
                    inbound.settings = settings;
                    inbounds.push(inbound);
                }
                "amux" => {
                    let mut settings = internal::AMuxInboundSettings::new();
                    if let Some(ext_settings) = ext_inbound.settings {
                        if let Ok(ext_settings) =
                            serde_json::from_str::<AMuxInboundSettings>(ext_settings.get())
                        {
                            if let Some(ext_actors) = ext_settings.actors {
                                for ext_actor in ext_actors {
                                    settings.actors.push(ext_actor);
                                }
                            }
                        }
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    inbound.settings = settings;
                    inbounds.push(inbound);
                }
                "chain" => {
                    if ext_inbound.settings.is_none() {
                        return Err(anyhow!("invalid chain inbound settings"));
                    }
                    let mut settings = internal::ChainInboundSettings::new();
                    let ext_settings: ChainInboundSettings =
                        serde_json::from_str(ext_inbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_actors) = ext_settings.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor);
                        }
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    inbound.settings = settings;
                    inbounds.push(inbound);
                }
                _ => {
                    // skip inbound with unknown protocol
                }
            }
        }
    }

    let mut outbounds = protobuf::RepeatedField::new();
    if let Some(ext_outbounds) = json.outbounds {
        for ext_outbound in ext_outbounds {
            let mut outbound = internal::Outbound::new();
            outbound.protocol = ext_outbound.protocol;
            if let Some(ext_tag) = ext_outbound.tag {
                outbound.tag = ext_tag;
            }
            if let Some(ext_bind) = ext_outbound.bind {
                outbound.bind = ext_bind;
            } else {
                outbound.bind = "0.0.0.0".to_string();
            }
            match outbound.protocol.as_str() {
                "direct" | "drop" => {
                    outbounds.push(outbound);
                }
                "redirect" => {
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid redirect outbound settings"));
                    }
                    let mut settings = internal::RedirectOutboundSettings::new();
                    let ext_settings: RedirectOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_address) = ext_settings.address {
                        settings.address = ext_address;
                    }
                    if let Some(ext_port) = ext_settings.port {
                        settings.port = ext_port as u32;
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "socks" => {
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid socks outbound settings"));
                    }
                    let mut settings = internal::SocksOutboundSettings::new();
                    let ext_settings: SocksOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_address) = ext_settings.address {
                        settings.address = ext_address; // TODO checks
                    }
                    if let Some(ext_port) = ext_settings.port {
                        settings.port = ext_port as u32; // TODO checks
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "shadowsocks" => {
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid shadowsocks outbound settings"));
                    }
                    let mut settings = internal::ShadowsocksOutboundSettings::new();
                    let ext_settings: ShadowsocksOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_address) = ext_settings.address {
                        settings.address = ext_address; // TODO checks
                    }
                    if let Some(ext_port) = ext_settings.port {
                        settings.port = ext_port as u32; // TODO checks
                    }
                    if let Some(ext_method) = ext_settings.method {
                        settings.method = ext_method;
                    } else {
                        settings.method = "chacha20-ietf-poly1305".to_string();
                    }
                    if let Some(ext_password) = ext_settings.password {
                        settings.password = ext_password;
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "trojan" => {
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid trojan outbound settings"));
                    }
                    let mut settings = internal::TrojanOutboundSettings::new();
                    let ext_settings: TrojanOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_address) = ext_settings.address {
                        settings.address = ext_address; // TODO checks
                    }
                    if let Some(ext_port) = ext_settings.port {
                        settings.port = ext_port as u32; // TODO checks
                    }
                    if let Some(ext_password) = ext_settings.password {
                        settings.password = ext_password;
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "vmess" => {
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid vmess outbound settings"));
                    }
                    let mut settings = internal::VMessOutboundSettings::new();
                    let ext_settings: VMessOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_address) = ext_settings.address {
                        settings.address = ext_address; // TODO checks
                    }
                    if let Some(ext_port) = ext_settings.port {
                        settings.port = ext_port as u32; // TODO checks
                    }
                    if let Some(ext_uuid) = ext_settings.uuid {
                        settings.uuid = ext_uuid;
                    }
                    if let Some(ext_security) = ext_settings.security {
                        settings.security = ext_security;
                    } else {
                        settings.security = "chacha20-ietf-poly1305".to_string();
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "vless" => {
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid vless outbound settings"));
                    }
                    let mut settings = internal::VLessOutboundSettings::new();
                    let ext_settings: VLessOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_address) = ext_settings.address {
                        settings.address = ext_address; // TODO checks
                    }
                    if let Some(ext_port) = ext_settings.port {
                        settings.port = ext_port as u32; // TODO checks
                    }
                    if let Some(ext_uuid) = ext_settings.uuid {
                        settings.uuid = ext_uuid;
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "tls" => {
                    let mut settings = internal::TlsOutboundSettings::new();
                    if ext_outbound.settings.is_some() {
                        let ext_settings: TlsOutboundSettings =
                            serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                        if let Some(ext_server_name) = ext_settings.server_name {
                            settings.server_name = ext_server_name; // TODO checks
                        }
                        let mut alpns = protobuf::RepeatedField::new();
                        if let Some(ext_alpns) = ext_settings.alpn {
                            for ext_alpn in ext_alpns {
                                alpns.push(ext_alpn);
                            }
                        }
                        if alpns.len() > 0 {
                            settings.alpn = alpns;
                        }
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "ws" | "websocket" => {
                    outbound.protocol = "ws".to_string(); // websocket -> ws
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid ws outbound settings"));
                    }
                    let mut settings = internal::WebSocketOutboundSettings::new();
                    let ext_settings: WebSocketOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_path) = ext_settings.path {
                        settings.path = ext_path; // TODO checks
                    }
                    if let Some(ext_headers) = ext_settings.headers {
                        settings.headers = ext_headers;
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "h2" | "http2" => {
                    outbound.protocol = "h2".to_string(); // use h2 anyway
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid h2 outbound settings"));
                    }
                    let mut settings = internal::HTTP2OutboundSettings::new();
                    let ext_settings: HTTP2OutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_path) = ext_settings.path {
                        settings.path = ext_path; // TODO checks
                    }
                    if let Some(ext_host) = ext_settings.host {
                        settings.host = ext_host; // TODO checks
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "tryall" => {
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid tryall outbound settings"));
                    }
                    let mut settings = internal::TryAllOutboundSettings::new();
                    let ext_settings: TryAllOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_actors) = ext_settings.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor);
                        }
                    }
                    if let Some(ext_delay_base) = ext_settings.delay_base {
                        settings.delay_base = ext_delay_base;
                    } else {
                        settings.delay_base = 0;
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "random" => {
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid random outbound settings"));
                    }
                    let mut settings = internal::RandomOutboundSettings::new();
                    let ext_settings: RandomOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_actors) = ext_settings.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor);
                        }
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "failover" => {
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid failover outbound settings"));
                    }
                    let mut settings = internal::FailOverOutboundSettings::new();
                    let ext_settings: FailOverOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_actors) = ext_settings.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor);
                        }
                    }
                    if let Some(ext_fail_timeout) = ext_settings.fail_timeout {
                        settings.fail_timeout = ext_fail_timeout;
                    } else {
                        settings.fail_timeout = 4;
                    }
                    if let Some(ext_health_check) = ext_settings.health_check {
                        settings.health_check = ext_health_check;
                    } else {
                        settings.health_check = true;
                    }
                    if let Some(ext_check_interval) = ext_settings.check_interval {
                        settings.check_interval = ext_check_interval;
                    } else {
                        settings.check_interval = 300;
                    }
                    if let Some(ext_failover) = ext_settings.failover {
                        settings.failover = ext_failover;
                    } else {
                        settings.failover = true;
                    }
                    if let Some(ext_fallback_cache) = ext_settings.fallback_cache {
                        settings.fallback_cache = ext_fallback_cache;
                    } else {
                        settings.fallback_cache = false;
                    }
                    if let Some(ext_cache_size) = ext_settings.cache_size {
                        settings.cache_size = ext_cache_size;
                    } else {
                        settings.cache_size = 256;
                    }
                    if let Some(ext_cache_timeout) = ext_settings.cache_timeout {
                        settings.cache_timeout = ext_cache_timeout;
                    } else {
                        settings.cache_timeout = 60; // in minutes
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "amux" => {
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid amux outbound settings"));
                    }
                    let mut settings = internal::AMuxOutboundSettings::new();
                    let ext_settings: AMuxOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_address) = ext_settings.address {
                        settings.address = ext_address;
                    }
                    if let Some(ext_port) = ext_settings.port {
                        settings.port = ext_port as u32;
                    }
                    if let Some(ext_actors) = ext_settings.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor);
                        }
                    }
                    if let Some(ext_max_accepts) = ext_settings.max_accepts {
                        settings.max_accepts = ext_max_accepts as u32;
                    } else {
                        settings.max_accepts = 8;
                    }
                    if let Some(ext_concurrency) = ext_settings.concurrency {
                        settings.concurrency = ext_concurrency as u32;
                    } else {
                        settings.concurrency = 2;
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "chain" => {
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid chain outbound settings"));
                    }
                    let mut settings = internal::ChainOutboundSettings::new();
                    let ext_settings: ChainOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_actors) = ext_settings.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor);
                        }
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "retry" => {
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid retry outbound settings"));
                    }
                    let mut settings = internal::RetryOutboundSettings::new();
                    let ext_settings: RetryOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_actors) = ext_settings.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor);
                        }
                    }
                    if let Some(ext_attempts) = ext_settings.attempts {
                        settings.attempts = ext_attempts;
                    } else {
                        settings.attempts = 2;
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "stat" => {
                    if ext_outbound.settings.is_none() {
                        return Err(anyhow!("invalid stat outbound settings"));
                    }
                    let mut settings = internal::StatOutboundSettings::new();
                    let ext_settings: StatOutboundSettings =
                        serde_json::from_str(ext_outbound.settings.unwrap().get()).unwrap();
                    if let Some(ext_address) = ext_settings.address {
                        settings.address = ext_address;
                    }
                    if let Some(ext_port) = ext_settings.port {
                        settings.port = ext_port as u32;
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                _ => {
                    // skip outbound with unknown protocol
                }
            }
        }
    }

    let mut rules = protobuf::RepeatedField::new();
    if let Some(ext_rules) = json.rules {
        // a map for caching external site so we need not load a same file multiple times
        let mut site_group_lists = HashMap::<String, geosite::SiteGroupList>::new();

        for ext_rule in ext_rules {
            let mut rule = internal::RoutingRule::new();
            rule.target_tag = ext_rule.target;
            if let Some(ext_ips) = ext_rule.ip {
                for ext_ip in ext_ips {
                    rule.ip_cidrs.push(ext_ip);
                }
            }
            if let Some(ext_domains) = ext_rule.domain {
                for ext_domain in ext_domains {
                    let mut domain = internal::RoutingRule_Domain::new();
                    domain.field_type = internal::RoutingRule_Domain_Type::FULL;
                    domain.value = ext_domain;
                    rule.domains.push(domain);
                }
            }
            if let Some(ext_domain_keywords) = ext_rule.domain_keyword {
                for ext_domain_keyword in ext_domain_keywords {
                    let mut domain = internal::RoutingRule_Domain::new();
                    domain.field_type = internal::RoutingRule_Domain_Type::PLAIN;
                    domain.value = ext_domain_keyword;
                    rule.domains.push(domain);
                }
            }
            if let Some(ext_domain_suffixes) = ext_rule.domain_suffix {
                for ext_domain_suffix in ext_domain_suffixes {
                    let mut domain = internal::RoutingRule_Domain::new();
                    domain.field_type = internal::RoutingRule_Domain_Type::DOMAIN;
                    domain.value = ext_domain_suffix;
                    rule.domains.push(domain);
                }
            }
            if let Some(ext_geoips) = ext_rule.geoip {
                for ext_geoip in ext_geoips {
                    let mut mmdb = internal::RoutingRule_Mmdb::new();
                    let mut file = std::env::current_exe().unwrap();
                    file.pop();
                    file.push("geo.mmdb");
                    mmdb.file = file.to_str().unwrap().to_string();
                    mmdb.country_code = ext_geoip;
                    rule.mmdbs.push(mmdb)
                }
            }
            if let Some(ext_externals) = ext_rule.external {
                for ext_external in ext_externals {
                    match external_rule::add_external_rule(
                        &mut rule,
                        &ext_external,
                        &mut site_group_lists,
                    ) {
                        Ok(_) => (),
                        Err(e) => {
                            println!("load external rule failed: {}", e);
                        }
                    }
                }
            }
            if let Some(ext_port_ranges) = ext_rule.port_range {
                for ext_port_range in ext_port_ranges {
                    // FIXME validate
                    rule.port_ranges.push(ext_port_range);
                }
            }
            rules.push(rule);
        }
        drop(site_group_lists); // make sure it's released
    }

    let mut dns = internal::Dns::new();
    let mut servers = protobuf::RepeatedField::new();
    let mut hosts = HashMap::new();
    if let Some(ext_dns) = json.dns {
        if let Some(ext_bind) = ext_dns.bind {
            dns.bind = ext_bind;
        }
        if let Some(ext_servers) = ext_dns.servers {
            for ext_server in ext_servers {
                servers.push(ext_server);
            }
        }
        if let Some(ext_hosts) = ext_dns.hosts {
            for (name, static_ips) in ext_hosts.iter() {
                let mut ips = internal::Dns_Ips::new();
                let mut ip_vals = protobuf::RepeatedField::new();
                for ip in static_ips {
                    ip_vals.push(ip.to_owned());
                }
                ips.values = ip_vals;
                hosts.insert(name.to_owned(), ips);
            }
        }
    }
    if dns.bind.is_empty() {
        dns.bind = "0.0.0.0".to_string();
    }
    if servers.len() == 0 {
        servers.push("114.114.114.114".to_string());
        servers.push("8.8.8.8".to_string());
    }
    dns.servers = servers;
    if !hosts.is_empty() {
        dns.hosts = hosts;
    }

    let mut config = internal::Config::new();
    config.log = protobuf::SingularPtrField::some(log);
    config.inbounds = inbounds;
    config.outbounds = outbounds;
    config.routing_rules = rules;
    config.dns = protobuf::SingularPtrField::some(dns);
    Ok(config)
}

pub fn from_string(config: String) -> Result<Config> {
    serde_json::from_str(config.as_str())
        .map_err(|e| anyhow!("deserialize json config failed: {}", e))
}

pub fn from_file<P>(path: P) -> Result<internal::Config>
where
    P: AsRef<Path>,
{
    let config = std::fs::read_to_string(path)?;
    let config = from_string(config)?;
    to_internal(config)
}
