use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use anyhow::Result;
use regex::Regex;

use crate::config::{common, internal};

#[derive(Debug, Default)]
pub struct Tun {
    pub name: Option<String>,
    pub address: Option<String>,
    pub netmask: Option<String>,
    pub gateway: Option<String>,
    pub mtu: Option<i32>,
}

#[derive(Debug, Default)]
pub struct Nf {
    pub driver_name: String,
    pub nfapi: Option<String>,
}

#[derive(Debug, Default)]
pub struct General {
    pub tun: Option<Tun>,
    pub tun_fd: Option<i32>,
    pub tun_auto: Option<bool>,
    pub tun2socks_backend: Option<String>,
    pub nf: Option<Nf>,
    pub loglevel: Option<String>,
    pub logoutput: Option<String>,
    pub logformat: Option<String>,
    pub dns_server: Option<Vec<String>>,
    pub dns_interface: Option<String>,
    pub always_real_ip: Option<Vec<String>>,
    pub always_fake_ip: Option<Vec<String>>,
    pub http_interface: Option<String>,
    pub http_port: Option<u16>,
    pub socks_interface: Option<String>,
    pub socks_port: Option<u16>,
    pub api_interface: Option<String>,
    pub api_port: Option<u16>,
    pub routing_domain_resolve: Option<bool>,
    pub wintun: Option<String>,
    pub tun_dns_server: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct Proxy {
    pub tag: String,
    pub protocol: String,
    pub interface: String,

    // common
    pub address: Option<String>,
    pub port: Option<u16>,

    // shadowsocks
    pub encrypt_method: Option<String>,
    pub prefix: Option<String>,

    // shadowsocks, trojan
    pub password: Option<String>,

    // simple-obfs
    pub obfs_type: Option<String>,
    pub obfs_host: Option<String>,
    pub obfs_path: Option<String>,

    pub ws: Option<bool>,
    pub tls: Option<bool>,
    pub tls_cert: Option<String>,
    pub tls_insecure: Option<bool>,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,

    // trojan
    pub sni: Option<String>,

    // vmess
    pub username: Option<String>,
    pub uuid: Option<String>,

    pub amux: Option<bool>,
    pub amux_max: Option<i32>,
    pub amux_con: Option<i32>,
    pub amux_max_recv: Option<u64>,
    pub amux_max_lifetime: Option<u64>,

    pub quic: Option<bool>,

    // reality
    pub reality: Option<bool>,
    pub reality_public_key: Option<String>,
    pub reality_short_id: Option<String>,
}

impl Default for Proxy {
    fn default() -> Self {
        Proxy {
            tag: "".to_string(),
            protocol: "".to_string(),
            interface: crate::option::UNSPECIFIED_BIND_ADDR.ip().to_string(),
            address: None,
            port: None,
            encrypt_method: Some("chacha20-ietf-poly1305".to_string()),
            prefix: None,
            password: None,
            obfs_type: None,
            obfs_host: None,
            obfs_path: None,
            ws: Some(false),
            tls: Some(false),
            tls_cert: None,
            tls_insecure: Some(false),
            ws_path: None,
            ws_host: None,
            sni: None,
            username: None,
            uuid: None,
            amux: Some(false),
            amux_max: Some(8),
            amux_con: Some(2),
            amux_max_recv: Some(0),
            amux_max_lifetime: Some(0),
            quic: Some(false),
            reality: Some(false),
            reality_public_key: None,
            reality_short_id: None,
        }
    }
}
#[derive(Debug)]
pub struct ProxyGroup {
    pub tag: String,
    pub protocol: String,
    pub actors: Option<Vec<String>>,

    // common
    pub address: Option<String>,
    pub port: Option<u16>,

    // failover
    pub health_check: Option<bool>,
    pub check_interval: Option<u32>,
    pub fail_timeout: Option<u32>,
    pub failover: Option<bool>,
    pub fallback_cache: Option<bool>,
    pub cache_size: Option<u32>,
    pub cache_timeout: Option<u32>,
    pub last_resort: Option<String>,
    pub health_check_timeout: Option<u32>,
    pub health_check_delay: Option<u32>,
    pub health_check_active: Option<u32>,
    pub health_check_prefers: Option<Vec<String>>,
    pub health_check_on_start: Option<bool>,
    pub health_check_wait: Option<bool>,
    pub health_check_attempts: Option<u32>,
    pub health_check_success_percentage: Option<u32>,

    // tryall
    pub delay_base: Option<u32>,

    // static
    pub method: Option<String>,
}

impl Default for ProxyGroup {
    fn default() -> Self {
        ProxyGroup {
            tag: "".to_string(),
            protocol: "".to_string(),
            actors: None,
            address: None,
            port: None,
            health_check: None,
            check_interval: None,
            fail_timeout: None,
            failover: None,
            fallback_cache: None,
            cache_size: None,
            cache_timeout: None,
            last_resort: None,
            health_check_timeout: None,
            health_check_delay: None,
            health_check_active: None,
            health_check_prefers: None,
            health_check_on_start: None,
            health_check_wait: None,
            health_check_attempts: None,
            health_check_success_percentage: None,
            delay_base: None,
            method: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Rule {
    pub type_field: String,
    pub filter: Option<String>,
    pub target: String,
}

#[derive(Debug, Default)]
pub struct Config {
    pub general: Option<General>,
    pub proxy: Option<Vec<Proxy>>,
    pub proxy_group: Option<Vec<ProxyGroup>>,
    pub rule: Option<Vec<Rule>>,
    pub host: Option<HashMap<String, Vec<String>>>,
    pub certificates: Option<HashMap<String, String>>,
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn remove_comments(text: &str) -> Cow<'_, str> {
    let re = Regex::new(r"(#[^*]*)").unwrap();
    re.replace(text, "")
}

fn get_section(text: &str) -> Option<&str> {
    let re = Regex::new(r"^\s*\[\s*([^\]]*)\s*\]\s*$").unwrap();
    let caps = re.captures(text);
    caps.as_ref()?;
    Some(caps.unwrap().get(1).unwrap().as_str())
}

fn normalize_section(s: &str) -> String {
    s.to_lowercase().replace(' ', "").replace('_', "")
}

fn get_certificate_sections<'a, I>(lines: I) -> HashMap<String, String>
where
    I: Iterator<Item = &'a io::Result<String>>,
{
    let mut certificates = HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current_lines: Vec<String> = Vec::new();

    for line in lines {
        let line = match line {
            Ok(line) => line,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if let Some(section) = get_section(trimmed) {
            if let Some(name) = current_name.take() {
                if !current_lines.is_empty() {
                    let mut content = current_lines.join("\n");
                    content.push('\n');
                    certificates.insert(name, content);
                }
                current_lines.clear();
            }
            let lower = section.to_lowercase();
            if let Some(name) = section.strip_prefix("Certificate.") {
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            } else if lower.starts_with("certificate.") {
                let name = &section["certificate.".len()..];
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            } else if lower.starts_with("certificate_") {
                let name = &section["certificate_".len()..];
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            } else if lower.starts_with("certificate ") {
                let name = &section["certificate ".len()..];
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            } else if lower.starts_with("certificate") {
                let name = &section["certificate".len()..];
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            }
            continue;
        }
        if current_name.is_some() {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            current_lines.push(trimmed.to_string());
        }
    }

    if let Some(name) = current_name.take() {
        if !current_lines.is_empty() {
            let mut content = current_lines.join("\n");
            content.push('\n');
            certificates.insert(name, content);
        }
    }

    certificates
}

fn get_lines_by_section<'a, I>(section: &str, lines: I) -> Vec<String>
where
    I: Iterator<Item = &'a io::Result<String>>,
{
    let mut new_lines = Vec::new();
    let mut curr_sect: String = "".to_string();
    let normalized_target = normalize_section(section);
    for line in lines.flatten().map(|x| x.trim()) {
        let line = remove_comments(line);
        if let Some(s) = get_section(line.as_ref()) {
            curr_sect = s.to_string();
            continue;
        }
        if normalize_section(&curr_sect) == normalized_target && !line.is_empty() {
            new_lines.push(line.to_string());
        }
    }
    new_lines
}

fn get_char_sep_slice(text: &str, pat: char) -> Option<Vec<String>>
where
{
    let mut items = Vec::new();
    for item in text.split(pat).map(str::trim) {
        if !item.is_empty() {
            items.push(item.to_string());
        }
    }
    if !items.is_empty() {
        Some(items)
    } else {
        None
    }
}

fn get_string(text: &str) -> Option<String> {
    if !text.is_empty() {
        Some(text.to_string())
    } else {
        None
    }
}

fn get_value<T>(text: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    if !text.is_empty() {
        if let Ok(v) = text.parse::<T>() {
            return Some(v);
        }
    }
    None
}

pub fn from_lines(lines: Vec<io::Result<String>>) -> Result<Config> {
    let certificates = get_certificate_sections(lines.iter());
    let env_lines = get_lines_by_section("Env", lines.iter());
    for line in env_lines {
        let parts: Vec<&str> = line
            .split('=')
            .map(|s| s.trim_matches('\u{0}'))
            .map(str::trim)
            .collect();
        if parts.len() != 2 {
            continue;
        }
        std::env::set_var(parts[0], parts[1]);
    }

    let mut general = General::default();
    let general_lines = get_lines_by_section("General", lines.iter());
    for line in general_lines {
        let parts: Vec<&str> = line.split('=').map(str::trim).collect();
        if parts.len() != 2 {
            continue;
        }
        match parts[0] {
            "tun-fd" => {
                general.tun_fd = get_value::<i32>(parts[1]);
            }
            "tun" => {
                if let Some(items) = get_char_sep_slice(parts[1], ',') {
                    if items.len() >= 1 && items[0] == "auto" {
                        general.tun_auto = Some(true);
                        continue;
                    }
                    if items.len() < 5 {
                        continue;
                    }
                    let tun = Tun {
                        name: Some(items[0].clone()),
                        address: Some(items[1].clone()),
                        netmask: Some(items[2].clone()),
                        gateway: Some(items[3].clone()),
                        mtu: get_value::<i32>(&items[4]),
                    };
                    general.tun = Some(tun);
                }
            }
            "tun2socks-backend" => {
                general.tun2socks_backend = Some(parts[1].to_string());
            }
            "nf" => {
                // nf = driver_name, path/to/nfapi.dll
                if let Some(items) = get_char_sep_slice(parts[1], ',') {
                    let nfapi = if items.len() >= 2 {
                        Some(items[1].trim().to_owned())
                    } else {
                        None
                    };
                    let nf = Nf {
                        driver_name: items[0].trim().to_owned(),
                        nfapi,
                    };
                    general.nf = Some(nf);
                }
            }
            "loglevel" => {
                general.loglevel = Some(parts[1].to_string());
            }
            "logoutput" => {
                general.logoutput = Some(parts[1].to_string());
            }
            "logformat" => {
                general.logformat = Some(parts[1].to_string());
            }
            "dns-server" => {
                general.dns_server = get_char_sep_slice(parts[1], ',');
            }
            "dns-interface" => {
                general.dns_interface = get_string(parts[1]);
            }
            "always-real-ip" => {
                general.always_real_ip = get_char_sep_slice(parts[1], ',');
            }
            "always-fake-ip" => {
                general.always_fake_ip = get_char_sep_slice(parts[1], ',');
            }
            "routing-domain-resolve" => {
                general.routing_domain_resolve = if parts[1] == "true" {
                    Some(true)
                } else {
                    Some(false)
                };
            }
            "http-interface" | "interface" => {
                general.http_interface = get_string(parts[1]);
            }
            "http-port" | "port" => {
                general.http_port = get_value::<u16>(parts[1]);
            }
            "socks-interface" => {
                general.socks_interface = get_string(parts[1]);
            }
            "socks-port" => {
                general.socks_port = get_value::<u16>(parts[1]);
            }
            "api-interface" => {
                general.api_interface = get_string(parts[1]);
            }
            "api-port" => {
                general.api_port = get_value::<u16>(parts[1]);
            }
            "wintun" => {
                general.wintun = get_string(parts[1]);
            }
            "tun-dns-server" => {
                general.tun_dns_server = get_char_sep_slice(parts[1], ',');
            }
            _ => {}
        }
    }

    let mut proxies = Vec::new();
    let proxy_lines = get_lines_by_section("Proxy", lines.iter());
    for line in proxy_lines {
        let parts: Vec<&str> = line.splitn(2, '=').map(str::trim).collect();
        if parts.len() != 2 {
            continue;
        }
        let mut proxy = Proxy::default();
        let tag = parts[0];
        if tag.is_empty() {
            // empty tag is not allowed
            continue;
        }
        proxy.tag = tag.to_string();
        let params = if let Some(p) = get_char_sep_slice(parts[1], ',') {
            p
        } else {
            continue;
        };
        if params.is_empty() {
            // there must be at least one param, i.e. the protocol field
            continue;
        }
        proxy.protocol = params[0].clone();

        // extract key-value params
        // let params = &params[2..];
        for param in &params {
            let parts: Vec<&str> = param.split('=').map(str::trim).collect();
            if parts.len() != 2 {
                continue;
            }
            let k = parts[0];
            let v = parts[1];
            if k.is_empty() || v.is_empty() {
                continue;
            }
            match k {
                "encrypt-method" => {
                    proxy.encrypt_method = Some(v.to_string());
                }
                "prefix" => {
                    proxy.prefix = Some(v.to_string());
                }
                "password" => {
                    proxy.password = Some(v.to_string());
                }
                "obfs" => {
                    proxy.obfs_type = Some(v.to_string());
                }
                "obfs-host" => {
                    proxy.obfs_host = Some(v.to_string());
                }
                "obfs-path" => {
                    proxy.obfs_path = Some(v.to_string());
                }
                "ws" => proxy.ws = if v == "true" { Some(true) } else { Some(false) },
                "tls" => proxy.tls = if v == "true" { Some(true) } else { Some(false) },
                "tls-cert" => {
                    proxy.tls_cert = Some(v.to_string());
                }
                "tls-insecure" => {
                    proxy.tls_insecure = if v == "true" { Some(true) } else { Some(false) }
                }
                "ws-path" => {
                    proxy.ws_path = Some(v.to_string());
                }
                "ws-host" => {
                    proxy.ws_host = Some(v.to_string());
                }
                "sni" => {
                    proxy.sni = Some(v.to_string());
                }
                "username" => {
                    proxy.username = Some(v.to_string());
                }
                "uuid" => {
                    proxy.uuid = Some(v.to_string());
                }
                "amux" => proxy.amux = if v == "true" { Some(true) } else { Some(false) },
                "amux-max" => {
                    let i = v.parse::<i32>().ok();
                    proxy.amux_max = i;
                }
                "amux-con" => {
                    let i = v.parse::<i32>().ok();
                    proxy.amux_con = i;
                }
                "amux-max-recv" => {
                    let i = v.parse::<u64>().ok();
                    proxy.amux_max_recv = i;
                }
                "amux-max-lifetime" => {
                    let i = v.parse::<u64>().ok();
                    proxy.amux_max_lifetime = i;
                }
                "quic" => proxy.quic = if v == "true" { Some(true) } else { Some(false) },
                "reality" => proxy.reality = if v == "true" { Some(true) } else { Some(false) },
                "reality-public-key" => {
                    proxy.reality_public_key = Some(v.to_string());
                }
                "reality-short-id" => {
                    proxy.reality_short_id = Some(v.to_string());
                }
                "interface" => {
                    proxy.interface = v.to_string();
                }
                _ => {}
            }
        }

        // built-in protocols have no address port, password
        match proxy.protocol.as_str() {
            "direct" => {
                proxies.push(proxy);
                continue;
            }
            "drop" => {
                proxies.push(proxy);
                continue;
            }
            // compat
            "reject" => {
                proxy.protocol = "drop".to_string();
                proxies.push(proxy);
                continue;
            }
            _ => {}
        }

        // parse address and port
        let params = &params[1..];
        if params.len() < 2 {
            // address and port are required
            continue;
        }
        proxy.address = Some(params[0].clone());
        let port = if let Ok(p) = params[1].parse::<u16>() {
            p
        } else {
            continue; // not valid port
        };
        proxy.port = Some(port);

        // parse positional params
        let pos_params = &params[2..];
        for (i, param) in pos_params.iter().enumerate() {
            if param.contains('=') {
                continue;
            }
            match (proxy.protocol.as_str(), i) {
                ("ss" | "shadowsocks", 0) => proxy.encrypt_method = Some(param.clone()),
                ("ss" | "shadowsocks", 1) => proxy.password = Some(param.clone()),
                ("trojan", 0) => proxy.password = Some(param.clone()),
                ("vmess", 0) => proxy.username = Some(param.clone()),
                ("vless", 0) => proxy.password = Some(param.clone()),
                _ => (),
            }
        }

        // compat
        if let "ss" = proxy.protocol.as_str() {
            proxy.protocol = "shadowsocks".to_string();
        }

        proxies.push(proxy);
    }

    let mut proxy_groups = Vec::new();
    let proxy_group_lines = get_lines_by_section("Proxy Group", lines.iter());
    for line in proxy_group_lines {
        let parts: Vec<&str> = line.splitn(2, '=').map(str::trim).collect();
        if parts.len() != 2 {
            continue;
        }
        let mut group = ProxyGroup::default();
        let tag = parts[0];
        if tag.is_empty() {
            // empty tag is not allowed
            continue;
        }
        group.tag = tag.to_string();
        let params = if let Some(p) = get_char_sep_slice(parts[1], ',') {
            p
        } else {
            continue;
        };
        if params.is_empty() {
            // there must be at least one param, i.e. the protocol field
            continue;
        }
        group.protocol = params[0].clone();

        let params = &params[1..];
        if params.is_empty() {
            // require at least one proxy
            continue;
        }

        let mut actors = Vec::new();
        for param in params {
            if !param.contains('=') && !param.is_empty() {
                actors.push(param.to_string());
            }
        }
        if actors.is_empty() {
            // require at least one actor
            continue;
        }
        group.actors = Some(actors);

        for param in params {
            if param.contains('=') {
                let parts: Vec<&str> = param.split('=').map(str::trim).collect();
                if parts.len() != 2 {
                    continue;
                }
                let k = parts[0];
                let v = parts[1];
                if k.is_empty() || v.is_empty() {
                    continue;
                }
                match k {
                    "address" => {
                        group.address = Some(v.to_string());
                    }
                    "port" => {
                        group.port = v.parse().ok();
                    }
                    "health-check" => {
                        group.health_check = if v == "true" { Some(true) } else { Some(false) };
                    }
                    "check-interval" => {
                        let i = v.parse().ok();
                        group.check_interval = i;
                    }
                    "fail-timeout" => {
                        let i = v.parse().ok();
                        group.fail_timeout = i;
                    }
                    "failover" => {
                        group.failover = if v == "true" { Some(true) } else { Some(false) };
                    }
                    "fallback-cache" => {
                        group.fallback_cache = if v == "true" { Some(true) } else { Some(false) };
                    }
                    "cache-size" => {
                        let i = v.parse().ok();
                        group.cache_size = i;
                    }
                    "cache-timeout" => {
                        let i = v.parse().ok();
                        group.cache_timeout = i;
                    }
                    "last-resort" => {
                        group.last_resort = if !v.is_empty() {
                            Some(v.to_owned())
                        } else {
                            None
                        };
                    }
                    "health-check-timeout" => {
                        let i = v.parse().ok();
                        group.health_check_timeout = i;
                    }
                    "health-check-delay" => {
                        let i = v.parse().ok();
                        group.health_check_delay = i;
                    }
                    "health-check-active" => {
                        let i = v.parse().ok();
                        group.health_check_active = i;
                    }
                    "health-check-prefers" => {
                        let i = v
                            .split(":")
                            .map(str::trim)
                            .map(|x| x.to_owned())
                            .collect::<Vec<_>>();
                        let i = if !i.is_empty() { Some(i) } else { None };
                        group.health_check_prefers = i;
                    }
                    "health-check-on-start" => {
                        group.health_check_on_start =
                            if v == "true" { Some(true) } else { Some(false) };
                    }
                    "health-check-wait" => {
                        group.health_check_wait =
                            if v == "true" { Some(true) } else { Some(false) };
                    }
                    "health-check-attempts" => {
                        let i = v.parse().ok();
                        group.health_check_attempts = i;
                    }
                    "health-check-success-percentage" => {
                        let i = v.parse().ok();
                        group.health_check_success_percentage = i;
                    }
                    "delay-base" => {
                        let i = v.parse().ok();
                        group.delay_base = i;
                    }
                    "method" => {
                        group.method = if !v.is_empty() {
                            Some(v.to_owned())
                        } else {
                            None
                        };
                    }
                    _ => {}
                }
            }
        }

        // compat
        match group.protocol.as_str() {
            // url-test group is just failover without failover
            "url-test" => {
                group.protocol = "failover".to_string();
                group.failover = Some(false);
            }
            // fallback group is just failover
            "fallback" => {
                group.protocol = "failover".to_string();
            }
            _ => {}
        }

        proxy_groups.push(group);
    }

    let mut rules = Vec::new();
    let rule_lines = get_lines_by_section("Rule", lines.iter());
    for line in rule_lines {
        let params = if let Some(p) = get_char_sep_slice(&line, ',') {
            p
        } else {
            continue;
        };
        if params.len() < 2 {
            continue; // at lease 2 params
        }
        let mut rule = Rule {
            type_field: params[0].to_string(),
            ..Default::default()
        };

        // handle the FINAL rule first
        if rule.type_field == "FINAL" {
            rule.target = params[1].to_string();
            rules.push(rule);
            break; // FINAL is final.
        }

        if params.len() < 3 {
            continue; // at lease 3 params except the FINAL rule
        }

        // the 3th must be the target
        rule.target = params[2].to_string();

        match rule.type_field.as_str() {
            "IP-CIDR" | "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "GEOIP" | "EXTERNAL"
            | "PORT-RANGE" | "NETWORK" | "INBOUND-TAG" | "PROCESS-NAME" => {
                rule.filter = Some(params[1].to_string());
            }
            _ => {}
        }

        rules.push(rule);
    }

    let mut hosts = HashMap::new();
    let host_lines = get_lines_by_section("Host", lines.iter());
    for line in host_lines {
        let parts: Vec<&str> = line.split('=').map(str::trim).collect();
        if parts.len() != 2 {
            continue;
        }
        let name = parts[0];
        let ips: Vec<String> = parts[1]
            .split(',')
            .map(str::trim)
            .map(|x| x.to_owned())
            .collect();
        hosts.insert(name.to_owned(), ips);
    }

    Ok(Config {
        general: Some(general),
        proxy: Some(proxies),
        proxy_group: Some(proxy_groups),
        rule: Some(rules),
        host: Some(hosts),
        certificates: if certificates.is_empty() {
            None
        } else {
            Some(certificates)
        },
    })
}

pub fn to_common(conf: &Config) -> Result<common::Config> {
    let mut common_config = common::Config::default();

    if let Some(ext_general) = &conf.general {
        let log = common::Log {
            level: ext_general.loglevel.clone(),
            output: ext_general.logoutput.clone(),
            format: ext_general.logformat.clone(),
        };
        common_config.log = Some(log);

        let mut inbounds = Vec::new();

        if let (Some(interface), Some(port)) = (
            ext_general.http_interface.as_ref(),
            ext_general.http_port.as_ref(),
        ) {
            inbounds.push(common::Inbound {
                tag: Some("http".to_string()),
                address: Some(interface.clone()),
                port: Some(*port),
                settings: common::InboundSettings::Http,
            });
        }

        if let (Some(interface), Some(port)) = (
            ext_general.socks_interface.as_ref(),
            ext_general.socks_port.as_ref(),
        ) {
            inbounds.push(common::Inbound {
                tag: Some("socks".to_string()),
                address: Some(interface.clone()),
                port: Some(*port),
                settings: common::InboundSettings::Socks { settings: None },
            });
        }

        if let Some(nf) = &ext_general.nf {
            inbounds.push(common::Inbound {
                tag: Some("nf".to_string()),
                address: Some("127.0.0.1".to_string()),
                port: Some(0),
                settings: common::InboundSettings::Nf {
                    settings: Some(common::NfInboundSettings {
                        driver_name: nf.driver_name.clone(),
                        nfapi: nf.nfapi.clone(),
                        fake_dns_exclude: ext_general.always_real_ip.clone(),
                        fake_dns_include: ext_general.always_fake_ip.clone(),
                        tun2socks: None,
                    }),
                },
            });
        }

        if ext_general.tun_fd.is_some()
            || ext_general.tun_auto.is_some()
            || ext_general.tun.is_some()
        {
            let mut settings = common::TunInboundSettings {
                auto: None,
                fd: None,
                name: None,
                address: None,
                gateway: None,
                netmask: None,
                mtu: None,
                fake_dns_exclude: ext_general.always_real_ip.clone(),
                fake_dns_include: ext_general.always_fake_ip.clone(),
                tun2socks: ext_general.tun2socks_backend.clone(),
                wintun: ext_general.wintun.clone(),
                dns_servers: ext_general.tun_dns_server.clone(),
            };

            if let Some(fd) = ext_general.tun_fd {
                settings.fd = Some(fd);
            } else if let Some(auto) = ext_general.tun_auto {
                if auto {
                    settings.auto = Some(true);
                    settings.fd = Some(-1);
                }
            } else if let Some(ext_tun) = &ext_general.tun {
                settings.fd = Some(-1);
                settings.name = ext_tun.name.clone();
                settings.address = ext_tun.address.clone();
                settings.gateway = ext_tun.gateway.clone();
                settings.netmask = ext_tun.netmask.clone();
                settings.mtu = ext_tun.mtu;
            }

            inbounds.push(common::Inbound {
                tag: Some("tun".to_string()),
                address: None,
                port: None,
                settings: common::InboundSettings::Tun {
                    settings: Some(settings),
                },
            });
        }

        // if let (Some(interface), Some(port)) = (
        //     ext_general.api_interface.as_ref(),
        //     ext_general.api_port.as_ref(),
        // ) {
        // The API inbound is actually an HTTP inbound with specific handling in the core
        // but in common config it might be represented differently or just not supported in this way
        // Looking at the original code, there was no API inbound handling in `to_common`
        // I added it because I saw `api_interface` in `General` struct.
        // But if `common::InboundSettings` doesn't support it, I should probably remove it or map to something else.
        // However, leaf usually handles API via a separate server, not necessarily a standard inbound.
        // Let's remove this block for now to fix the compilation error, as the user asked for `tun` config support, not API.
        // }

        common_config.inbounds = Some(inbounds);
    }

    let mut outbounds = Vec::new();
    let certificates = conf.certificates.as_ref();
    let resolve_cert = |value: &Option<String>| -> Option<String> {
        let value = value.as_ref()?;
        if let Some(certificates) = certificates {
            if let Some(content) = certificates.get(value) {
                return Some(content.clone());
            }
        }
        Some(value.clone())
    };
    if let Some(ext_proxies) = &conf.proxy {
        for ext_proxy in ext_proxies {
            let protocol = match ext_proxy.protocol.as_str() {
                "ss" => "shadowsocks",
                _ => &ext_proxy.protocol,
            };

            match protocol {
                "direct" => {
                    outbounds.push(common::Outbound {
                        tag: Some(ext_proxy.tag.clone()),
                        settings: common::OutboundSettings::Direct,
                    });
                }
                "drop" => {
                    outbounds.push(common::Outbound {
                        tag: Some(ext_proxy.tag.clone()),
                        settings: common::OutboundSettings::Drop,
                    });
                }
                "redirect" => {
                    outbounds.push(common::Outbound {
                        tag: Some(ext_proxy.tag.clone()),
                        settings: common::OutboundSettings::Redirect {
                            settings: Some(common::RedirectOutboundSettings {
                                address: ext_proxy.address.clone(),
                                port: ext_proxy.port,
                            }),
                        },
                    });
                }
                "socks" => {
                    outbounds.push(common::Outbound {
                        tag: Some(ext_proxy.tag.clone()),
                        settings: common::OutboundSettings::Socks {
                            settings: Some(common::SocksOutboundSettings {
                                address: ext_proxy.address.clone(),
                                port: ext_proxy.port,
                                username: ext_proxy.username.clone(),
                                password: ext_proxy.password.clone(),
                            }),
                        },
                    });
                }
                "shadowsocks" => {
                    let settings = common::ShadowsocksOutboundSettings {
                        address: ext_proxy.address.clone(),
                        port: ext_proxy.port,
                        method: ext_proxy.encrypt_method.clone(),
                        password: ext_proxy.password.clone(),
                        prefix: ext_proxy.prefix.clone(),
                    };

                    if let Some(obfs) = &ext_proxy.obfs_type {
                        let ss_tag = format!("{}_ss_xxx", ext_proxy.tag);
                        let obfs_tag = format!("{}_obfs_xxx", ext_proxy.tag);

                        outbounds.push(common::Outbound {
                            tag: Some(ext_proxy.tag.clone()),
                            settings: common::OutboundSettings::Chain {
                                settings: Some(common::ChainOutboundSettings {
                                    actors: Some(vec![obfs_tag.clone(), ss_tag.clone()]),
                                }),
                            },
                        });

                        outbounds.push(common::Outbound {
                            tag: Some(obfs_tag),
                            settings: common::OutboundSettings::Obfs {
                                settings: Some(common::ObfsOutboundSettings {
                                    method: Some(obfs.clone()),
                                    host: ext_proxy.obfs_host.clone(),
                                    path: Some(
                                        ext_proxy.obfs_path.as_deref().unwrap_or("/").to_string(),
                                    ),
                                }),
                            },
                        });

                        outbounds.push(common::Outbound {
                            tag: Some(ss_tag),
                            settings: common::OutboundSettings::Shadowsocks {
                                settings: Some(settings),
                            },
                        });
                    } else {
                        outbounds.push(common::Outbound {
                            tag: Some(ext_proxy.tag.clone()),
                            settings: common::OutboundSettings::Shadowsocks {
                                settings: Some(settings),
                            },
                        });
                    }
                }
                "vless" => {
                    let settings = common::VlessOutboundSettings {
                        address: ext_proxy.address.clone(),
                        port: ext_proxy.port,
                        uuid: ext_proxy
                            .uuid
                            .clone()
                            .or_else(|| ext_proxy.password.clone()), // prioritize uuid, then password
                    };

                    let mut next_tag = ext_proxy.tag.clone();

                    if ext_proxy.reality.unwrap_or(false) {
                        let reality_tag = format!("{}_reality_xxx", ext_proxy.tag);
                        outbounds.push(common::Outbound {
                            tag: Some(ext_proxy.tag.clone()),
                            settings: common::OutboundSettings::Chain {
                                settings: Some(common::ChainOutboundSettings {
                                    actors: Some(vec![
                                        reality_tag.clone(),
                                        format!("{}_vless_xxx", ext_proxy.tag),
                                    ]),
                                }),
                            },
                        });

                        outbounds.push(common::Outbound {
                            tag: Some(reality_tag),
                            settings: common::OutboundSettings::Reality {
                                settings: Some(common::RealityOutboundSettings {
                                    server_name: ext_proxy.sni.clone(),
                                    public_key: ext_proxy.reality_public_key.clone(),
                                    short_id: ext_proxy.reality_short_id.clone(),
                                }),
                            },
                        });

                        next_tag = format!("{}_vless_xxx", ext_proxy.tag);
                    }

                    outbounds.push(common::Outbound {
                        tag: Some(next_tag),
                        settings: common::OutboundSettings::Vless {
                            settings: Some(settings),
                        },
                    });
                }
                "trojan" | "vmess" => {
                    let mut actors = Vec::new();
                    let mut component_outbounds = Vec::new();

                    // tls
                    let tls_tag = format!("{}_tls_xxx", ext_proxy.tag);
                    component_outbounds.push(common::Outbound {
                        tag: Some(tls_tag.clone()),
                        settings: common::OutboundSettings::Tls {
                            settings: Some(common::TlsOutboundSettings {
                                server_name: ext_proxy.sni.clone(),
                                alpn: if protocol == "trojan" {
                                    None
                                } else {
                                    Some(vec!["http/1.1".to_string()])
                                },
                                certificate: resolve_cert(&ext_proxy.tls_cert),
                                certificate_key: None,
                                raw_certificate: None,
                                raw_certificate_key: None,
                                insecure: ext_proxy.tls_insecure,
                            }),
                        },
                    });

                    // ws
                    let ws_tag = format!("{}_ws_xxx", ext_proxy.tag);
                    let mut ws_headers = HashMap::new();
                    if let Some(host) = &ext_proxy.ws_host {
                        ws_headers.insert("Host".to_string(), host.clone());
                    }
                    component_outbounds.push(common::Outbound {
                        tag: Some(ws_tag.clone()),
                        settings: common::OutboundSettings::WebSocket {
                            settings: Some(common::WebSocketOutboundSettings {
                                path: Some(ext_proxy.ws_path.as_deref().unwrap_or("/").to_string()),
                                headers: if ws_headers.is_empty() {
                                    None
                                } else {
                                    Some(ws_headers)
                                },
                            }),
                        },
                    });

                    // amux or quic or tls/ws
                    if ext_proxy.amux.unwrap_or(false) {
                        let amux_tag = format!("{}_amux_xxx", ext_proxy.tag);
                        let mut amux_actors = vec![tls_tag.clone()];
                        if ext_proxy.ws.unwrap_or(false) {
                            amux_actors.push(ws_tag.clone());
                        }
                        component_outbounds.push(common::Outbound {
                            tag: Some(amux_tag.clone()),
                            settings: common::OutboundSettings::AMux {
                                settings: Some(common::AMuxOutboundSettings {
                                    address: ext_proxy.address.clone(),
                                    port: ext_proxy.port,
                                    actors: Some(amux_actors),
                                    max_accepts: ext_proxy.amux_max.map(|x| x as u32),
                                    concurrency: ext_proxy.amux_con.map(|x| x as u32),
                                    max_recv_bytes: ext_proxy.amux_max_recv,
                                    max_lifetime: ext_proxy.amux_max_lifetime,
                                }),
                            },
                        });
                        actors.push(amux_tag);
                    } else if ext_proxy.quic.unwrap_or(false) {
                        let quic_tag = format!("{}_quic_xxx", ext_proxy.tag);
                        component_outbounds.push(common::Outbound {
                            tag: Some(quic_tag.clone()),
                            settings: common::OutboundSettings::Quic {
                                settings: Some(common::QuicOutboundSettings {
                                    address: ext_proxy.address.clone(),
                                    port: ext_proxy.port,
                                    server_name: ext_proxy.sni.clone(),
                                    certificate: resolve_cert(&ext_proxy.tls_cert),
                                    certificate_key: None,
                                    raw_certificate: None,
                                    raw_certificate_key: None,
                                    alpn: Some(vec!["http/1.1".to_string()]),
                                }),
                            },
                        });
                        actors.push(quic_tag);
                    } else {
                        actors.push(tls_tag);
                        if ext_proxy.ws.unwrap_or(false) {
                            actors.push(ws_tag);
                        }
                    }

                    // core protocol
                    let core_tag = format!("{}_{}_xxx", ext_proxy.tag, protocol);
                    if protocol == "trojan" {
                        component_outbounds.push(common::Outbound {
                            tag: Some(core_tag.clone()),
                            settings: common::OutboundSettings::Trojan {
                                settings: Some(common::TrojanOutboundSettings {
                                    address: if ext_proxy.amux.unwrap_or(false) {
                                        None
                                    } else {
                                        ext_proxy.address.clone()
                                    },
                                    port: if ext_proxy.amux.unwrap_or(false) {
                                        None
                                    } else {
                                        ext_proxy.port
                                    },
                                    password: ext_proxy.password.clone(),
                                }),
                            },
                        });
                    } else {
                        component_outbounds.push(common::Outbound {
                            tag: Some(core_tag.clone()),
                            settings: common::OutboundSettings::VMess {
                                settings: Some(common::VMessOutboundSettings {
                                    address: if ext_proxy.amux.unwrap_or(false) {
                                        None
                                    } else {
                                        ext_proxy.address.clone()
                                    },
                                    port: if ext_proxy.amux.unwrap_or(false) {
                                        None
                                    } else {
                                        ext_proxy.port
                                    },
                                    uuid: ext_proxy
                                        .uuid
                                        .clone()
                                        .or_else(|| ext_proxy.username.clone()),
                                    security: Some(
                                        ext_proxy
                                            .encrypt_method
                                            .as_deref()
                                            .unwrap_or("chacha20-ietf-poly1305")
                                            .to_string(),
                                    ),
                                }),
                            },
                        });
                    }
                    actors.push(core_tag);

                    // chain
                    outbounds.push(common::Outbound {
                        tag: Some(ext_proxy.tag.clone()),
                        settings: common::OutboundSettings::Chain {
                            settings: Some(common::ChainOutboundSettings {
                                actors: Some(actors),
                            }),
                        },
                    });
                    outbounds.append(&mut component_outbounds);
                }
                _ => {}
            }
        }
    }

    if let Some(ext_proxy_groups) = &conf.proxy_group {
        for ext_proxy_group in ext_proxy_groups {
            let protocol = ext_proxy_group.protocol.as_str();
            match protocol {
                "chain" => {
                    outbounds.push(common::Outbound {
                        tag: Some(ext_proxy_group.tag.clone()),
                        settings: common::OutboundSettings::Chain {
                            settings: Some(common::ChainOutboundSettings {
                                actors: ext_proxy_group.actors.clone(),
                            }),
                        },
                    });
                }
                "tryall" => {
                    outbounds.push(common::Outbound {
                        tag: Some(ext_proxy_group.tag.clone()),
                        settings: common::OutboundSettings::TryAll {
                            settings: Some(common::TryAllOutboundSettings {
                                actors: ext_proxy_group.actors.clone(),
                                delay_base: ext_proxy_group.delay_base,
                            }),
                        },
                    });
                }
                "static" => {
                    outbounds.push(common::Outbound {
                        tag: Some(ext_proxy_group.tag.clone()),
                        settings: common::OutboundSettings::Static {
                            settings: Some(common::StaticOutboundSettings {
                                actors: ext_proxy_group.actors.clone(),
                                method: ext_proxy_group.method.clone(),
                            }),
                        },
                    });
                }
                "failover" => {
                    outbounds.push(common::Outbound {
                        tag: Some(ext_proxy_group.tag.clone()),
                        settings: common::OutboundSettings::FailOver {
                            settings: Some(common::FailOverOutboundSettings {
                                actors: ext_proxy_group.actors.clone(),
                                fail_timeout: ext_proxy_group.fail_timeout,
                                health_check: ext_proxy_group.health_check,
                                health_check_timeout: ext_proxy_group.health_check_timeout,
                                health_check_delay: ext_proxy_group.health_check_delay,
                                health_check_active: ext_proxy_group.health_check_active,
                                health_check_prefers: ext_proxy_group.health_check_prefers.clone(),
                                check_interval: ext_proxy_group.check_interval,
                                health_check_on_start: ext_proxy_group.health_check_on_start,
                                health_check_wait: ext_proxy_group.health_check_wait,
                                health_check_attempts: ext_proxy_group.health_check_attempts,
                                health_check_success_percentage: ext_proxy_group
                                    .health_check_success_percentage,
                                failover: ext_proxy_group.failover,
                                fallback_cache: ext_proxy_group.fallback_cache,
                                cache_size: ext_proxy_group.cache_size,
                                cache_timeout: ext_proxy_group.cache_timeout,
                            }),
                        },
                    });
                }
                "select" => {
                    outbounds.push(common::Outbound {
                        tag: Some(ext_proxy_group.tag.clone()),
                        settings: common::OutboundSettings::Select {
                            settings: Some(common::SelectOutboundSettings {
                                actors: ext_proxy_group.actors.clone(),
                            }),
                        },
                    });
                }
                "mptp" => {
                    outbounds.push(common::Outbound {
                        tag: Some(ext_proxy_group.tag.clone()),
                        settings: common::OutboundSettings::Mptp {
                            settings: Some(common::MptpOutboundSettings {
                                actors: ext_proxy_group.actors.clone(),
                                address: ext_proxy_group.address.clone(),
                                port: ext_proxy_group.port,
                            }),
                        },
                    });
                }
                _ => {}
            }
        }
    }
    common_config.outbounds = Some(outbounds);

    let mut rules = Vec::new();
    if let Some(ext_rules) = &conf.rule {
        for ext_rule in ext_rules {
            let mut rule = common::Rule {
                type_field: Some(ext_rule.type_field.clone()),
                ip: None,
                domain: None,
                domain_keyword: None,
                domain_suffix: None,
                geoip: None,
                external: None,
                port_range: None,
                network: None,
                inbound_tag: None,
                process_name: None,
                target: ext_rule.target.clone(),
            };

            if let Some(filter) = &ext_rule.filter {
                match ext_rule.type_field.as_str() {
                    "IP-CIDR" => rule.ip = Some(vec![filter.clone()]),
                    "DOMAIN" => rule.domain = Some(vec![filter.clone()]),
                    "DOMAIN-KEYWORD" => rule.domain_keyword = Some(vec![filter.clone()]),
                    "DOMAIN-SUFFIX" => rule.domain_suffix = Some(vec![filter.clone()]),
                    "GEOIP" => rule.geoip = Some(vec![filter.clone()]),
                    "EXTERNAL" => rule.external = Some(vec![filter.clone()]),
                    "PORT-RANGE" => rule.port_range = Some(vec![filter.clone()]),
                    "NETWORK" => rule.network = Some(vec![filter.clone()]),
                    "INBOUND-TAG" => rule.inbound_tag = Some(vec![filter.clone()]),
                    "PROCESS-NAME" => rule.process_name = Some(vec![filter.clone()]),
                    _ => {}
                }
            }
            rules.push(rule);
        }
    }
    common_config.router = Some(common::Router {
        rules: Some(rules),
        domain_resolve: conf.general.as_ref().and_then(|g| g.routing_domain_resolve),
    });

    let mut dns = common::Dns {
        servers: None,
        hosts: None,
    };
    if let Some(ext_general) = &conf.general {
        dns.servers = ext_general.dns_server.clone();
    }
    dns.hosts = conf.host.clone();
    common_config.dns = Some(dns);

    Ok(common_config)
}

pub fn to_internal(conf: &Config) -> Result<internal::Config> {
    let common_config = to_common(conf)?;
    common::to_internal(common_config)
}

pub fn from_string(s: &str) -> Result<internal::Config> {
    let lines = s.lines().map(|s| Ok(s.to_string())).collect();
    let config = from_lines(lines)?;
    to_internal(&config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trojan_tls_outbound_order() {
        let conf = r#"
[Proxy]
Direct = direct
Trojan = trojan, 1.2.3.4, 443, password, sni=www.google.com
"#;
        let lines: Vec<io::Result<String>> = conf.lines().map(|s| Ok(s.to_string())).collect();
        let config = from_lines(lines).unwrap();
        let common = to_common(&config).unwrap();

        let outbounds = common.outbounds.unwrap();
        // The first outbound should be "Direct"
        assert_eq!(outbounds[0].tag, Some("Direct".to_string()));
        // The second outbound should be the main "Trojan" outbound (which is a Chain)
        assert_eq!(outbounds[1].tag, Some("Trojan".to_string()));
        if let common::OutboundSettings::Chain { .. } = &outbounds[1].settings {
            // Correct
        } else {
            panic!(
                "Second outbound is not a Chain: {:?}",
                outbounds[1].settings
            );
        }
        // The third outbound should be the TLS component
        assert_eq!(outbounds[2].tag, Some("Trojan_tls_xxx".to_string()));
    }

    #[test]
    fn test_vmess_amux_outbound_order() {
        let conf = r#"
[Proxy]
Vmess = vmess, 1.2.3.4, 443, username, amux=true, sni=www.google.com
"#;
        let lines: Vec<io::Result<String>> = conf.lines().map(|s| Ok(s.to_string())).collect();
        let config = from_lines(lines).unwrap();
        let common = to_common(&config).unwrap();

        let outbounds = common.outbounds.unwrap();
        // The first outbound should be the main "Vmess" outbound (Chain)
        assert_eq!(outbounds[0].tag, Some("Vmess".to_string()));
        // The following should be components
        let tags: Vec<_> = outbounds.iter().map(|o| o.tag.as_ref().unwrap()).collect();
        assert!(tags.contains(&&"Vmess_tls_xxx".to_string()));
        assert!(tags.contains(&&"Vmess_amux_xxx".to_string()));
        assert!(tags.contains(&&"Vmess_vmess_xxx".to_string()));
        let vmess = outbounds
            .iter()
            .find(|o| o.tag == Some("Vmess_vmess_xxx".to_string()))
            .unwrap();
        if let common::OutboundSettings::VMess { settings } = &vmess.settings {
            assert_eq!(
                settings.as_ref().unwrap().uuid,
                Some("username".to_string())
            );
        }
    }

    #[test]
    fn test_wintun_conf() {
        let conf = r#"
[General]
tun = auto
wintun = /path/to/wintun.dll
tun-dns-server = 8.8.8.8, 8.8.4.4
"#;
        let lines: Vec<io::Result<String>> = conf.lines().map(|s| Ok(s.to_string())).collect();
        let config = from_lines(lines).unwrap();
        let common = to_common(&config).unwrap();

        if let Some(inbounds) = common.inbounds {
            let tun = inbounds
                .iter()
                .find(|i| i.tag == Some("tun".to_string()))
                .unwrap();
            if let common::InboundSettings::Tun { settings } = &tun.settings {
                let settings = settings.as_ref().unwrap();
                assert_eq!(settings.wintun, Some("/path/to/wintun.dll".to_string()));
                assert_eq!(
                    settings.dns_servers,
                    Some(vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()])
                );
            } else {
                panic!("Not tun inbound");
            }
        } else {
            panic!("No inbounds");
        }
    }

    #[test]
    fn test_vmess_vless_uuid() {
        let conf = r#"
[Proxy]
Vmess1 = vmess, 1.2.3.4, 443, username, uuid=uuid1
Vmess2 = vmess, 1.2.3.4, 443, username
Vless1 = vless, 1.2.3.4, 443, password, uuid=uuid2
Vless2 = vless, 1.2.3.4, 443, password
"#;
        let lines: Vec<io::Result<String>> = conf.lines().map(|s| Ok(s.to_string())).collect();
        let config = from_lines(lines).unwrap();
        let common = to_common(&config).unwrap();

        let outbounds = common.outbounds.unwrap();

        // Vmess1: should use uuid1
        let vmess1 = outbounds
            .iter()
            .find(|o| o.tag == Some("Vmess1_vmess_xxx".to_string()))
            .unwrap();
        if let common::OutboundSettings::VMess { settings } = &vmess1.settings {
            assert_eq!(settings.as_ref().unwrap().uuid, Some("uuid1".to_string()));
        } else {
            panic!("Not vmess: {:?}", vmess1.settings);
        }

        // Vmess2: should use username
        let vmess2 = outbounds
            .iter()
            .find(|o| o.tag == Some("Vmess2_vmess_xxx".to_string()))
            .unwrap();
        if let common::OutboundSettings::VMess { settings } = &vmess2.settings {
            assert_eq!(
                settings.as_ref().unwrap().uuid,
                Some("username".to_string())
            );
        } else {
            panic!("Not vmess: {:?}", vmess2.settings);
        }

        // Vless1: should use uuid2
        let vless1 = outbounds
            .iter()
            .find(|o| o.tag == Some("Vless1".to_string()))
            .unwrap();
        if let common::OutboundSettings::Vless { settings } = &vless1.settings {
            assert_eq!(settings.as_ref().unwrap().uuid, Some("uuid2".to_string()));
        } else {
            panic!("Not vless: {:?}", vless1.settings);
        }

        // Vless2: should use password
        let vless2 = outbounds
            .iter()
            .find(|o| o.tag == Some("Vless2".to_string()))
            .unwrap();
        if let common::OutboundSettings::Vless { settings } = &vless2.settings {
            assert_eq!(
                settings.as_ref().unwrap().uuid,
                Some("password".to_string())
            );
        } else {
            panic!("Not vless: {:?}", vless2.settings);
        }
    }

    #[test]
    fn test_mptp_proxy_group() {
        let conf = r#"
[Proxy Group]
MptpOutTag = mptp, actor1, actor2, actor3, address=1.2.3.4, port=10000
"#;
        let lines: Vec<io::Result<String>> = conf.lines().map(|s| Ok(s.to_string())).collect();
        let config = from_lines(lines).unwrap();
        let common = to_common(&config).unwrap();

        let outbounds = common.outbounds.unwrap();
        assert_eq!(outbounds.len(), 1);
        let mptp = &outbounds[0];
        assert_eq!(mptp.tag, Some("MptpOutTag".to_string()));
        if let common::OutboundSettings::Mptp { settings } = &mptp.settings {
            let settings = settings.as_ref().unwrap();
            assert_eq!(
                settings.actors,
                Some(vec![
                    "actor1".to_string(),
                    "actor2".to_string(),
                    "actor3".to_string()
                ])
            );
            assert_eq!(settings.address, Some("1.2.3.4".to_string()));
            assert_eq!(settings.port, Some(10000));
        } else {
            panic!("Not mptp outbound: {:?}", mptp.settings);
        }
    }

    #[test]
    fn test_section_name_compatibility() {
        let conf = r#"
[general]
loglevel = trace

[PROXY_GROUP]
ProxyGroup1 = select, Direct, Trojan

[proxygroup]
ProxyGroup2 = select, Direct, Trojan

[proxy_group]
ProxyGroup3 = select, Direct, Trojan

[rule]
DOMAIN,google.com,Direct

[host]
google.com = 1.2.3.4

[certificate_MyCert]
CERT1

[certificate.AnotherCert]
CERT2

[certificate MyThirdCert]
CERT3

[certificateNoSpaceCert]
CERT4
"#;
        let lines: Vec<io::Result<String>> = conf.lines().map(|s| Ok(s.to_string())).collect();
        let config = from_lines(lines).unwrap();

        assert!(config.general.is_some());
        assert_eq!(config.general.unwrap().loglevel, Some("trace".to_string()));

        assert!(config.proxy_group.is_some());
        assert_eq!(config.proxy_group.as_ref().unwrap().len(), 3);
        assert_eq!(config.proxy_group.as_ref().unwrap()[0].tag, "ProxyGroup1");
        assert_eq!(config.proxy_group.as_ref().unwrap()[1].tag, "ProxyGroup2");
        assert_eq!(config.proxy_group.as_ref().unwrap()[2].tag, "ProxyGroup3");

        assert!(config.rule.is_some());
        assert_eq!(config.rule.unwrap().len(), 1);

        assert!(config.host.is_some());
        assert_eq!(config.host.unwrap().len(), 1);

        assert!(config.certificates.is_some());
        let certs = config.certificates.unwrap();
        assert!(certs.contains_key("MyCert"));
        assert!(certs.contains_key("AnotherCert"));
        assert!(certs.contains_key("MyThirdCert"));
        assert!(certs.contains_key("NoSpaceCert"));
        assert_eq!(certs.get("MyCert").unwrap(), "CERT1\n");
        assert_eq!(certs.get("AnotherCert").unwrap(), "CERT2\n");
        assert_eq!(certs.get("MyThirdCert").unwrap(), "CERT3\n");
        assert_eq!(certs.get("NoSpaceCert").unwrap(), "CERT4\n");
    }
}

pub fn from_file<P>(path: P) -> Result<internal::Config>
where
    P: AsRef<Path>,
{
    let lines = read_lines(path)?.collect();
    let config = from_lines(lines)?;
    to_internal(&config)
}
