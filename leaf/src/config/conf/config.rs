use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use anyhow::Result;
use protobuf::Message;
use regex::Regex;

use crate::config::{external_rule, internal};

#[derive(Debug, Default)]
pub struct Tun {
    pub name: Option<String>,
    pub address: Option<String>,
    pub netmask: Option<String>,
    pub gateway: Option<String>,
    pub mtu: Option<i32>,
}

#[derive(Debug, Default)]
pub struct General {
    pub tun: Option<Tun>,
    pub tun_fd: Option<i32>,
    pub tun_auto: Option<bool>,
    pub loglevel: Option<String>,
    pub logoutput: Option<String>,
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

    pub amux: Option<bool>,
    pub amux_max: Option<i32>,
    pub amux_con: Option<i32>,

    pub quic: Option<bool>,
}

impl Default for Proxy {
    fn default() -> Self {
        Proxy {
            tag: "".to_string(),
            protocol: "".to_string(),
            interface: (&*crate::option::UNSPECIFIED_BIND_ADDR).ip().to_string(),
            address: None,
            port: None,
            encrypt_method: Some("chacha20-ietf-poly1305".to_string()),
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
            amux: Some(false),
            amux_max: Some(8),
            amux_con: Some(2),
            quic: Some(false),
        }
    }
}
#[derive(Debug)]
pub struct ProxyGroup {
    pub tag: String,
    pub protocol: String,
    pub actors: Option<Vec<String>>,

    // failover
    pub health_check: Option<bool>,
    pub check_interval: Option<i32>,
    pub fail_timeout: Option<i32>,
    pub failover: Option<bool>,
    pub fallback_cache: Option<bool>,
    pub cache_size: Option<i32>,
    pub cache_timeout: Option<i32>,
    pub last_resort: Option<String>,
    pub health_check_timeout: Option<i32>,
    pub health_check_delay: Option<i32>,
    pub health_check_active: Option<i32>,

    // tryall
    pub delay_base: Option<i32>,

    // static
    pub method: Option<String>,
}

impl Default for ProxyGroup {
    fn default() -> Self {
        ProxyGroup {
            tag: "".to_string(),
            protocol: "".to_string(),
            actors: None,
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
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn remove_comments(text: &str) -> Cow<str> {
    let re = Regex::new(r"(#[^*]*)").unwrap();
    re.replace(text, "")
}

fn get_section(text: &str) -> Option<&str> {
    let re = Regex::new(r"^\s*\[\s*([^\]]*)\s*\]\s*$").unwrap();
    let caps = re.captures(text);
    caps.as_ref()?;
    Some(caps.unwrap().get(1).unwrap().as_str())
}

fn get_lines_by_section<'a, I>(section: &str, lines: I) -> Vec<String>
where
    I: Iterator<Item = &'a io::Result<String>>,
{
    let mut new_lines = Vec::new();
    let mut curr_sect: String = "".to_string();
    for line in lines.flatten().map(|x| x.trim()) {
        let line = remove_comments(line);
        if let Some(s) = get_section(line.as_ref()) {
            curr_sect = s.to_string();
            continue;
        }
        if curr_sect.as_str() == section && !line.is_empty() {
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
    let env_lines = get_lines_by_section("Env", lines.iter());
    for line in env_lines {
        let parts: Vec<&str> = line.split('=').map(str::trim).collect();
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
                    if items.len() == 1 {
                        general.tun_auto = Some(items[0] == "auto");
                        continue;
                    }
                    if items.len() != 5 {
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
            "loglevel" => {
                general.loglevel = Some(parts[1].to_string());
            }
            "logoutput" => {
                general.logoutput = Some(parts[1].to_string());
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
                "amux" => proxy.amux = if v == "true" { Some(true) } else { Some(false) },
                "amux-max" => {
                    let i = if let Ok(i) = v.parse::<i32>() {
                        Some(i)
                    } else {
                        None
                    };
                    proxy.amux_max = i;
                }
                "amux-con" => {
                    let i = if let Ok(i) = v.parse::<i32>() {
                        Some(i)
                    } else {
                        None
                    };
                    proxy.amux_con = i;
                }
                "quic" => proxy.quic = if v == "true" { Some(true) } else { Some(false) },
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
                    "health-check" => {
                        group.health_check = if v == "true" { Some(true) } else { Some(false) };
                    }
                    "check-interval" => {
                        let i = if let Ok(i) = v.parse::<i32>() {
                            Some(i)
                        } else {
                            None
                        };
                        group.check_interval = i;
                    }
                    "fail-timeout" => {
                        let i = if let Ok(i) = v.parse::<i32>() {
                            Some(i)
                        } else {
                            None
                        };
                        group.fail_timeout = i;
                    }
                    "failover" => {
                        group.failover = if v == "true" { Some(true) } else { Some(false) };
                    }
                    "fallback-cache" => {
                        group.fallback_cache = if v == "true" { Some(true) } else { Some(false) };
                    }
                    "cache-size" => {
                        let i = if let Ok(i) = v.parse::<i32>() {
                            Some(i)
                        } else {
                            None
                        };
                        group.cache_size = i;
                    }
                    "cache-timeout" => {
                        let i = if let Ok(i) = v.parse::<i32>() {
                            Some(i)
                        } else {
                            None
                        };
                        group.cache_timeout = i;
                    }
                    "last-resort" => {
                        let i = if let Ok(i) = v.parse::<String>() {
                            Some(i)
                        } else {
                            None
                        };
                        group.last_resort = i;
                    }
                    "health-check-timeout" => {
                        let i = if let Ok(i) = v.parse::<i32>() {
                            Some(i)
                        } else {
                            None
                        };
                        group.health_check_timeout = i;
                    }
                    "health-check-delay" => {
                        let i = if let Ok(i) = v.parse::<i32>() {
                            Some(i)
                        } else {
                            None
                        };
                        group.health_check_delay = i;
                    }
                    "health-check-active" => {
                        let i = if let Ok(i) = v.parse::<i32>() {
                            Some(i)
                        } else {
                            None
                        };
                        group.health_check_active = i;
                    }
                    "delay-base" => {
                        let i = if let Ok(i) = v.parse::<i32>() {
                            Some(i)
                        } else {
                            None
                        };
                        group.delay_base = i;
                    }
                    "method" => {
                        let i = if let Ok(i) = v.parse::<String>() {
                            Some(i)
                        } else {
                            None
                        };
                        group.method = i;
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
            | "PORT-RANGE" | "NETWORK" | "INBOUND-TAG" => {
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
    })
}

pub fn to_internal(conf: &mut Config) -> Result<internal::Config> {
    let mut log = internal::Log::new();
    if let Some(ext_general) = &conf.general {
        if let Some(ext_loglevel) = &ext_general.loglevel {
            match ext_loglevel.as_str() {
                "trace" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::TRACE),
                "debug" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::DEBUG),
                "info" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::INFO),
                "warn" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::WARN),
                "error" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::ERROR),
                _ => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::WARN),
            }
        }
        if let Some(ext_logoutput) = &ext_general.logoutput {
            match ext_logoutput.as_str() {
                "console" => {
                    log.output = protobuf::EnumOrUnknown::new(internal::log::Output::CONSOLE)
                }
                _ => {
                    log.output = protobuf::EnumOrUnknown::new(internal::log::Output::FILE);
                    log.output_file = ext_logoutput.clone();
                }
            }
        }
    }

    let mut inbounds = Vec::new();
    if let Some(ext_general) = &conf.general {
        if ext_general.http_interface.is_some() && ext_general.http_port.is_some() {
            let mut inbound = internal::Inbound::new();
            inbound.protocol = "http".to_string();
            inbound.tag = "http".to_string();
            inbound.address = ext_general.http_interface.as_ref().unwrap().to_string();
            inbound.port = ext_general.http_port.unwrap() as u32;
            inbounds.push(inbound);
        }
        if ext_general.socks_interface.is_some() && ext_general.socks_port.is_some() {
            let mut inbound = internal::Inbound::new();
            inbound.protocol = "socks".to_string();
            inbound.tag = "socks".to_string();
            inbound.address = ext_general.socks_interface.as_ref().unwrap().to_string();
            inbound.port = ext_general.socks_port.unwrap() as u32;
            inbounds.push(inbound);
        }

        if ext_general.tun_fd.is_some()
            || ext_general.tun_auto.is_some()
            || ext_general.tun.is_some()
        {
            let mut inbound = internal::Inbound::new();
            inbound.protocol = "tun".to_string();
            inbound.tag = "tun".to_string();
            let mut settings = internal::TunInboundSettings::new();

            let mut fake_dns_exclude = Vec::new();
            if let Some(ext_always_real_ip) = &ext_general.always_real_ip {
                for item in ext_always_real_ip {
                    fake_dns_exclude.push(item.clone())
                }
                if fake_dns_exclude.len() > 0 {
                    settings.fake_dns_exclude = fake_dns_exclude;
                }
            }

            let mut fake_dns_include = Vec::new();
            if let Some(ext_always_fake_ip) = &ext_general.always_fake_ip {
                for item in ext_always_fake_ip {
                    fake_dns_include.push(item.clone())
                }
                if fake_dns_include.len() > 0 {
                    settings.fake_dns_include = fake_dns_include;
                }
            }

            if ext_general.tun_fd.is_some() {
                settings.fd = ext_general.tun_fd.unwrap();
            } else if ext_general.tun_auto.is_some() && ext_general.tun_auto.unwrap() {
                settings.auto = true;
                settings.fd = -1; // disable fd option
            } else {
                let ext_tun = ext_general.tun.as_ref().unwrap();

                settings.fd = -1; // disable fd option
                if let Some(ext_name) = &ext_tun.name {
                    settings.name = ext_name.clone();
                }
                if let Some(ext_address) = &ext_tun.address {
                    settings.address = ext_address.clone();
                }
                if let Some(ext_gateway) = &ext_tun.gateway {
                    settings.gateway = ext_gateway.clone();
                }
                if let Some(ext_netmask) = &ext_tun.netmask {
                    settings.netmask = ext_netmask.clone();
                }
                if let Some(ext_mtu) = ext_tun.mtu {
                    settings.mtu = ext_mtu;
                } else {
                    settings.mtu = 1500;
                }
            }

            // TODO tun opts
            let settings = settings.write_to_bytes().unwrap();
            inbound.settings = settings;
            inbounds.push(inbound);
        }
    }

    let mut outbounds = Vec::new();
    if let Some(ext_proxies) = &conf.proxy {
        for ext_proxy in ext_proxies {
            let mut outbound = internal::Outbound::new();
            let ext_protocol = match ext_proxy.protocol.as_str() {
                "ss" => "shadowsocks",
                _ => &ext_proxy.protocol,
            };
            outbound.protocol = ext_protocol.to_string();
            outbound.tag = ext_proxy.tag.clone();
            match outbound.protocol.as_str() {
                "direct" | "drop" => {
                    outbounds.push(outbound);
                }
                "redirect" => {
                    let mut settings = internal::RedirectOutboundSettings::new();
                    if let Some(ext_address) = &ext_proxy.address {
                        settings.address = ext_address.clone();
                    }
                    if let Some(ext_port) = &ext_proxy.port {
                        settings.port = *ext_port as u32;
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "socks" => {
                    let mut settings = internal::SocksOutboundSettings::new();
                    if let Some(ext_address) = &ext_proxy.address {
                        settings.address = ext_address.clone();
                    }
                    if let Some(ext_port) = &ext_proxy.port {
                        settings.port = *ext_port as u32;
                    }
                    if let Some(ext_username) = &ext_proxy.username {
                        settings.username = ext_username.clone();
                    }
                    if let Some(ext_password) = &ext_proxy.password {
                        settings.password = ext_password.clone();
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "shadowsocks" => {
                    let mut settings = internal::ShadowsocksOutboundSettings::new();
                    if let Some(ext_address) = &ext_proxy.address {
                        settings.address = ext_address.clone();
                    }
                    if let Some(ext_port) = &ext_proxy.port {
                        settings.port = *ext_port as u32;
                    }
                    if let Some(ext_encrypt_method) = &ext_proxy.encrypt_method {
                        settings.method = ext_encrypt_method.clone();
                    } else {
                        settings.method = "chacha20-ietf-poly1305".to_string();
                    }
                    if let Some(ext_password) = &ext_proxy.password {
                        settings.password = ext_password.clone();
                    }
                    if let Some(obfs) = &ext_proxy.obfs_type {
                        outbound.tag = format!("{}_ss_xxx", ext_proxy.tag.clone());
                        // obfs
                        let mut obfs_outbound = internal::Outbound::new();
                        obfs_outbound.protocol = "obfs".to_string();
                        let mut obfs_settings = internal::ObfsOutboundSettings::new();
                        obfs_settings.method = obfs.clone();
                        if let Some(ext_obfs_host) = &ext_proxy.obfs_host {
                            obfs_settings.host = ext_obfs_host.clone();
                        }
                        obfs_settings.path =
                            ext_proxy.obfs_path.as_deref().unwrap_or("/").to_string();
                        let obfs_settings = obfs_settings.write_to_bytes().unwrap();
                        obfs_outbound.settings = obfs_settings;
                        obfs_outbound.tag = format!("{}_obfs_xxx", ext_proxy.tag.clone());

                        // chain
                        let mut chain_outbound = internal::Outbound::new();
                        chain_outbound.tag = ext_proxy.tag.clone();
                        let mut chain_settings = internal::ChainOutboundSettings::new();
                        chain_settings.actors.push(obfs_outbound.tag.clone());
                        chain_settings.actors.push(outbound.tag.clone());
                        let chain_settings = chain_settings.write_to_bytes().unwrap();
                        chain_outbound.settings = chain_settings;
                        chain_outbound.protocol = "chain".to_string();

                        // always push chain first, in case there isn't final rule,
                        // the chain outbound will be the default one to use
                        outbounds.push(chain_outbound);
                        outbounds.push(obfs_outbound);
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "trojan" => {
                    // tls
                    let mut tls_outbound = internal::Outbound::new();
                    tls_outbound.protocol = "tls".to_string();
                    let mut tls_settings = internal::TlsOutboundSettings::new();
                    if let Some(ext_sni) = &ext_proxy.sni {
                        tls_settings.server_name = ext_sni.clone();
                    }
                    if let Some(ext_tls_cert) = &ext_proxy.tls_cert {
                        let cert = Path::new(ext_tls_cert);
                        if cert.is_absolute() {
                            tls_settings.certificate = cert.to_string_lossy().to_string();
                        } else {
                            let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                            let path = asset_loc.join(cert).to_string_lossy().to_string();
                            tls_settings.certificate = path;
                        }
                    }
                    tls_settings.insecure = ext_proxy.tls_insecure.unwrap_or_default();
                    let tls_settings = tls_settings.write_to_bytes().unwrap();
                    tls_outbound.settings = tls_settings;
                    tls_outbound.tag = format!("{}_tls_xxx", ext_proxy.tag.clone());

                    // ws
                    let mut ws_outbound = internal::Outbound::new();
                    ws_outbound.protocol = "ws".to_string();
                    let mut ws_settings = internal::WebSocketOutboundSettings::new();
                    if let Some(ext_ws_path) = &ext_proxy.ws_path {
                        ws_settings.path = ext_ws_path.clone();
                    } else {
                        ws_settings.path = "/".to_string();
                    }
                    if let Some(ext_ws_host) = &ext_proxy.ws_host {
                        let mut headers = HashMap::new();
                        headers.insert("Host".to_string(), ext_ws_host.clone());
                        ws_settings.headers = headers;
                    }
                    let ws_settings = ws_settings.write_to_bytes().unwrap();
                    ws_outbound.settings = ws_settings;
                    ws_outbound.tag = format!("{}_ws_xxx", ext_proxy.tag.clone());

                    // amux
                    let mut amux_outbound = internal::Outbound::new();
                    amux_outbound.tag = ext_proxy.tag.clone();
                    let mut amux_settings = internal::AMuxOutboundSettings::new();
                    // always enable tls for trojan
                    amux_settings.actors.push(tls_outbound.tag.clone());
                    if ext_proxy.ws.unwrap() {
                        amux_settings.actors.push(ws_outbound.tag.clone());
                    }
                    if let Some(ext_address) = &ext_proxy.address {
                        amux_settings.address = ext_address.clone();
                    }
                    if let Some(ext_port) = &ext_proxy.port {
                        amux_settings.port = *ext_port as u32;
                    }
                    if let Some(ext_max_accepts) = &ext_proxy.amux_max {
                        amux_settings.max_accepts = *ext_max_accepts as u32;
                    }
                    if let Some(ext_concurrency) = &ext_proxy.amux_con {
                        amux_settings.concurrency = *ext_concurrency as u32;
                    }
                    let amux_settings = amux_settings.write_to_bytes().unwrap();
                    amux_outbound.settings = amux_settings;
                    amux_outbound.protocol = "amux".to_string();
                    amux_outbound.tag = format!("{}_amux_xxx", ext_proxy.tag.clone());
                    // quic
                    let mut quic_outbound = internal::Outbound::new();
                    quic_outbound.tag = ext_proxy.tag.clone();
                    let mut quic_settings = internal::QuicOutboundSettings::new();
                    if let Some(ext_address) = &ext_proxy.address {
                        quic_settings.address = ext_address.clone();
                    }
                    if let Some(ext_port) = &ext_proxy.port {
                        quic_settings.port = *ext_port as u32;
                    }
                    if let Some(ext_sni) = &ext_proxy.sni {
                        quic_settings.server_name = ext_sni.clone();
                    }
                    if let Some(ext_tls_cert) = &ext_proxy.tls_cert {
                        let cert = Path::new(ext_tls_cert);
                        if cert.is_absolute() {
                            quic_settings.certificate = cert.to_string_lossy().to_string();
                        } else {
                            let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                            let path = asset_loc.join(cert).to_string_lossy().to_string();
                            quic_settings.certificate = path;
                        }
                    }
                    let quic_settings = quic_settings.write_to_bytes().unwrap();
                    quic_outbound.settings = quic_settings;
                    quic_outbound.protocol = "quic".to_string();
                    quic_outbound.tag = format!("{}_quic_xxx", ext_proxy.tag.clone());

                    // plain trojan
                    let mut settings = internal::TrojanOutboundSettings::new();
                    if !ext_proxy.amux.unwrap() {
                        if let Some(ext_address) = &ext_proxy.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = &ext_proxy.port {
                            settings.port = *ext_port as u32;
                        }
                    }
                    if let Some(ext_password) = &ext_proxy.password {
                        settings.password = ext_password.clone();
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbound.tag = format!("{}_trojan_xxx", ext_proxy.tag.clone());

                    // chain
                    let mut chain_outbound = internal::Outbound::new();
                    chain_outbound.tag = ext_proxy.tag.clone();
                    let mut chain_settings = internal::ChainOutboundSettings::new();
                    if ext_proxy.amux.unwrap() {
                        chain_settings.actors.push(amux_outbound.tag.clone());
                    } else if ext_proxy.quic.unwrap() {
                        chain_settings.actors.push(quic_outbound.tag.clone());
                    } else {
                        chain_settings.actors.push(tls_outbound.tag.clone());
                        if ext_proxy.ws.unwrap() {
                            chain_settings.actors.push(ws_outbound.tag.clone());
                        }
                    }
                    chain_settings.actors.push(outbound.tag.clone());
                    let chain_settings = chain_settings.write_to_bytes().unwrap();
                    chain_outbound.settings = chain_settings;
                    chain_outbound.protocol = "chain".to_string();

                    // always push chain first, in case there isn't final rule,
                    // the chain outbound will be the default one to use
                    outbounds.push(chain_outbound);
                    if ext_proxy.amux.unwrap() {
                        outbounds.push(amux_outbound);
                    }
                    if ext_proxy.quic.unwrap() {
                        outbounds.push(quic_outbound);
                    } else {
                        outbounds.push(tls_outbound);
                    }
                    if ext_proxy.ws.unwrap() {
                        outbounds.push(ws_outbound);
                    }
                    outbounds.push(outbound);
                }
                "vmess" => {
                    // tls
                    let mut tls_outbound = internal::Outbound::new();
                    tls_outbound.protocol = "tls".to_string();
                    let mut tls_settings = internal::TlsOutboundSettings::new();
                    if let Some(ext_sni) = &ext_proxy.sni {
                        tls_settings.server_name = ext_sni.clone();
                    }
                    if let Some(ext_tls_cert) = &ext_proxy.tls_cert {
                        let cert = Path::new(ext_tls_cert);
                        if cert.is_absolute() {
                            tls_settings.certificate = cert.to_string_lossy().to_string();
                        } else {
                            let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                            let path = asset_loc.join(cert).to_string_lossy().to_string();
                            tls_settings.certificate = path;
                        }
                    }
                    tls_settings.insecure = ext_proxy.tls_insecure.unwrap_or_default();
                    let tls_settings = tls_settings.write_to_bytes().unwrap();
                    tls_outbound.settings = tls_settings;
                    tls_outbound.tag = format!("{}_tls_xxx", ext_proxy.tag.clone());

                    // ws
                    let mut ws_outbound = internal::Outbound::new();
                    ws_outbound.protocol = "ws".to_string();
                    let mut ws_settings = internal::WebSocketOutboundSettings::new();
                    if let Some(ext_ws_path) = &ext_proxy.ws_path {
                        ws_settings.path = ext_ws_path.clone();
                    } else {
                        ws_settings.path = "/".to_string();
                    }
                    if let Some(ext_ws_host) = &ext_proxy.ws_host {
                        let mut headers = HashMap::new();
                        headers.insert("Host".to_string(), ext_ws_host.clone());
                        ws_settings.headers = headers;
                    }
                    let ws_settings = ws_settings.write_to_bytes().unwrap();
                    ws_outbound.settings = ws_settings;
                    ws_outbound.tag = format!("{}_ws_xxx", ext_proxy.tag.clone());

                    // amux
                    let mut amux_outbound = internal::Outbound::new();
                    amux_outbound.tag = ext_proxy.tag.clone();
                    let mut amux_settings = internal::AMuxOutboundSettings::new();
                    // always enable tls for trojan
                    amux_settings.actors.push(tls_outbound.tag.clone());
                    if ext_proxy.ws.unwrap() {
                        amux_settings.actors.push(ws_outbound.tag.clone());
                    }
                    if let Some(ext_address) = &ext_proxy.address {
                        amux_settings.address = ext_address.clone();
                    }
                    if let Some(ext_port) = &ext_proxy.port {
                        amux_settings.port = *ext_port as u32;
                    }
                    if let Some(ext_max_accepts) = &ext_proxy.amux_max {
                        amux_settings.max_accepts = *ext_max_accepts as u32;
                    }
                    if let Some(ext_concurrency) = &ext_proxy.amux_con {
                        amux_settings.concurrency = *ext_concurrency as u32;
                    }
                    let amux_settings = amux_settings.write_to_bytes().unwrap();
                    amux_outbound.settings = amux_settings;
                    amux_outbound.protocol = "amux".to_string();
                    amux_outbound.tag = format!("{}_amux_xxx", ext_proxy.tag.clone());
                    // quic
                    let mut quic_outbound = internal::Outbound::new();
                    quic_outbound.tag = ext_proxy.tag.clone();
                    let mut quic_settings = internal::QuicOutboundSettings::new();
                    if let Some(ext_address) = &ext_proxy.address {
                        quic_settings.address = ext_address.clone();
                    }
                    if let Some(ext_port) = &ext_proxy.port {
                        quic_settings.port = *ext_port as u32;
                    }
                    if let Some(ext_sni) = &ext_proxy.sni {
                        quic_settings.server_name = ext_sni.clone();
                    }
                    if let Some(ext_tls_cert) = &ext_proxy.tls_cert {
                        let cert = Path::new(ext_tls_cert);
                        if cert.is_absolute() {
                            quic_settings.certificate = cert.to_string_lossy().to_string();
                        } else {
                            let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                            let path = asset_loc.join(cert).to_string_lossy().to_string();
                            quic_settings.certificate = path;
                        }
                    }
                    let quic_settings = quic_settings.write_to_bytes().unwrap();
                    quic_outbound.settings = quic_settings;
                    quic_outbound.protocol = "quic".to_string();
                    quic_outbound.tag = format!("{}_quic_xxx", ext_proxy.tag.clone());

                    // plain vmess
                    let mut settings = internal::VMessOutboundSettings::new();
                    if !ext_proxy.amux.unwrap() {
                        if let Some(ext_address) = &ext_proxy.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = &ext_proxy.port {
                            settings.port = *ext_port as u32;
                        }
                    }
                    if let Some(ext_username) = &ext_proxy.username {
                        settings.uuid = ext_username.clone();
                    }
                    if let Some(ext_encrypt_method) = &ext_proxy.encrypt_method {
                        settings.security = ext_encrypt_method.clone();
                    } else {
                        settings.security = "chacha20-ietf-poly1305".to_string();
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbound.tag = format!("{}_vmess_xxx", ext_proxy.tag.clone());

                    // chain
                    let mut chain_outbound = internal::Outbound::new();
                    chain_outbound.tag = ext_proxy.tag.clone();
                    let mut chain_settings = internal::ChainOutboundSettings::new();
                    if ext_proxy.amux.unwrap() {
                        chain_settings.actors.push(amux_outbound.tag.clone());
                    } else if ext_proxy.quic.unwrap() {
                        chain_settings.actors.push(quic_outbound.tag.clone());
                    } else {
                        if ext_proxy.tls.unwrap() {
                            chain_settings.actors.push(tls_outbound.tag.clone());
                        }
                        if ext_proxy.ws.unwrap() {
                            chain_settings.actors.push(ws_outbound.tag.clone());
                        }
                    }

                    if !chain_settings.actors.is_empty() {
                        chain_settings.actors.push(outbound.tag.clone());
                        let chain_settings = chain_settings.write_to_bytes().unwrap();
                        chain_outbound.settings = chain_settings;
                        chain_outbound.protocol = "chain".to_string();

                        // always push chain first, in case there isn't final rule,
                        // the chain outbound will be the default one to use
                        outbounds.push(chain_outbound);
                        if ext_proxy.amux.unwrap() {
                            outbounds.push(amux_outbound);
                        }
                        if ext_proxy.quic.unwrap() {
                            outbounds.push(quic_outbound);
                        } else if ext_proxy.tls.unwrap() {
                            outbounds.push(tls_outbound);
                        }
                        if ext_proxy.ws.unwrap() {
                            outbounds.push(ws_outbound);
                        }
                        outbounds.push(outbound);
                    } else {
                        outbound.tag = ext_proxy.tag.clone();
                        outbounds.push(outbound);
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(ext_proxy_groups) = &conf.proxy_group {
        for ext_proxy_group in ext_proxy_groups {
            let mut outbound = internal::Outbound::new();
            outbound.protocol = ext_proxy_group.protocol.clone();
            outbound.tag = ext_proxy_group.tag.clone();
            match outbound.protocol.as_str() {
                "chain" => {
                    let mut settings = internal::ChainOutboundSettings::new();
                    if let Some(ext_actors) = &ext_proxy_group.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor.to_string());
                        }
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "tryall" => {
                    let mut settings = internal::TryAllOutboundSettings::new();
                    if let Some(ext_actors) = &ext_proxy_group.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor.to_string());
                        }
                    }
                    if let Some(ext_delay_base) = ext_proxy_group.delay_base {
                        settings.delay_base = ext_delay_base as u32;
                    } else {
                        settings.delay_base = 0;
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "static" => {
                    let mut settings = internal::StaticOutboundSettings::new();
                    if let Some(ext_actors) = &ext_proxy_group.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor.to_string());
                        }
                    }
                    if let Some(ext_method) = &ext_proxy_group.method {
                        settings.method = ext_method.clone();
                    } else {
                        settings.method = "random".to_string();
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "failover" => {
                    let mut settings = internal::FailOverOutboundSettings::new();
                    if let Some(ext_actors) = &ext_proxy_group.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor.to_string());
                        }
                    }
                    if let Some(ext_fail_timeout) = ext_proxy_group.fail_timeout {
                        settings.fail_timeout = ext_fail_timeout as u32;
                    } else {
                        settings.fail_timeout = 4;
                    }
                    if let Some(ext_health_check) = ext_proxy_group.health_check {
                        settings.health_check = ext_health_check;
                    } else {
                        settings.health_check = true;
                    }
                    if let Some(ext_check_interval) = ext_proxy_group.check_interval {
                        settings.check_interval = ext_check_interval as u32;
                    } else {
                        settings.check_interval = 5 * 60; // 5mins
                    }
                    if let Some(ext_failover) = ext_proxy_group.failover {
                        settings.failover = ext_failover;
                    } else {
                        settings.failover = true;
                    }
                    if let Some(ext_fallback_cache) = ext_proxy_group.fallback_cache {
                        settings.fallback_cache = ext_fallback_cache;
                    } else {
                        settings.fallback_cache = false;
                    }
                    if let Some(ext_cache_size) = ext_proxy_group.cache_size {
                        settings.cache_size = ext_cache_size as u32;
                    } else {
                        settings.cache_size = 256;
                    }
                    if let Some(ext_cache_timeout) = ext_proxy_group.cache_timeout {
                        settings.cache_timeout = ext_cache_timeout as u32;
                    } else {
                        settings.cache_timeout = 60; // 60mins
                    }
                    if let Some(ext_last_resort) = &ext_proxy_group.last_resort {
                        settings.last_resort = ext_last_resort.clone();
                    } else {
                        settings.last_resort = "".to_string();
                    }
                    if let Some(ext_health_check_timeout) = ext_proxy_group.health_check_timeout {
                        settings.health_check_timeout = ext_health_check_timeout as u32;
                    } else {
                        settings.health_check_timeout = 4; // 4s
                    }
                    if let Some(ext_health_check_delay) = ext_proxy_group.health_check_delay {
                        settings.health_check_delay = ext_health_check_delay as u32;
                    } else {
                        settings.health_check_delay = 200; // 200ms
                    }
                    if let Some(ext_health_check_active) = ext_proxy_group.health_check_active {
                        settings.health_check_active = ext_health_check_active as u32;
                    } else {
                        settings.health_check_active = 15 * 60; // 15mins
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "select" => {
                    let mut settings = internal::SelectOutboundSettings::new();
                    if let Some(ext_actors) = &ext_proxy_group.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor.to_string());
                        }
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                _ => {}
            }
        }
    }

    let mut int_router = internal::Router::new();
    let mut rules = Vec::new();
    if let Some(ext_rules) = conf.rule.as_mut() {
        for ext_rule in ext_rules.iter_mut() {
            let mut rule = internal::router::Rule::new();

            let target_tag = std::mem::take(&mut ext_rule.target);
            rule.target_tag = target_tag;

            // handle FINAL rule first
            if ext_rule.type_field == "FINAL" {
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

            // the remaining rules must have a filter
            let ext_filter = if let Some(f) = ext_rule.filter.as_mut() {
                std::mem::take(f)
            } else {
                continue;
            };
            match ext_rule.type_field.as_str() {
                "IP-CIDR" => {
                    rule.ip_cidrs.push(ext_filter);
                }
                "DOMAIN" => {
                    let mut domain = internal::router::rule::Domain::new();
                    domain.type_ =
                        protobuf::EnumOrUnknown::new(internal::router::rule::domain::Type::FULL);
                    domain.value = ext_filter;
                    rule.domains.push(domain);
                }
                "DOMAIN-KEYWORD" => {
                    let mut domain = internal::router::rule::Domain::new();
                    domain.type_ =
                        protobuf::EnumOrUnknown::new(internal::router::rule::domain::Type::PLAIN);
                    domain.value = ext_filter;
                    rule.domains.push(domain);
                }
                "DOMAIN-SUFFIX" => {
                    let mut domain = internal::router::rule::Domain::new();
                    domain.type_ =
                        protobuf::EnumOrUnknown::new(internal::router::rule::domain::Type::DOMAIN);
                    domain.value = ext_filter;
                    rule.domains.push(domain);
                }
                "GEOIP" => {
                    let mut mmdb = internal::router::rule::Mmdb::new();

                    let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                    mmdb.file = asset_loc.join("geo.mmdb").to_string_lossy().to_string();
                    mmdb.country_code = ext_filter;
                    rule.mmdbs.push(mmdb)
                }
                "EXTERNAL" => match external_rule::add_external_rule(&mut rule, &ext_filter) {
                    Ok(_) => (),
                    Err(e) => {
                        println!("load external rule failed: {}", e);
                    }
                },
                "PORT-RANGE" => {
                    rule.port_ranges.push(ext_filter);
                }
                "NETWORK" => {
                    rule.networks.push(ext_filter);
                }
                "INBOUND-TAG" => {
                    rule.inbound_tags.push(ext_filter);
                }
                _ => {}
            }
            rules.push(rule);
        }
    }
    int_router.rules = rules;
    if let Some(ext_general) = &conf.general {
        if let Some(ext_domain_resolve) = ext_general.routing_domain_resolve {
            int_router.domain_resolve = ext_domain_resolve;
        }
    }
    let router = protobuf::MessageField::some(int_router);

    let mut dns = internal::Dns::new();
    let mut servers = Vec::new();
    let mut hosts = HashMap::new();
    if let Some(ext_general) = &conf.general {
        if let Some(ext_dns_servers) = &ext_general.dns_server {
            for ext_dns_server in ext_dns_servers {
                servers.push(ext_dns_server.clone());
            }
            if !servers.is_empty() {
                dns.servers = servers;
            }
        }
    }
    if dns.servers.is_empty() {
        dns.servers.push("1.1.1.1".to_string());
    }
    if let Some(ext_hosts) = &conf.host {
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

pub fn from_string(s: &str) -> Result<internal::Config> {
    let lines = s.lines().map(|s| Ok(s.to_string())).collect();
    let mut config = from_lines(lines)?;
    to_internal(&mut config)
}

pub fn from_file<P>(path: P) -> Result<internal::Config>
where
    P: AsRef<Path>,
{
    let lines = read_lines(path)?.collect();
    let mut config = from_lines(lines)?;
    to_internal(&mut config)
}
