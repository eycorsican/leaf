use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use anyhow::anyhow;
use anyhow::Result;
use protobuf::Message;
use regex::Regex;

use crate::config::{external_rule, geosite, internal};

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
    pub loglevel: Option<String>,
    pub dns_server: Option<Vec<String>>,
    pub dns_interface: Option<String>,
    pub always_real_ip: Option<Vec<String>>,
    pub always_fake_ip: Option<Vec<String>>,
    pub interface: Option<String>,
    pub port: Option<u16>,
    pub socks_interface: Option<String>,
    pub socks_port: Option<u16>,
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

    // vmess
    pub username: Option<String>,
    pub ws: Option<bool>,
    pub tls: Option<bool>,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,

    // trojan
    pub sni: Option<String>,

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
            interface: "0.0.0.0".to_string(),
            address: None,
            port: None,
            encrypt_method: Some("chacha20-ietf-poly1305".to_string()),
            password: None,
            username: None,
            ws: Some(false),
            tls: Some(false),
            ws_path: None,
            ws_host: None,
            sni: None,
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

    // tryall
    pub delay_base: Option<i32>,

    // retry
    pub attempts: Option<i32>,
}

impl Default for ProxyGroup {
    fn default() -> Self {
        ProxyGroup {
            tag: "".to_string(),
            protocol: "".to_string(),
            actors: None,
            health_check: Some(true),
            check_interval: Some(300),
            fail_timeout: Some(4),
            failover: Some(true),
            fallback_cache: Some(false),
            cache_size: Some(256),
            cache_timeout: Some(60),
            delay_base: Some(0),
            attempts: Some(2),
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

fn get_lines_by_section<'a, I>(section: &str, lines: I) -> Result<Vec<String>>
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
        if curr_sect.as_str() == section {
            if !line.is_empty() {
                new_lines.push(line.to_string());
            }
        }
    }
    Ok(new_lines)
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
    let mut general = General::default();
    let general_lines = get_lines_by_section("General", lines.iter()).unwrap();
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
                std::env::set_var("ROUTING_DOMAIN_RESOLVE", parts[1]);
            }
            "interface" => {
                general.interface = get_string(parts[1]);
            }
            "port" => {
                general.port = get_value::<u16>(parts[1]);
            }
            "socks-interface" => {
                general.socks_interface = get_string(parts[1]);
            }
            "socks-port" => {
                general.socks_port = get_value::<u16>(parts[1]);
            }
            _ => {}
        }
    }

    let mut proxies = Vec::new();
    let proxy_lines = get_lines_by_section("Proxy", lines.iter()).unwrap();
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
                "username" => {
                    proxy.username = Some(v.to_string());
                }
                "ws" => proxy.ws = if v == "true" { Some(true) } else { Some(false) },
                "tls" => proxy.tls = if v == "true" { Some(true) } else { Some(false) },
                "ws-path" => {
                    proxy.ws_path = Some(v.to_string());
                }
                "ws-host" => {
                    proxy.ws_host = Some(v.to_string());
                }
                "sni" => {
                    proxy.sni = Some(v.to_string());
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

        // built-in protocols have no address port, username, password
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
    let proxy_group_lines = get_lines_by_section("Proxy Group", lines.iter()).unwrap();
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
            if !param.contains('=') {
                if !param.is_empty() {
                    actors.push(param.to_string());
                }
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
                    "delay-base" => {
                        let i = if let Ok(i) = v.parse::<i32>() {
                            Some(i)
                        } else {
                            None
                        };
                        group.delay_base = i;
                    }
                    "attempts" => {
                        let i = if let Ok(i) = v.parse::<i32>() {
                            Some(i)
                        } else {
                            None
                        };
                        group.attempts = i;
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
    let rule_lines = get_lines_by_section("Rule", lines.iter()).unwrap();
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
            continue; // maybe break? to enforce FINAL as the final rule
        }

        if params.len() < 3 {
            continue; // at lease 3 params except the FINAL rule
        }

        // the 3th must be the target
        rule.target = params[2].to_string();

        match rule.type_field.as_str() {
            "IP-CIDR" | "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "GEOIP" | "EXTERNAL"
            | "PORT-RANGE" => {
                rule.filter = Some(params[1].to_string());
            }
            _ => {}
        }

        rules.push(rule);
    }

    let mut hosts = HashMap::new();
    let host_lines = get_lines_by_section("Host", lines.iter()).unwrap();
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

pub fn to_internal(conf: Config) -> Result<internal::Config> {
    let mut log = internal::Log::new();
    if let Some(ext_general) = &conf.general {
        if let Some(ext_loglevel) = &ext_general.loglevel {
            match ext_loglevel.as_str() {
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
    } else {
        log.level = internal::Log_Level::INFO;
    }
    log.output = internal::Log_Output::CONSOLE; // unimplemented

    let mut inbounds = protobuf::RepeatedField::new();
    if let Some(ext_general) = &conf.general {
        if ext_general.interface.is_some() && ext_general.port.is_some() {
            let mut inbound = internal::Inbound::new();
            inbound.protocol = "http".to_string();
            inbound.tag = "http".to_string();
            inbound.address = ext_general.interface.as_ref().unwrap().to_string();
            inbound.port = ext_general.port.unwrap() as u32;
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

        if ext_general.tun_fd.is_some() || ext_general.tun.is_some() {
            let mut inbound = internal::Inbound::new();
            inbound.protocol = "tun".to_string();
            inbound.tag = "tun".to_string();
            let mut settings = internal::TunInboundSettings::new();

            let mut fake_dns_exclude = protobuf::RepeatedField::new();
            if let Some(ext_always_real_ip) = &ext_general.always_real_ip {
                for item in ext_always_real_ip {
                    fake_dns_exclude.push(item.clone())
                }
                if fake_dns_exclude.len() > 0 {
                    settings.fake_dns_exclude = fake_dns_exclude;
                }
            }

            let mut fake_dns_include = protobuf::RepeatedField::new();
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

    let mut outbounds = protobuf::RepeatedField::new();
    if let Some(ext_proxies) = &conf.proxy {
        for ext_proxy in ext_proxies {
            let mut outbound = internal::Outbound::new();
            let ext_protocol = match ext_proxy.protocol.as_str() {
                "ss" => "shadowsocks",
                _ => &ext_proxy.protocol,
            };
            outbound.protocol = ext_protocol.to_string();
            outbound.tag = ext_proxy.tag.clone();
            outbound.bind = ext_proxy.interface.clone();
            match outbound.protocol.as_str() {
                "direct" | "drop" => {
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
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "trojan" => {
                    // tls
                    let mut tls_outbound = internal::Outbound::new();
                    tls_outbound.protocol = "tls".to_string();
                    tls_outbound.bind = ext_proxy.interface.clone();
                    let mut tls_settings = internal::TlsOutboundSettings::new();
                    if let Some(ext_sni) = &ext_proxy.sni {
                        tls_settings.server_name = ext_sni.clone();
                    }
                    let tls_settings = tls_settings.write_to_bytes().unwrap();
                    tls_outbound.settings = tls_settings;
                    tls_outbound.tag = format!("{}_tls_xxx", ext_proxy.tag.clone());

                    // ws
                    let mut ws_outbound = internal::Outbound::new();
                    ws_outbound.protocol = "ws".to_string();
                    ws_outbound.bind = ext_proxy.interface.clone();
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
                    amux_outbound.bind = ext_proxy.interface.clone();
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
                    let quic_settings = quic_settings.write_to_bytes().unwrap();
                    quic_outbound.settings = quic_settings;
                    quic_outbound.bind = ext_proxy.interface.clone();
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
                    chain_outbound.bind = ext_proxy.interface.clone();
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
                    tls_outbound.bind = ext_proxy.interface.clone();
                    let mut tls_settings = internal::TlsOutboundSettings::new();
                    if let Some(ext_sni) = &ext_proxy.sni {
                        tls_settings.server_name = ext_sni.clone();
                    }
                    let tls_settings = tls_settings.write_to_bytes().unwrap();
                    tls_outbound.settings = tls_settings;
                    tls_outbound.tag = format!("{}_tls_xxx", ext_proxy.tag.clone());

                    // ws
                    let mut ws_outbound = internal::Outbound::new();
                    ws_outbound.protocol = "ws".to_string();
                    ws_outbound.bind = ext_proxy.interface.clone();
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

                    // vmess
                    let mut settings = internal::VMessOutboundSettings::new();
                    if ext_proxy.address.is_none()
                        || ext_proxy.port.is_none()
                        || ext_proxy.username.is_none()
                    {
                        return Err(anyhow!("invalid vmess outbound settings"));
                    }
                    if let Some(ext_encrypt_method) = &ext_proxy.encrypt_method {
                        settings.security = ext_encrypt_method.clone();
                    } else {
                        settings.security = "chacha20-ietf-poly1305".to_string();
                    }
                    if let Some(ext_address) = &ext_proxy.address {
                        settings.address = ext_address.clone();
                    }
                    if let Some(ext_port) = &ext_proxy.port {
                        settings.port = *ext_port as u32;
                    }
                    if let Some(ext_username) = &ext_proxy.username {
                        settings.uuid = ext_username.clone();
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbound.tag = format!("{}_vmess_xxx", ext_proxy.tag.clone());

                    // chain
                    let mut chain_outbound = internal::Outbound::new();
                    chain_outbound.tag = ext_proxy.tag.clone();
                    let mut chain_settings = internal::ChainOutboundSettings::new();
                    if ext_proxy.tls.unwrap() {
                        chain_settings.actors.push(tls_outbound.tag.clone());
                    }
                    if ext_proxy.ws.unwrap() {
                        chain_settings.actors.push(ws_outbound.tag.clone());
                    }
                    chain_settings.actors.push(outbound.tag.clone());
                    let chain_settings = chain_settings.write_to_bytes().unwrap();
                    chain_outbound.settings = chain_settings;
                    chain_outbound.bind = ext_proxy.interface.clone();
                    chain_outbound.protocol = "chain".to_string();

                    // always push chain first, in case there isn't final rule,
                    // the chain outbound will be the default one to use
                    outbounds.push(chain_outbound);
                    if ext_proxy.tls.unwrap() {
                        outbounds.push(tls_outbound);
                    }
                    if ext_proxy.ws.unwrap() {
                        outbounds.push(ws_outbound);
                    }
                    outbounds.push(outbound);
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
            outbound.bind = "0.0.0.0".to_string();
            match outbound.protocol.as_str() {
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
                "random" => {
                    let mut settings = internal::RandomOutboundSettings::new();
                    if let Some(ext_actors) = &ext_proxy_group.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor.to_string());
                        }
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
                        settings.check_interval = 300;
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
                        settings.cache_timeout = 60; // in minutes
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                "retry" => {
                    let mut settings = internal::RetryOutboundSettings::new();
                    if let Some(ext_actors) = &ext_proxy_group.actors {
                        for ext_actor in ext_actors {
                            settings.actors.push(ext_actor.to_string());
                        }
                    }
                    if let Some(ext_attempts) = ext_proxy_group.attempts {
                        settings.attempts = ext_attempts as u32;
                    } else {
                        settings.attempts = 2;
                    }
                    let settings = settings.write_to_bytes().unwrap();
                    outbound.settings = settings;
                    outbounds.push(outbound);
                }
                _ => {}
            }
        }
    }

    let mut rules = protobuf::RepeatedField::new();
    if let Some(ext_rules) = &conf.rule {
        let mut site_group_lists = HashMap::<String, geosite::SiteGroupList>::new();
        for ext_rule in ext_rules {
            let mut rule = internal::RoutingRule::new();
            rule.target_tag = ext_rule.target.clone();

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
            let ext_filter = if let Some(f) = &ext_rule.filter {
                f.clone()
            } else {
                continue;
            };
            match ext_rule.type_field.as_str() {
                "IP-CIDR" => {
                    rule.ip_cidrs.push(ext_filter);
                }
                "DOMAIN" => {
                    let mut domain = internal::RoutingRule_Domain::new();
                    domain.field_type = internal::RoutingRule_Domain_Type::FULL;
                    domain.value = ext_filter;
                    rule.domains.push(domain);
                }
                "DOMAIN-KEYWORD" => {
                    let mut domain = internal::RoutingRule_Domain::new();
                    domain.field_type = internal::RoutingRule_Domain_Type::PLAIN;
                    domain.value = ext_filter;
                    rule.domains.push(domain);
                }
                "DOMAIN-SUFFIX" => {
                    let mut domain = internal::RoutingRule_Domain::new();
                    domain.field_type = internal::RoutingRule_Domain_Type::DOMAIN;
                    domain.value = ext_filter;
                    rule.domains.push(domain);
                }
                "GEOIP" => {
                    let mut mmdb = internal::RoutingRule_Mmdb::new();
                    let mut file = std::env::current_exe().unwrap();
                    file.pop();
                    file.push("geo.mmdb");
                    mmdb.file = file.to_str().unwrap().to_string();
                    mmdb.country_code = ext_filter;
                    rule.mmdbs.push(mmdb)
                }
                "EXTERNAL" => {
                    match external_rule::add_external_rule(
                        &mut rule,
                        &ext_filter,
                        &mut site_group_lists,
                    ) {
                        Ok(_) => (),
                        Err(e) => {
                            println!("load external rule failed: {}", e);
                        }
                    }
                }
                "PORT-RANGE" => {
                    rule.port_ranges.push(ext_filter);
                }
                _ => {}
            }
            rules.push(rule);
        }
        drop(site_group_lists); // make sure it's released
    }

    let mut dns = internal::Dns::new();
    let mut servers = protobuf::RepeatedField::new();
    let mut hosts = HashMap::new();
    if let Some(ext_general) = &conf.general {
        if let Some(ext_dns_interface) = &ext_general.dns_interface {
            dns.bind = ext_dns_interface.clone();
        } else {
            dns.bind = "0.0.0.0".to_string();
        }
        if let Some(ext_dns_servers) = &ext_general.dns_server {
            for ext_dns_server in ext_dns_servers {
                servers.push(ext_dns_server.clone());
            }
            if servers.len() == 0 {
                servers.push("114.114.114.114".to_string());
                servers.push("8.8.8.8".to_string());
            }
            dns.servers = servers;
        }
    }
    if let Some(ext_hosts) = &conf.host {
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
    if !hosts.is_empty() {
        dns.hosts = hosts;
    }

    let mut config = internal::Config::new();
    config.log = protobuf::SingularPtrField::some(log);
    config.inbounds = inbounds;
    config.outbounds = outbounds;
    config.routing_rules = rules;
    config.dns = protobuf::SingularPtrField::some(dns);

    drop(conf); // make sure no partial moved fields

    Ok(config)
}

pub fn from_file<P>(path: P) -> Result<internal::Config>
where
    P: AsRef<Path>,
{
    let lines = read_lines(path)?.collect();
    let config = from_lines(lines)?;
    to_internal(config)
}
