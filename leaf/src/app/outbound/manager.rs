use std::{
    collections::{hash_map, HashMap},
    convert::From,
    net::{IpAddr, SocketAddr, SocketAddrV4},
    str::FromStr,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use log::*;
use protobuf::Message;

#[cfg(feature = "outbound-chain")]
use crate::proxy::chain;
#[cfg(feature = "outbound-failover")]
use crate::proxy::failover;
#[cfg(feature = "outbound-random")]
use crate::proxy::random;
#[cfg(feature = "outbound-retry")]
use crate::proxy::retry;
#[cfg(feature = "outbound-tryall")]
use crate::proxy::tryall;

#[cfg(feature = "outbound-stat")]
use crate::proxy::stat;

#[cfg(feature = "outbound-amux")]
use crate::proxy::amux;
#[cfg(feature = "outbound-direct")]
use crate::proxy::direct;
#[cfg(feature = "outbound-drop")]
use crate::proxy::drop;
#[cfg(feature = "outbound-redirect")]
use crate::proxy::redirect;
#[cfg(feature = "outbound-shadowsocks")]
use crate::proxy::shadowsocks;
#[cfg(feature = "outbound-socks")]
use crate::proxy::socks;
#[cfg(feature = "outbound-tls")]
use crate::proxy::tls;
#[cfg(feature = "outbound-trojan")]
use crate::proxy::trojan;
#[cfg(feature = "outbound-vless")]
use crate::proxy::vless;
#[cfg(feature = "outbound-vmess")]
use crate::proxy::vmess;
#[cfg(feature = "outbound-ws")]
use crate::proxy::ws;

use crate::{
    app::dns_client::DnsClient,
    config::{self, Dns, Outbound},
    proxy::{self, OutboundHandler, ProxyHandlerType},
};

pub struct OutboundManager {
    handlers: HashMap<String, Arc<dyn OutboundHandler>>,
    default_handler: Option<String>,
}

impl OutboundManager {
    pub fn new(outbounds: &protobuf::RepeatedField<Outbound>, dns: &Dns) -> Result<Self> {
        let mut handlers: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
        let mut default_handler: Option<String> = None;
        let mut dns_servers = Vec::new();
        let mut dns_hosts = HashMap::new();
        for dns_server in dns.servers.iter() {
            if let Ok(ip) = dns_server.parse::<IpAddr>() {
                dns_servers.push(SocketAddr::new(ip, 53));
            }
        }
        for (name, ips) in dns.hosts.iter() {
            dns_hosts.insert(name.to_owned(), ips.values.to_vec());
        }
        if dns_servers.is_empty() {
            Err(anyhow!("no dns servers"))?;
        }
        let dns_bind_addr = {
            let addr = format!("{}:0", &dns.bind);
            let addr = SocketAddrV4::from_str(&addr)
                .map_err(|e| anyhow!("invalid bind addr [{}] in dns: {}", &dns.bind, e))?;
            SocketAddr::from(addr)
        };
        let dns_client = Arc::new(DnsClient::new(dns_servers, dns_hosts, dns_bind_addr));

        for outbound in outbounds.iter() {
            let tag = String::from(&outbound.tag);
            if default_handler.is_none() {
                default_handler = Some(String::from(&outbound.tag));
                debug!("default handler [{}]", &outbound.tag);
            }
            let bind_addr = {
                let addr = format!("{}:0", &outbound.bind);
                let addr = SocketAddrV4::from_str(&addr).map_err(|e| {
                    anyhow!(
                        "invalid bind addr [{}] in outbound {}: {}",
                        &outbound.bind,
                        &outbound.tag,
                        e
                    )
                })?;
                SocketAddr::from(addr)
            };
            match outbound.protocol.as_str() {
                #[cfg(feature = "outbound-direct")]
                "direct" => {
                    let tcp = Box::new(direct::TcpHandler::new(bind_addr, dns_client.clone()));
                    let udp = Box::new(direct::UdpHandler::new(bind_addr, dns_client.clone()));
                    let handler = proxy::outbound::Handler::new(
                        tag.clone(),
                        colored::Color::Green,
                        ProxyHandlerType::Direct,
                        Some(tcp),
                        Some(udp),
                    );
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "outbound-drop")]
                "drop" => {
                    let tcp = Box::new(drop::TcpHandler {});
                    let udp = Box::new(drop::UdpHandler {});
                    let handler = proxy::outbound::Handler::new(
                        tag.clone(),
                        colored::Color::Red,
                        ProxyHandlerType::Endpoint,
                        Some(tcp),
                        Some(udp),
                    );
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "outbound-redirect")]
                "redirect" => {
                    let settings = match config::RedirectOutboundSettings::parse_from_bytes(
                        &outbound.settings,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("invalid [{}] outbound settings: {}", &tag, e);
                            continue;
                        }
                    };
                    let tcp = Box::new(redirect::TcpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let udp = Box::new(redirect::UdpHandler {
                        address: settings.address,
                        port: settings.port as u16,
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let handler = proxy::outbound::Handler::new(
                        tag.clone(),
                        colored::Color::BrightYellow,
                        ProxyHandlerType::Endpoint,
                        Some(tcp),
                        Some(udp),
                    );
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "outbound-socks")]
                "socks" => {
                    let settings =
                        match config::SocksOutboundSettings::parse_from_bytes(&outbound.settings) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                    let tcp = Box::new(socks::outbound::TcpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let udp = Box::new(socks::outbound::UdpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let handler = proxy::outbound::Handler::new(
                        tag.clone(),
                        colored::Color::TrueColor {
                            r: 252,
                            g: 107,
                            b: 3,
                        },
                        ProxyHandlerType::Endpoint,
                        Some(tcp),
                        Some(udp),
                    );
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "outbound-shadowsocks")]
                "shadowsocks" => {
                    let settings = match config::ShadowsocksOutboundSettings::parse_from_bytes(
                        &outbound.settings,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("invalid [{}] outbound settings: {}", &tag, e);
                            continue;
                        }
                    };
                    let tcp = Box::new(shadowsocks::outbound::TcpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        cipher: settings.method.clone(),
                        password: settings.password.clone(),
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let udp = Box::new(shadowsocks::outbound::UdpHandler {
                        address: settings.address,
                        port: settings.port as u16,
                        cipher: settings.method,
                        password: settings.password,
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let handler = proxy::outbound::Handler::new(
                        tag.clone(),
                        colored::Color::Blue,
                        ProxyHandlerType::Endpoint,
                        Some(tcp),
                        Some(udp),
                    );
                    handlers.insert(tag, handler);
                }
                #[cfg(feature = "outbound-trojan")]
                "trojan" => {
                    let settings = match config::TrojanOutboundSettings::parse_from_bytes(
                        &outbound.settings,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("invalid [{}] outbound settings: {}", &tag, e);
                            continue;
                        }
                    };
                    let tcp = Box::new(trojan::outbound::TcpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        password: settings.password.clone(),
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let udp = Box::new(trojan::outbound::UdpHandler {
                        address: settings.address,
                        port: settings.port as u16,
                        password: settings.password,
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let handler = proxy::outbound::Handler::new(
                        tag.clone(),
                        colored::Color::Cyan,
                        ProxyHandlerType::Endpoint,
                        Some(tcp),
                        Some(udp),
                    );
                    handlers.insert(tag, handler);
                }
                #[cfg(feature = "outbound-vmess")]
                "vmess" => {
                    let settings =
                        match config::VMessOutboundSettings::parse_from_bytes(&outbound.settings) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };

                    let tcp = Box::new(vmess::TcpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        uuid: settings.uuid.clone(),
                        security: settings.security.clone(),
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let udp = Box::new(vmess::UdpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        uuid: settings.uuid.clone(),
                        security: settings.security.clone(),
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let handler = proxy::outbound::Handler::new(
                        tag.clone(),
                        colored::Color::Magenta,
                        ProxyHandlerType::Endpoint,
                        Some(tcp),
                        Some(udp),
                    );
                    handlers.insert(tag, handler);
                }
                #[cfg(feature = "outbound-vless")]
                "vless" => {
                    let settings =
                        match config::VLessOutboundSettings::parse_from_bytes(&outbound.settings) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };

                    let tcp = Box::new(vless::TcpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        uuid: settings.uuid.clone(),
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let udp = Box::new(vless::UdpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        uuid: settings.uuid.clone(),
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let handler = proxy::outbound::Handler::new(
                        tag.clone(),
                        colored::Color::Magenta,
                        ProxyHandlerType::Endpoint,
                        Some(tcp),
                        Some(udp),
                    );
                    handlers.insert(tag, handler);
                }
                #[cfg(feature = "outbound-tls")]
                "tls" => {
                    let settings =
                        match config::TlsOutboundSettings::parse_from_bytes(&outbound.settings) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                    let mut alpns = Vec::new();
                    for alpn in settings.alpn.iter() {
                        alpns.push(alpn.clone());
                    }
                    let tcp = Box::new(tls::TcpHandler {
                        server_name: settings.server_name.clone(),
                        alpns: alpns.clone(),
                    });
                    let handler = proxy::outbound::Handler::new(
                        tag.clone(),
                        colored::Color::TrueColor {
                            r: 252,
                            g: 107,
                            b: 3,
                        },
                        ProxyHandlerType::Endpoint,
                        Some(tcp),
                        None,
                    );
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "outbound-ws")]
                "ws" => {
                    let settings = match config::WebSocketOutboundSettings::parse_from_bytes(
                        &outbound.settings,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("invalid [{}] outbound settings: {}", &tag, e);
                            continue;
                        }
                    };
                    let tcp = Box::new(ws::outbound::TcpHandler {
                        path: settings.path.clone(),
                        headers: settings.headers.clone(),
                        dns_client: dns_client.clone(),
                    });
                    let handler = proxy::outbound::Handler::new(
                        tag.clone(),
                        colored::Color::TrueColor {
                            r: 252,
                            g: 107,
                            b: 3,
                        },
                        ProxyHandlerType::Endpoint,
                        Some(tcp),
                        None,
                    );
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "outbound-h2")]
                "h2" => {
                    let settings =
                        match config::HTTP2OutboundSettings::parse_from_bytes(&outbound.settings) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                    let tcp = Box::new(crate::proxy::h2::TcpHandler {
                        path: settings.path.clone(),
                        host: settings.host.clone(),
                    });
                    let handler = proxy::outbound::Handler::new(
                        tag.clone(),
                        colored::Color::TrueColor {
                            r: 252,
                            g: 107,
                            b: 3,
                        },
                        ProxyHandlerType::Endpoint,
                        Some(tcp),
                        None,
                    );
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "outbound-stat")]
                "stat" => {
                    let settings =
                        match config::StatOutboundSettings::parse_from_bytes(&outbound.settings) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                    let tcp = Box::new(stat::TcpHandler::new(
                        settings.address,
                        settings.port as u16,
                    ));
                    let udp = Box::new(stat::UdpHandler::new());
                    let handler = proxy::outbound::Handler::new(
                        tag.clone(),
                        colored::Color::Red,
                        ProxyHandlerType::Endpoint,
                        Some(tcp),
                        Some(udp),
                    );
                    handlers.insert(tag.clone(), handler);
                }
                _ => (),
            }
        }

        // FIXME a better way to find outbound deps?
        for _i in 0..4 {
            for outbound in outbounds.iter() {
                let tag = String::from(&outbound.tag);
                let bind_addr = {
                    let addr = format!("{}:0", &outbound.bind);
                    let addr = SocketAddrV4::from_str(&addr).map_err(|e| {
                        anyhow!(
                            "invalid bind addr [{}] in outbound {}: {}",
                            &outbound.bind,
                            &outbound.tag,
                            e
                        )
                    })?;
                    SocketAddr::from(addr)
                };
                match outbound.protocol.as_str() {
                    #[cfg(feature = "outbound-tryall")]
                    "tryall" => {
                        let settings = match config::TryAllOutboundSettings::parse_from_bytes(
                            &outbound.settings,
                        ) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let tcp = Box::new(tryall::TcpHandler {
                            actors: actors.clone(),
                            delay_base: settings.delay_base,
                        });
                        let udp = Box::new(tryall::UdpHandler {
                            actors,
                            delay_base: settings.delay_base,
                        });
                        let handler = proxy::outbound::Handler::new(
                            tag.clone(),
                            colored::Color::TrueColor {
                                r: 182,
                                g: 235,
                                b: 250,
                            },
                            ProxyHandlerType::Ensemble,
                            Some(tcp),
                            Some(udp),
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    #[cfg(feature = "outbound-random")]
                    "random" => {
                        let settings = match config::RandomOutboundSettings::parse_from_bytes(
                            &outbound.settings,
                        ) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let tcp = Box::new(random::TcpHandler {
                            actors: actors.clone(),
                        });
                        let udp = Box::new(random::UdpHandler { actors });
                        let handler = proxy::outbound::Handler::new(
                            tag.clone(),
                            colored::Color::TrueColor {
                                r: 182,
                                g: 235,
                                b: 250,
                            },
                            ProxyHandlerType::Ensemble,
                            Some(tcp),
                            Some(udp),
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    #[cfg(feature = "outbound-failover")]
                    "failover" => {
                        let settings = match config::FailOverOutboundSettings::parse_from_bytes(
                            &outbound.settings,
                        ) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let tcp = Box::new(failover::TcpHandler::new(
                            actors.clone(),
                            settings.fail_timeout,
                            settings.health_check,
                            settings.check_interval,
                            settings.failover,
                            settings.fallback_cache,
                            settings.cache_size as usize,
                            settings.cache_timeout as u64,
                        ));
                        let udp = Box::new(failover::UdpHandler::new(
                            actors,
                            settings.fail_timeout,
                            settings.health_check,
                            settings.check_interval,
                            settings.failover,
                        ));
                        let handler = proxy::outbound::Handler::new(
                            tag.clone(),
                            colored::Color::TrueColor {
                                r: 182,
                                g: 235,
                                b: 250,
                            },
                            ProxyHandlerType::Ensemble,
                            Some(tcp),
                            Some(udp),
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    #[cfg(feature = "outbound-amux")]
                    "amux" => {
                        let settings = match config::AMuxOutboundSettings::parse_from_bytes(
                            &outbound.settings,
                        ) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        let tcp = Box::new(amux::outbound::TcpHandler::new(
                            settings.address.clone(),
                            settings.port as u16,
                            actors.clone(),
                            settings.max_accepts as usize,
                            settings.concurrency as usize,
                            bind_addr,
                            dns_client.clone(),
                        ));
                        let handler = proxy::outbound::Handler::new(
                            tag.clone(),
                            colored::Color::TrueColor {
                                r: 226,
                                g: 103,
                                b: 245,
                            },
                            ProxyHandlerType::Ensemble,
                            Some(tcp),
                            None,
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    #[cfg(feature = "outbound-chain")]
                    "chain" => {
                        let settings = match config::ChainOutboundSettings::parse_from_bytes(
                            &outbound.settings,
                        ) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let tcp = Box::new(chain::outbound::TcpHandler {
                            actors: actors.clone(),
                            dns_client: dns_client.clone(),
                        });
                        let udp = Box::new(chain::outbound::UdpHandler {
                            actors: actors.clone(),
                            dns_client: dns_client.clone(),
                        });
                        let handler = proxy::outbound::Handler::new(
                            tag.clone(),
                            colored::Color::Blue,
                            ProxyHandlerType::Ensemble,
                            Some(tcp),
                            Some(udp),
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    #[cfg(feature = "outbound-retry")]
                    "retry" => {
                        let settings = match config::RetryOutboundSettings::parse_from_bytes(
                            &outbound.settings,
                        ) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("invalid [{}] outbound settings: {}", &tag, e);
                                continue;
                            }
                        };
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let tcp = Box::new(retry::TcpHandler {
                            actors: actors.clone(),
                            attempts: settings.attempts as usize,
                        });
                        let udp = Box::new(retry::UdpHandler {
                            actors,
                            attempts: settings.attempts as usize,
                        });
                        let handler = proxy::outbound::Handler::new(
                            tag.clone(),
                            colored::Color::TrueColor {
                                r: 182,
                                g: 235,
                                b: 250,
                            },
                            ProxyHandlerType::Ensemble,
                            Some(tcp),
                            Some(udp),
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    _ => (),
                }
            }
        }

        Ok(OutboundManager {
            handlers,
            default_handler,
        })
    }

    pub fn add(&mut self, tag: String, handler: Arc<dyn OutboundHandler>) {
        self.handlers.insert(tag, handler);
    }

    pub fn get(&self, tag: &str) -> Option<&Arc<dyn OutboundHandler>> {
        self.handlers.get(tag)
    }

    pub fn default_handler(&self) -> Option<&String> {
        self.default_handler.as_ref()
    }

    pub fn handlers(&self) -> Handlers {
        Handlers {
            inner: self.handlers.values(),
        }
    }
}

pub struct Handlers<'a> {
    inner: hash_map::Values<'a, String, Arc<dyn OutboundHandler>>,
}

impl<'a> Iterator for Handlers<'a> {
    type Item = &'a Arc<dyn OutboundHandler>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}
