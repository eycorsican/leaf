use std::{
    collections::HashMap,
    convert::From,
    net::{IpAddr, SocketAddr, SocketAddrV4},
    str::FromStr,
    sync::Arc,
};

use log::*;

#[cfg(feature = "chain")]
use crate::proxy::chain;
#[cfg(feature = "failover")]
use crate::proxy::failover;
#[cfg(feature = "random")]
use crate::proxy::random;
#[cfg(feature = "tryall")]
use crate::proxy::tryall;

#[cfg(feature = "direct")]
use crate::proxy::direct;
#[cfg(feature = "drop")]
use crate::proxy::drop;
#[cfg(feature = "redirect")]
use crate::proxy::redirect;
#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks;
#[cfg(feature = "socks")]
use crate::proxy::socks;
#[cfg(feature = "tls")]
use crate::proxy::tls;
#[cfg(feature = "trojan")]
use crate::proxy::trojan;
#[cfg(feature = "vless")]
use crate::proxy::vless;
#[cfg(feature = "vmess")]
use crate::proxy::vmess;
#[cfg(feature = "ws")]
use crate::proxy::ws;

use crate::{
    common::dns_client::DnsClient,
    config::{self, Outbound, DNS},
    proxy::{self, ProxyHandler, ProxyHandlerType},
};

pub struct HandlerManager {
    handlers: HashMap<String, Arc<dyn ProxyHandler>>,
    default_handler: Option<String>,
}

impl HandlerManager {
    pub fn new(outbounds: &protobuf::RepeatedField<Outbound>, dns: &DNS) -> Self {
        let mut handlers: HashMap<String, Arc<dyn ProxyHandler>> = HashMap::new();
        let mut default_handler: Option<String> = None;
        let mut dns_servers = Vec::new();
        for dns_server in dns.servers.iter() {
            if let Ok(ip) = dns_server.parse::<IpAddr>() {
                dns_servers.push(SocketAddr::new(ip, 53));
            }
        }
        if dns_servers.is_empty() {
            panic!("no dns servers");
        }
        let bind_addr = {
            let addr = format!("{}:0", dns.bind);
            let addr = match SocketAddrV4::from_str(&addr) {
                Ok(a) => a,
                Err(e) => {
                    error!("invalid bind addr [{}] in dns: {}", &dns.bind, e);
                    panic!("");
                }
            };
            SocketAddr::from(addr)
        };
        let dns_client = Arc::new(DnsClient::new(dns_servers, bind_addr));
        for outbound in outbounds.iter() {
            let tag = String::from(&outbound.tag);
            if default_handler.is_none() {
                default_handler = Some(String::from(&outbound.tag));
                debug!("default handler [{}]", &outbound.tag);
            }
            match outbound.protocol.as_str() {
                #[cfg(feature = "direct")]
                "direct" => {
                    let tcp = Box::new(direct::TcpHandler::new(bind_addr, dns_client.clone()));
                    let udp = Box::new(direct::UdpHandler::new(bind_addr));
                    let handler = proxy::Handler::new(
                        tag.clone(),
                        colored::Color::Green,
                        ProxyHandlerType::Direct,
                        tcp,
                        udp,
                    );
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "drop")]
                "drop" => {
                    let tcp = Box::new(drop::TcpHandler {});
                    let udp = Box::new(drop::UdpHandler {});
                    let handler = proxy::Handler::new(
                        tag.clone(),
                        colored::Color::Red,
                        ProxyHandlerType::Endpoint,
                        tcp,
                        udp,
                    );
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "redirect")]
                "redirect" => {
                    let settings = match protobuf::parse_from_bytes::<
                        config::RedirectOutboundSettings,
                    >(&outbound.settings)
                    {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("invalid [{}] outbound settings: {}", &tag, e);
                            continue;
                        }
                    };
                    let tcp = Box::new(redirect::TcpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                    });
                    let udp = Box::new(redirect::UdpHandler {
                        address: settings.address,
                        port: settings.port as u16,
                    });
                    let handler = proxy::Handler::new(
                        tag.clone(),
                        colored::Color::BrightYellow,
                        ProxyHandlerType::Endpoint,
                        tcp,
                        udp,
                    );
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "socks")]
                "socks" => {
                    let settings = match protobuf::parse_from_bytes::<config::SocksOutboundSettings>(
                        &outbound.settings,
                    ) {
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
                    let handler = proxy::Handler::new(
                        tag.clone(),
                        colored::Color::TrueColor {
                            r: 252,
                            g: 107,
                            b: 3,
                        },
                        ProxyHandlerType::Endpoint,
                        tcp,
                        udp,
                    );
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "shadowsocks")]
                "shadowsocks" => {
                    let settings = match protobuf::parse_from_bytes::<
                        config::ShadowsocksOutboundSettings,
                    >(&outbound.settings)
                    {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("invalid [{}] outbound settings: {}", &tag, e);
                            continue;
                        }
                    };
                    let tcp = Box::new(shadowsocks::TcpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        cipher: settings.method.clone(),
                        password: settings.password.clone(),
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let udp = Box::new(shadowsocks::UdpHandler {
                        address: settings.address,
                        port: settings.port as u16,
                        cipher: settings.method,
                        password: settings.password,
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let handler = proxy::Handler::new(
                        tag.clone(),
                        colored::Color::Blue,
                        ProxyHandlerType::Endpoint,
                        tcp,
                        udp,
                    );
                    handlers.insert(tag, handler);
                }
                #[cfg(feature = "trojan")]
                "trojan" => {
                    let settings = match protobuf::parse_from_bytes::<config::TrojanOutboundSettings>(
                        &outbound.settings,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("invalid [{}] outbound settings: {}", &tag, e);
                            continue;
                        }
                    };
                    let tcp = Box::new(trojan::TcpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        password: settings.password.clone(),
                        // domain: settings.domain.clone(),
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let udp = Box::new(trojan::UdpHandler {
                        address: settings.address,
                        port: settings.port as u16,
                        password: settings.password,
                        // domain: settings.domain,
                        bind_addr,
                        dns_client: dns_client.clone(),
                    });
                    let handler = proxy::Handler::new(
                        tag.clone(),
                        colored::Color::Cyan,
                        ProxyHandlerType::Endpoint,
                        tcp,
                        udp,
                    );
                    handlers.insert(tag, handler);
                }
                #[cfg(feature = "vmess")]
                "vmess" => {
                    let settings = match protobuf::parse_from_bytes::<config::VMessOutboundSettings>(
                        &outbound.settings,
                    ) {
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
                    let handler = proxy::Handler::new(
                        tag.clone(),
                        colored::Color::Magenta,
                        ProxyHandlerType::Endpoint,
                        tcp,
                        udp,
                    );
                    handlers.insert(tag, handler);
                    drop(settings); // TODO do this for all others
                }
                #[cfg(feature = "vless")]
                "vless" => {
                    let settings = match protobuf::parse_from_bytes::<config::VLessOutboundSettings>(
                        &outbound.settings,
                    ) {
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
                    let handler = proxy::Handler::new(
                        tag.clone(),
                        colored::Color::Magenta,
                        ProxyHandlerType::Endpoint,
                        tcp,
                        udp,
                    );
                    handlers.insert(tag, handler);
                    drop(settings); // TODO do this for all others
                }
                #[cfg(feature = "tls")]
                "tls" => {
                    let settings = match protobuf::parse_from_bytes::<config::TlsOutboundSettings>(
                        &outbound.settings,
                    ) {
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
                    let udp = Box::new(tls::UdpHandler {
                        server_name: settings.server_name.clone(),
                        alpns: alpns.clone(),
                    });
                    let handler = proxy::Handler::new(
                        tag.clone(),
                        colored::Color::TrueColor {
                            r: 252,
                            g: 107,
                            b: 3,
                        },
                        ProxyHandlerType::Endpoint,
                        tcp,
                        udp,
                    );
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "ws")]
                "ws" => {
                    let settings = match protobuf::parse_from_bytes::<
                        config::WebSocketOutboundSettings,
                    >(&outbound.settings)
                    {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("invalid [{}] outbound settings: {}", &tag, e);
                            continue;
                        }
                    };
                    let tcp = Box::new(ws::TcpHandler {
                        path: settings.path.clone(),
                    });
                    let udp = Box::new(ws::UdpHandler {
                        path: settings.path.clone(),
                    });
                    let handler = proxy::Handler::new(
                        tag.clone(),
                        colored::Color::TrueColor {
                            r: 252,
                            g: 107,
                            b: 3,
                        },
                        ProxyHandlerType::Endpoint,
                        tcp,
                        udp,
                    );
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "feature-h2")]
                "h2" => {
                    let settings = match protobuf::parse_from_bytes::<config::HTTP2OutboundSettings>(
                        &outbound.settings,
                    ) {
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
                    let udp = Box::new(crate::proxy::h2::UdpHandler {
                        path: settings.path.clone(),
                        host: settings.host.clone(),
                    });
                    let handler = proxy::Handler::new(
                        tag.clone(),
                        colored::Color::TrueColor {
                            r: 252,
                            g: 107,
                            b: 3,
                        },
                        ProxyHandlerType::Endpoint,
                        tcp,
                        udp,
                    );
                    handlers.insert(tag.clone(), handler);
                }
                "tryall" | "failover" | "random" | "chain" => (),
                _ => {
                    warn!("unknown outbound protocol {:?}", outbound.protocol);
                }
            }
        }

        // FIXME a better way to find outbound deps?
        for _i in 0..4 {
            for outbound in outbounds.iter() {
                let tag = String::from(&outbound.tag);
                match outbound.protocol.as_str() {
                    #[cfg(feature = "tryall")]
                    "tryall" => {
                        let settings = match protobuf::parse_from_bytes::<
                            config::TryAllOutboundSettings,
                        >(&outbound.settings)
                        {
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
                        let handler = proxy::Handler::new(
                            tag.clone(),
                            colored::Color::TrueColor {
                                r: 182,
                                g: 235,
                                b: 250,
                            },
                            ProxyHandlerType::Ensemble,
                            tcp,
                            udp,
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    #[cfg(feature = "random")]
                    "random" => {
                        let settings = match protobuf::parse_from_bytes::<
                            config::RandomOutboundSettings,
                        >(&outbound.settings)
                        {
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
                        let handler = proxy::Handler::new(
                            tag.clone(),
                            colored::Color::TrueColor {
                                r: 182,
                                g: 235,
                                b: 250,
                            },
                            ProxyHandlerType::Ensemble,
                            tcp,
                            udp,
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    #[cfg(feature = "failover")]
                    "failover" => {
                        let settings = match protobuf::parse_from_bytes::<
                            config::FailOverOutboundSettings,
                        >(&outbound.settings)
                        {
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
                        ));
                        let udp = Box::new(failover::UdpHandler::new(
                            actors,
                            settings.fail_timeout,
                            settings.health_check,
                            settings.check_interval,
                            settings.failover,
                        ));
                        let handler = proxy::Handler::new(
                            tag.clone(),
                            colored::Color::TrueColor {
                                r: 182,
                                g: 235,
                                b: 250,
                            },
                            ProxyHandlerType::Ensemble,
                            tcp,
                            udp,
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    #[cfg(feature = "chain")]
                    "chain" => {
                        let settings = match protobuf::parse_from_bytes::<
                            config::ChainOutboundSettings,
                        >(&outbound.settings)
                        {
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
                        let tcp = Box::new(chain::TcpHandler {
                            actors: actors.clone(),
                            dns_client: dns_client.clone(),
                        });
                        let udp = Box::new(chain::UdpHandler {
                            actors: actors.clone(),
                            dns_client: dns_client.clone(),
                        });
                        let handler = proxy::Handler::new(
                            tag.clone(),
                            colored::Color::TrueColor {
                                r: 226,
                                g: 103,
                                b: 245,
                            },
                            ProxyHandlerType::Ensemble,
                            tcp,
                            udp,
                        );
                        handlers.insert(tag.clone(), handler);
                    }
                    "direct" | "drop" | "redirect" | "socks" | "shadowsocks" | "trojan"
                    | "vmess" | "vless" | "tls" | "ws" | "h2" => (),
                    _ => {
                        warn!("unknown outbound protocol {:?}", outbound.protocol);
                    }
                }
            }
        }

        HandlerManager {
            handlers,
            default_handler,
        }
    }

    pub fn add(&mut self, tag: String, handler: Arc<dyn ProxyHandler>) {
        self.handlers.insert(tag, handler);
    }

    pub fn get(&self, tag: &str) -> Option<&Arc<dyn ProxyHandler>> {
        self.handlers.get(tag)
    }

    pub fn default_handler(&self) -> Option<&String> {
        self.default_handler.as_ref()
    }
}
