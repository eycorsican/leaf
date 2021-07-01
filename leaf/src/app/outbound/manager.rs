use std::{
    collections::{hash_map, HashMap},
    convert::From,
    sync::atomic::AtomicUsize,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use futures::future::AbortHandle;
use log::*;
use protobuf::Message;
use tokio::sync::RwLock;

use crate::proxy::null;

#[cfg(feature = "outbound-chain")]
use crate::proxy::chain;
#[cfg(feature = "outbound-failover")]
use crate::proxy::failover;
#[cfg(feature = "outbound-random")]
use crate::proxy::random;
#[cfg(feature = "outbound-retry")]
use crate::proxy::retry;
#[cfg(feature = "outbound-rr")]
use crate::proxy::rr;
#[cfg(feature = "outbound-select")]
use crate::proxy::select;
#[cfg(feature = "outbound-tryall")]
use crate::proxy::tryall;

#[cfg(feature = "outbound-amux")]
use crate::proxy::amux;
#[cfg(feature = "outbound-direct")]
use crate::proxy::direct;
#[cfg(feature = "outbound-drop")]
use crate::proxy::drop;
#[cfg(feature = "outbound-quic")]
use crate::proxy::quic;
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
#[cfg(feature = "outbound-vmess")]
use crate::proxy::vmess;
#[cfg(feature = "outbound-ws")]
use crate::proxy::ws;

use crate::{
    app::dns_client::DnsClient,
    common,
    config::{self, Outbound},
    proxy::{self, outbound::HandlerBuilder, OutboundHandler},
};

use super::selector::OutboundSelector;

pub struct OutboundManager {
    handlers: HashMap<String, Arc<dyn OutboundHandler>>,
    selectors: Arc<super::Selectors>,
    default_handler: Option<String>,
    abort_handles: Vec<AbortHandle>,
}

impl OutboundManager {
    #[allow(clippy::type_complexity)]
    fn load_handlers(
        outbounds: &protobuf::RepeatedField<Outbound>,
        dns_client: Arc<RwLock<DnsClient>>,
        handlers: &mut HashMap<String, Arc<dyn OutboundHandler>>,
        default_handler: &mut Option<String>,
        abort_handles: &mut Vec<AbortHandle>,
    ) -> Result<()> {
        for outbound in outbounds.iter() {
            let tag = String::from(&outbound.tag);
            if handlers.contains_key(&tag) {
                continue;
            }
            if default_handler.is_none() {
                default_handler.replace(String::from(&outbound.tag));
                debug!("default handler [{}]", &outbound.tag);
            }
            let bind_addr = common::net::parse_bind_addr(&outbound.bind)?;
            match outbound.protocol.as_str() {
                #[cfg(feature = "outbound-direct")]
                "direct" => {
                    handlers.insert(
                        tag.clone(),
                        HandlerBuilder::default()
                            .tag(tag.clone())
                            .color(colored::Color::Green)
                            .tcp_handler(Box::new(direct::TcpHandler::new(
                                bind_addr,
                                dns_client.clone(),
                            )))
                            .udp_handler(Box::new(direct::UdpHandler::new(
                                bind_addr,
                                dns_client.clone(),
                            )))
                            .build(),
                    );
                    trace!("added handler [{}]", &tag);
                }
                #[cfg(feature = "outbound-drop")]
                "drop" => {
                    handlers.insert(
                        tag.clone(),
                        HandlerBuilder::default()
                            .tag(tag.clone())
                            .tcp_handler(Box::new(drop::TcpHandler))
                            .udp_handler(Box::new(drop::UdpHandler))
                            .build(),
                    );
                    trace!("added handler [{}]", &tag);
                }
                #[cfg(feature = "outbound-redirect")]
                "redirect" => {
                    let settings =
                        config::RedirectOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
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
                    let handler = HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .udp_handler(udp)
                        .build();
                    handlers.insert(tag.clone(), handler);
                    trace!("added handler [{}]", &tag);
                }
                #[cfg(feature = "outbound-socks")]
                "socks" => {
                    let settings =
                        config::SocksOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
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
                    let handler = HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .udp_handler(udp)
                        .build();
                    handlers.insert(tag.clone(), handler);
                    trace!("added handler [{}]", &tag);
                }
                #[cfg(feature = "outbound-shadowsocks")]
                "shadowsocks" => {
                    let settings =
                        config::ShadowsocksOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
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
                    let handler = HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .udp_handler(udp)
                        .build();
                    handlers.insert(tag.clone(), handler);
                    trace!("added handler [{}]", &tag);
                }
                #[cfg(feature = "outbound-trojan")]
                "trojan" => {
                    let settings =
                        config::TrojanOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
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
                    let handler = HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .udp_handler(udp)
                        .build();
                    handlers.insert(tag.clone(), handler);
                    trace!("added handler [{}]", &tag);
                }
                #[cfg(feature = "outbound-vmess")]
                "vmess" => {
                    let settings =
                        config::VMessOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
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
                    let handler = HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .udp_handler(udp)
                        .build();
                    handlers.insert(tag.clone(), handler);
                    trace!("added handler [{}]", &tag);
                }
                #[cfg(feature = "outbound-tls")]
                "tls" => {
                    let settings =
                        config::TlsOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let mut alpns = Vec::new();
                    for alpn in settings.alpn.iter() {
                        alpns.push(alpn.clone());
                    }
                    let tcp = Box::new(tls::TcpHandler::new(
                        settings.server_name.clone(),
                        alpns.clone(),
                    ));
                    let udp = Box::new(null::outbound::UdpHandler {
                        connect: None,
                        transport_type: proxy::DatagramTransportType::Stream,
                    });
                    let handler = HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .udp_handler(udp)
                        .build();
                    handlers.insert(tag.clone(), handler);
                    trace!("added handler [{}]", &tag);
                }
                #[cfg(feature = "outbound-ws")]
                "ws" => {
                    let settings =
                        config::WebSocketOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let tcp = Box::new(ws::outbound::TcpHandler {
                        path: settings.path.clone(),
                        headers: settings.headers.clone(),
                        dns_client: dns_client.clone(),
                    });
                    let udp = Box::new(null::outbound::UdpHandler {
                        connect: None,
                        transport_type: proxy::DatagramTransportType::Stream,
                    });
                    let handler = HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .udp_handler(udp)
                        .build();
                    handlers.insert(tag.clone(), handler);
                    trace!("added handler [{}]", &tag);
                }
                #[cfg(feature = "outbound-quic")]
                "quic" => {
                    let settings =
                        config::QuicOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let server_name = if settings.server_name.is_empty() {
                        None
                    } else {
                        Some(settings.server_name.clone())
                    };
                    let certificate = if settings.certificate.is_empty() {
                        None
                    } else {
                        Some(settings.certificate.clone())
                    };
                    let tcp = Box::new(quic::outbound::TcpHandler::new(
                        settings.address.clone(),
                        settings.port as u16,
                        server_name,
                        certificate,
                        bind_addr,
                        dns_client.clone(),
                    ));
                    let udp = Box::new(null::outbound::UdpHandler {
                        connect: Some(proxy::OutboundConnect::NoConnect),
                        transport_type: proxy::DatagramTransportType::Stream,
                    });
                    let handler = HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .udp_handler(udp)
                        .build();
                    handlers.insert(tag.clone(), handler);
                    trace!("added handler [{}]", &tag);
                }
                #[cfg(feature = "outbound-h2")]
                "h2" => {
                    let settings =
                        config::HTTP2OutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
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
                        Some(tcp),
                        None,
                    );
                    trace!("add handler [{}]", &tag);
                    handlers.insert(tag.clone(), handler);
                }
                _ => continue,
            }
        }

        // FIXME a better way to find outbound deps?
        for _i in 0..8 {
            'outbounds: for outbound in outbounds.iter() {
                let tag = String::from(&outbound.tag);
                if handlers.contains_key(&tag) {
                    continue;
                }
                let bind_addr = common::net::parse_bind_addr(&outbound.bind)?;
                match outbound.protocol.as_str() {
                    #[cfg(feature = "outbound-tryall")]
                    "tryall" => {
                        let settings =
                            config::TryAllOutboundSettings::parse_from_bytes(&outbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] outbound settings: {}", &tag, e)
                                })?;
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            } else {
                                continue 'outbounds;
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
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .tcp_handler(tcp)
                            .udp_handler(udp)
                            .build();
                        handlers.insert(tag.clone(), handler);
                        trace!(
                            "added handler [{}] with actors: {}",
                            &tag,
                            settings.actors.join(",")
                        );
                    }
                    #[cfg(feature = "outbound-random")]
                    "random" => {
                        let settings =
                            config::RandomOutboundSettings::parse_from_bytes(&outbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] outbound settings: {}", &tag, e)
                                })?;
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            } else {
                                continue 'outbounds;
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let tcp = Box::new(random::TcpHandler {
                            actors: actors.clone(),
                        });
                        let udp = Box::new(random::UdpHandler { actors });
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .tcp_handler(tcp)
                            .udp_handler(udp)
                            .build();
                        handlers.insert(tag.clone(), handler);
                        trace!(
                            "added handler [{}] with actors: {}",
                            &tag,
                            settings.actors.join(",")
                        );
                    }
                    #[cfg(feature = "outbound-rr")]
                    "rr" => {
                        let settings =
                            config::RROutboundSettings::parse_from_bytes(&outbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] outbound settings: {}", &tag, e)
                                })?;
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            } else {
                                continue 'outbounds;
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let tcp = Box::new(rr::TcpHandler {
                            actors: actors.clone(),
                            next: AtomicUsize::new(0),
                        });
                        let udp = Box::new(rr::UdpHandler {
                            actors,
                            next: AtomicUsize::new(0),
                        });
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .tcp_handler(tcp)
                            .udp_handler(udp)
                            .build();
                        handlers.insert(tag.clone(), handler);
                        trace!(
                            "added handler [{}] with actors: {}",
                            &tag,
                            settings.actors.join(",")
                        );
                    }
                    #[cfg(feature = "outbound-failover")]
                    "failover" => {
                        let settings =
                            config::FailOverOutboundSettings::parse_from_bytes(&outbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] outbound settings: {}", &tag, e)
                                })?;
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            } else {
                                continue 'outbounds;
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let (tcp, mut tcp_abort_handles) = failover::TcpHandler::new(
                            actors.clone(),
                            settings.fail_timeout,
                            settings.health_check,
                            settings.check_interval,
                            settings.failover,
                            settings.fallback_cache,
                            settings.cache_size as usize,
                            settings.cache_timeout as u64,
                        );
                        let (udp, mut udp_abort_handles) = failover::UdpHandler::new(
                            actors,
                            settings.fail_timeout,
                            settings.health_check,
                            settings.check_interval,
                            settings.failover,
                        );
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .tcp_handler(Box::new(tcp))
                            .udp_handler(Box::new(udp))
                            .build();
                        handlers.insert(tag.clone(), handler);
                        abort_handles.append(&mut tcp_abort_handles);
                        abort_handles.append(&mut udp_abort_handles);
                        trace!(
                            "added handler [{}] with actors: {}",
                            &tag,
                            settings.actors.join(",")
                        );
                    }
                    #[cfg(feature = "outbound-amux")]
                    "amux" => {
                        let settings =
                            config::AMuxOutboundSettings::parse_from_bytes(&outbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] outbound settings: {}", &tag, e)
                                })?;
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            } else {
                                continue 'outbounds;
                            }
                        }
                        let (tcp, mut tcp_abort_handles) = amux::outbound::TcpHandler::new(
                            settings.address.clone(),
                            settings.port as u16,
                            actors.clone(),
                            settings.max_accepts as usize,
                            settings.concurrency as usize,
                            bind_addr,
                            dns_client.clone(),
                        );
                        let udp = Box::new(null::outbound::UdpHandler {
                            connect: Some(proxy::OutboundConnect::NoConnect),
                            transport_type: proxy::DatagramTransportType::Stream,
                        });
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .tcp_handler(Box::new(tcp))
                            .udp_handler(udp)
                            .build();
                        handlers.insert(tag.clone(), handler);
                        abort_handles.append(&mut tcp_abort_handles);
                        trace!(
                            "added handler [{}] with actors: {}",
                            &tag,
                            settings.actors.join(",")
                        );
                    }
                    #[cfg(feature = "outbound-chain")]
                    "chain" => {
                        let settings =
                            config::ChainOutboundSettings::parse_from_bytes(&outbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] outbound settings: {}", &tag, e)
                                })?;
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            } else {
                                continue 'outbounds;
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
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .tcp_handler(tcp)
                            .udp_handler(udp)
                            .build();
                        handlers.insert(tag.clone(), handler);
                        trace!(
                            "added handler [{}] with actors: {}",
                            &tag,
                            settings.actors.join(",")
                        );
                    }
                    #[cfg(feature = "outbound-retry")]
                    "retry" => {
                        let settings =
                            config::RetryOutboundSettings::parse_from_bytes(&outbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] outbound settings: {}", &tag, e)
                                })?;
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            } else {
                                continue 'outbounds;
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
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .tcp_handler(tcp)
                            .udp_handler(udp)
                            .build();
                        handlers.insert(tag.clone(), handler);
                        trace!(
                            "added handler [{}] with actors: {}",
                            &tag,
                            settings.actors.join(",")
                        );
                    }
                    _ => continue,
                }
            }
        }

        Ok(())
    }

    fn load_selectors(
        outbounds: &protobuf::RepeatedField<Outbound>,
        handlers: &mut HashMap<String, Arc<dyn OutboundHandler>>,
        selectors: &mut super::Selectors,
    ) -> Result<()> {
        // FIXME a better way to find outbound deps?
        for _i in 0..8 {
            'outbounds: for outbound in outbounds.iter() {
                let tag = String::from(&outbound.tag);
                if handlers.contains_key(&tag) || selectors.contains_key(&tag) {
                    continue;
                }
                #[allow(clippy::single_match)]
                match outbound.protocol.as_str() {
                    #[cfg(feature = "outbound-select")]
                    "select" => {
                        let settings =
                            config::SelectOutboundSettings::parse_from_bytes(&outbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] outbound settings: {}", &tag, e)
                                })?;
                        let mut actors = HashMap::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.insert(actor.to_owned(), a.clone());
                            } else {
                                continue 'outbounds;
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }

                        let mut selector = OutboundSelector::new(tag.clone(), actors);
                        if let Ok(Some(selected)) = super::selector::get_selected_from_cache(&tag) {
                            // FIXME handle error
                            let _ = selector.set_selected(&selected);
                        } else {
                            let _ = selector.set_selected(&settings.actors[0]);
                        }
                        let selector = Arc::new(RwLock::new(selector));

                        let tcp = Box::new(select::TcpHandler {
                            selector: selector.clone(),
                        });
                        let udp = Box::new(select::UdpHandler {
                            selector: selector.clone(),
                        });
                        selectors.insert(tag.clone(), selector);
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .tcp_handler(tcp)
                            .udp_handler(udp)
                            .build();
                        handlers.insert(tag.clone(), handler);
                        trace!(
                            "added handler [{}] with actors: {}",
                            &tag,
                            settings.actors.join(",")
                        );
                    }
                    _ => continue,
                }
            }
        }

        Ok(())
    }

    // TODO make this non-async?
    pub async fn reload(
        &mut self,
        outbounds: &protobuf::RepeatedField<Outbound>,
        dns_client: Arc<RwLock<DnsClient>>,
    ) -> Result<()> {
        // Save outound select states.
        let mut selected_outbounds = HashMap::new();
        for (k, v) in self.selectors.iter() {
            selected_outbounds.insert(k.to_owned(), v.read().await.get_selected_tag());
        }

        // Load new outbounds.
        let mut handlers: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
        let mut default_handler: Option<String> = None;
        let mut abort_handles: Vec<AbortHandle> = Vec::new();
        let mut selectors: super::Selectors = HashMap::new();
        for _i in 0..4 {
            Self::load_handlers(
                outbounds,
                dns_client.clone(),
                &mut handlers,
                &mut default_handler,
                &mut abort_handles,
            )?;
            Self::load_selectors(outbounds, &mut handlers, &mut selectors)?;
        }

        // Restore outbound select states.
        for (k, v) in selected_outbounds.iter() {
            for (k2, v2) in selectors.iter_mut() {
                if k == k2 {
                    if let Some(v) = v {
                        let _ = v2.write().await.set_selected(v);
                    }
                }
            }
        }

        // Abort spawned tasks inside handlers.
        for abort_handle in self.abort_handles.iter() {
            abort_handle.abort();
        }

        self.handlers = handlers;
        self.selectors = Arc::new(selectors);
        self.default_handler = default_handler;
        self.abort_handles = abort_handles;
        Ok(())
    }

    pub fn new(
        outbounds: &protobuf::RepeatedField<Outbound>,
        dns_client: Arc<RwLock<DnsClient>>,
    ) -> Result<Self> {
        let mut handlers: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
        let mut default_handler: Option<String> = None;
        let mut abort_handles: Vec<AbortHandle> = Vec::new();
        let mut selectors: super::Selectors = HashMap::new();
        for _i in 0..4 {
            Self::load_handlers(
                outbounds,
                dns_client.clone(),
                &mut handlers,
                &mut default_handler,
                &mut abort_handles,
            )?;
            Self::load_selectors(outbounds, &mut handlers, &mut selectors)?;
        }
        Ok(OutboundManager {
            handlers,
            selectors: Arc::new(selectors),
            default_handler,
            abort_handles,
        })
    }

    pub fn add(&mut self, tag: String, handler: Arc<dyn OutboundHandler>) {
        self.handlers.insert(tag, handler);
    }

    pub fn get(&self, tag: &str) -> Option<Arc<dyn OutboundHandler>> {
        self.handlers.get(tag).map(Clone::clone)
    }

    pub fn default_handler(&self) -> Option<String> {
        self.default_handler.as_ref().map(Clone::clone)
    }

    pub fn handlers(&self) -> Handlers {
        Handlers {
            inner: self.handlers.values(),
        }
    }

    pub fn get_selector(&self, tag: &str) -> Option<Arc<RwLock<OutboundSelector>>> {
        self.selectors.get(tag).map(Clone::clone)
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
