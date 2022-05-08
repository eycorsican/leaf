use std::{
    collections::{hash_map, HashMap},
    convert::From,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use futures::future::AbortHandle;
use log::*;
use protobuf::Message;
use tokio::sync::RwLock;

#[cfg(feature = "outbound-chain")]
use crate::proxy::chain;
#[cfg(feature = "outbound-failover")]
use crate::proxy::failover;
#[cfg(feature = "outbound-static")]
use crate::proxy::r#static;
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
    app::SyncDnsClient,
    config::{self, Outbound},
    proxy::{outbound::HandlerBuilder, *},
};

use super::selector::OutboundSelector;

pub struct OutboundManager {
    handlers: HashMap<String, AnyOutboundHandler>,
    #[cfg(feature = "plugin")]
    external_handlers: super::plugin::ExternalHandlers,
    selectors: Arc<super::Selectors>,
    default_handler: Option<String>,
    abort_handles: Vec<AbortHandle>,
}

struct HandlerCacheEntry<'a> {
    tag: &'a str,
    handler: AnyOutboundHandler,
    protocol: &'a str,
    settings: &'a Vec<u8>,
}

impl OutboundManager {
    #[allow(clippy::type_complexity)]
    fn load_handlers(
        outbounds: &protobuf::RepeatedField<Outbound>,
        dns_client: SyncDnsClient,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
        #[cfg(feature = "plugin")] external_handlers: &mut super::plugin::ExternalHandlers,
        default_handler: &mut Option<String>,
        abort_handles: &mut Vec<AbortHandle>,
    ) -> Result<()> {
        // If there are multiple outbounds with the same setting, we would want
        // a shared one to reduce memory usage. This vector is used as a cache for
        // unseen outbounds so we can reuse them later.
        let mut cached_handlers: Vec<HandlerCacheEntry> = Vec::new();

        'loop1: for outbound in outbounds.iter() {
            let tag = String::from(&outbound.tag);
            if handlers.contains_key(&tag) {
                continue;
            }
            if default_handler.is_none() {
                default_handler.replace(String::from(&outbound.tag));
                debug!("default handler [{}]", &outbound.tag);
            }

            // Check whether an identical one already exist.
            for e in cached_handlers.iter() {
                if e.protocol == &outbound.protocol && e.settings == &outbound.settings {
                    trace!("add handler [{}] cloned from [{}]", &tag, &e.tag);
                    handlers.insert(tag.clone(), e.handler.clone());
                    continue 'loop1;
                }
            }

            let h: AnyOutboundHandler = match outbound.protocol.as_str() {
                #[cfg(feature = "outbound-direct")]
                "direct" => HandlerBuilder::default()
                    .tag(tag.clone())
                    .color(colored::Color::Green)
                    .tcp_handler(Box::new(direct::TcpHandler))
                    .udp_handler(Box::new(direct::UdpHandler))
                    .build(),
                #[cfg(feature = "outbound-drop")]
                "drop" => HandlerBuilder::default()
                    .tag(tag.clone())
                    .color(colored::Color::Red)
                    .tcp_handler(Box::new(drop::TcpHandler))
                    .udp_handler(Box::new(drop::UdpHandler))
                    .build(),
                #[cfg(feature = "outbound-redirect")]
                "redirect" => {
                    let settings =
                        config::RedirectOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let tcp = Box::new(redirect::TcpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                    });
                    let udp = Box::new(redirect::UdpHandler {
                        address: settings.address,
                        port: settings.port as u16,
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .udp_handler(udp)
                        .build()
                }
                #[cfg(feature = "outbound-socks")]
                "socks" => {
                    let settings =
                        config::SocksOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let tcp = Box::new(socks::outbound::TcpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                    });
                    let udp = Box::new(socks::outbound::UdpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        dns_client: dns_client.clone(),
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .udp_handler(udp)
                        .build()
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
                    });
                    let udp = Box::new(shadowsocks::outbound::UdpHandler {
                        address: settings.address,
                        port: settings.port as u16,
                        cipher: settings.method,
                        password: settings.password,
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .udp_handler(udp)
                        .build()
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
                    });
                    let udp = Box::new(trojan::outbound::UdpHandler {
                        address: settings.address,
                        port: settings.port as u16,
                        password: settings.password,
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .udp_handler(udp)
                        .build()
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
                    });
                    let udp = Box::new(vmess::UdpHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        uuid: settings.uuid.clone(),
                        security: settings.security.clone(),
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .udp_handler(udp)
                        .build()
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
                    let certificate = if settings.certificate.is_empty() {
                        None
                    } else {
                        Some(settings.certificate.clone())
                    };
                    let tcp = Box::new(tls::outbound::TcpHandler::new(
                        settings.server_name.clone(),
                        alpns.clone(),
                        certificate,
                    )?);
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .build()
                }
                #[cfg(feature = "outbound-ws")]
                "ws" => {
                    let settings =
                        config::WebSocketOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let tcp = Box::new(ws::outbound::TcpHandler {
                        path: settings.path.clone(),
                        headers: settings.headers.clone(),
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .build()
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
                        dns_client.clone(),
                    ));
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .tcp_handler(tcp)
                        .build()
                }
                _ => continue,
            };
            cached_handlers.push(HandlerCacheEntry {
                tag: &outbound.tag,
                handler: h.clone(),
                protocol: &outbound.protocol,
                settings: &outbound.settings,
            });
            trace!("add handler [{}]", &tag);
            handlers.insert(tag, h);
        }

        drop(cached_handlers);

        // FIXME a better way to find outbound deps?
        for _i in 0..8 {
            'outbounds: for outbound in outbounds.iter() {
                let tag = String::from(&outbound.tag);
                if handlers.contains_key(&tag) {
                    continue;
                }
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
                            dns_client: dns_client.clone(),
                        });
                        let udp = Box::new(tryall::UdpHandler {
                            actors,
                            delay_base: settings.delay_base,
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
                    #[cfg(feature = "outbound-static")]
                    "static" => {
                        let settings =
                            config::StaticOutboundSettings::parse_from_bytes(&outbound.settings)
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
                        let tcp =
                            Box::new(r#static::TcpHandler::new(actors.clone(), &settings.method)?);
                        let udp = Box::new(r#static::UdpHandler::new(actors, &settings.method)?);
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
                        let last_resort = if settings.last_resort.is_empty() {
                            None
                        } else {
                            if let Some(a) = handlers.get(&settings.last_resort) {
                                Some(a.clone())
                            } else {
                                None
                            }
                        };
                        let (tcp, mut tcp_abort_handles) = failover::TcpHandler::new(
                            actors.clone(),
                            settings.fail_timeout,
                            settings.health_check,
                            settings.check_interval,
                            settings.failover,
                            settings.fallback_cache,
                            settings.cache_size as usize,
                            settings.cache_timeout as u64,
                            last_resort.clone(),
                            settings.health_check_timeout,
                            settings.health_check_delay,
                            dns_client.clone(),
                        );
                        let (udp, mut udp_abort_handles) = failover::UdpHandler::new(
                            actors,
                            settings.fail_timeout,
                            settings.health_check,
                            settings.check_interval,
                            settings.failover,
                            last_resort,
                            settings.health_check_timeout,
                            settings.health_check_delay,
                            dns_client.clone(),
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
                            dns_client.clone(),
                        );
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .tcp_handler(Box::new(tcp))
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
                        });
                        let udp = Box::new(chain::outbound::UdpHandler {
                            actors: actors.clone(),
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
                    #[cfg(feature = "plugin")]
                    "plugin" => {
                        let settings =
                            config::PluginOutboundSettings::parse_from_bytes(&outbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] outbound settings: {}", &tag, e)
                                })?;
                        unsafe {
                            external_handlers
                                .new_handler(settings.path, &tag, &settings.args)
                                .unwrap()
                        };
                        let tcp = Box::new(super::plugin::ExternalTcpOutboundHandlerProxy(
                            external_handlers.get_tcp_handler(&tag).unwrap(),
                        ));
                        let udp = Box::new(super::plugin::ExternalUdpOutboundHandlerProxy(
                            external_handlers.get_udp_handler(&tag).unwrap(),
                        ));
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .tcp_handler(tcp)
                            .udp_handler(udp)
                            .build();
                        handlers.insert(tag.clone(), handler);
                        trace!("added handler [{}]", &tag,);
                    }
                    _ => continue,
                }
            }
        }

        Ok(())
    }

    #[allow(unused_variables)]
    fn load_selectors(
        outbounds: &protobuf::RepeatedField<Outbound>,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
        #[cfg(feature = "plugin")] external_handlers: &mut super::plugin::ExternalHandlers,
        selectors: &mut super::Selectors,
    ) -> Result<()> {
        // FIXME a better way to find outbound deps?
        for _i in 0..8 {
            #[allow(unused_labels)]
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

                        let actors_tags: Vec<String> =
                            actors.iter().map(|x| x.tag().to_owned()).collect();

                        use std::sync::atomic::AtomicUsize;
                        let selected = Arc::new(AtomicUsize::new(0));

                        let mut selector =
                            OutboundSelector::new(tag.clone(), actors_tags, selected.clone());
                        if let Ok(Some(selected)) = super::selector::get_selected_from_cache(&tag) {
                            // FIXME handle error
                            let _ = selector.set_selected(&selected);
                        } else {
                            let _ = selector.set_selected(&settings.actors[0]);
                        }
                        let selector = Arc::new(RwLock::new(selector));

                        let tcp = Box::new(select::TcpHandler {
                            actors: actors.clone(),
                            selected: selected.clone(),
                        });
                        let udp = Box::new(select::UdpHandler { actors, selected });
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
        dns_client: SyncDnsClient,
    ) -> Result<()> {
        // Save outound select states.
        let mut selected_outbounds = HashMap::new();
        for (k, v) in self.selectors.iter() {
            selected_outbounds.insert(k.to_owned(), v.read().await.get_selected_tag());
        }

        // Load new outbounds.
        let mut handlers: HashMap<String, AnyOutboundHandler> = HashMap::new();

        #[cfg(feature = "plugin")]
        let mut external_handlers = super::plugin::ExternalHandlers::new();
        let mut default_handler: Option<String> = None;
        let mut abort_handles: Vec<AbortHandle> = Vec::new();
        let mut selectors: super::Selectors = HashMap::new();
        for _i in 0..4 {
            Self::load_handlers(
                outbounds,
                dns_client.clone(),
                &mut handlers,
                #[cfg(feature = "plugin")]
                &mut external_handlers,
                &mut default_handler,
                &mut abort_handles,
            )?;
            Self::load_selectors(
                outbounds,
                &mut handlers,
                #[cfg(feature = "plugin")]
                &mut external_handlers,
                &mut selectors,
            )?;
        }

        // Restore outbound select states.
        for (k, v) in selected_outbounds.iter() {
            for (k2, v2) in selectors.iter_mut() {
                if k == k2 {
                    let _ = v2.write().await.set_selected(v);
                }
            }
        }

        // Abort spawned tasks inside handlers.
        for abort_handle in self.abort_handles.iter() {
            abort_handle.abort();
        }

        self.handlers = handlers;
        #[cfg(feature = "plugin")]
        {
            self.external_handlers = external_handlers;
        }
        self.selectors = Arc::new(selectors);
        self.default_handler = default_handler;
        self.abort_handles = abort_handles;
        Ok(())
    }

    pub fn new(
        outbounds: &protobuf::RepeatedField<Outbound>,
        dns_client: SyncDnsClient,
    ) -> Result<Self> {
        let mut handlers: HashMap<String, AnyOutboundHandler> = HashMap::new();
        #[cfg(feature = "plugin")]
        let mut external_handlers = super::plugin::ExternalHandlers::new();
        let mut default_handler: Option<String> = None;
        let mut abort_handles: Vec<AbortHandle> = Vec::new();
        let mut selectors: super::Selectors = HashMap::new();
        for _i in 0..4 {
            Self::load_handlers(
                outbounds,
                dns_client.clone(),
                &mut handlers,
                #[cfg(feature = "plugin")]
                &mut external_handlers,
                &mut default_handler,
                &mut abort_handles,
            )?;
            Self::load_selectors(
                outbounds,
                &mut handlers,
                #[cfg(feature = "plugin")]
                &mut external_handlers,
                &mut selectors,
            )?;
        }
        Ok(OutboundManager {
            handlers,
            #[cfg(feature = "plugin")]
            external_handlers,
            selectors: Arc::new(selectors),
            default_handler,
            abort_handles,
        })
    }

    pub fn add(&mut self, tag: String, handler: AnyOutboundHandler) {
        self.handlers.insert(tag, handler);
    }

    pub fn get(&self, tag: &str) -> Option<AnyOutboundHandler> {
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
    inner: hash_map::Values<'a, String, AnyOutboundHandler>,
}

impl<'a> Iterator for Handlers<'a> {
    type Item = &'a AnyOutboundHandler;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}
