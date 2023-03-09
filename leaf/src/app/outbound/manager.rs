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
        outbounds: &Vec<Outbound>,
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
                    .stream_handler(Box::new(direct::StreamHandler))
                    .datagram_handler(Box::new(direct::DatagramHandler))
                    .build(),
                #[cfg(feature = "outbound-drop")]
                "drop" => HandlerBuilder::default()
                    .tag(tag.clone())
                    .color(colored::Color::Red)
                    .stream_handler(Box::new(drop::StreamHandler))
                    .datagram_handler(Box::new(drop::DatagramHandler))
                    .build(),
                #[cfg(feature = "outbound-redirect")]
                "redirect" => {
                    let settings =
                        config::RedirectOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let stream = Box::new(redirect::StreamHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                    });
                    let datagram = Box::new(redirect::DatagramHandler {
                        address: settings.address,
                        port: settings.port as u16,
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .stream_handler(stream)
                        .datagram_handler(datagram)
                        .build()
                }
                #[cfg(feature = "outbound-socks")]
                "socks" => {
                    let settings =
                        config::SocksOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let stream = Box::new(socks::outbound::StreamHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        username: settings.username.clone(),
                        password: settings.password.clone(),
                    });
                    let datagram = Box::new(socks::outbound::DatagramHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        dns_client: dns_client.clone(),
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .stream_handler(stream)
                        .datagram_handler(datagram)
                        .build()
                }
                #[cfg(feature = "outbound-shadowsocks")]
                "shadowsocks" => {
                    let settings =
                        config::ShadowsocksOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let stream = Box::new(shadowsocks::outbound::StreamHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        cipher: settings.method.clone(),
                        password: settings.password.clone(),
                    });
                    let datagram = Box::new(shadowsocks::outbound::DatagramHandler {
                        address: settings.address,
                        port: settings.port as u16,
                        cipher: settings.method,
                        password: settings.password,
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .stream_handler(stream)
                        .datagram_handler(datagram)
                        .build()
                }
                #[cfg(feature = "outbound-trojan")]
                "trojan" => {
                    let settings =
                        config::TrojanOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let stream = Box::new(trojan::outbound::StreamHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        password: settings.password.clone(),
                    });
                    let datagram = Box::new(trojan::outbound::DatagramHandler {
                        address: settings.address,
                        port: settings.port as u16,
                        password: settings.password,
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .stream_handler(stream)
                        .datagram_handler(datagram)
                        .build()
                }
                #[cfg(feature = "outbound-vmess")]
                "vmess" => {
                    let settings =
                        config::VMessOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let stream = Box::new(vmess::outbound::StreamHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        uuid: settings.uuid.clone(),
                        security: settings.security.clone(),
                    });
                    let datagram = Box::new(vmess::outbound::DatagramHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        uuid: settings.uuid.clone(),
                        security: settings.security.clone(),
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .stream_handler(stream)
                        .datagram_handler(datagram)
                        .build()
                }
                #[cfg(feature = "outbound-tls")]
                "tls" => {
                    let settings =
                        config::TlsOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let certificate = if settings.certificate.is_empty() {
                        None
                    } else {
                        Some(settings.certificate.clone())
                    };
                    let stream = Box::new(tls::outbound::StreamHandler::new(
                        settings.server_name.clone(),
                        settings.alpn.clone(),
                        certificate,
                    )?);
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .stream_handler(stream)
                        .build()
                }
                #[cfg(feature = "outbound-ws")]
                "ws" => {
                    let settings =
                        config::WebSocketOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let stream = Box::new(ws::outbound::StreamHandler {
                        path: settings.path.clone(),
                        headers: settings.headers.clone(),
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .stream_handler(stream)
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
                    let stream = Box::new(quic::outbound::StreamHandler::new(
                        settings.address.clone(),
                        settings.port as u16,
                        server_name,
                        settings.alpn.clone(),
                        certificate,
                        dns_client.clone(),
                    ));
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .stream_handler(stream)
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
                        let stream = Box::new(tryall::StreamHandler {
                            actors: actors.clone(),
                            delay_base: settings.delay_base,
                            dns_client: dns_client.clone(),
                        });
                        let datagram = Box::new(tryall::DatagramHandler {
                            actors,
                            delay_base: settings.delay_base,
                            dns_client: dns_client.clone(),
                        });
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .stream_handler(stream)
                            .datagram_handler(datagram)
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
                        let stream = Box::new(r#static::StreamHandler::new(
                            actors.clone(),
                            &settings.method,
                        )?);
                        let datagram =
                            Box::new(r#static::DatagramHandler::new(actors, &settings.method)?);
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .stream_handler(stream)
                            .datagram_handler(datagram)
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
                                continue 'outbounds;
                            }
                        };
                        let (stream, mut stream_abort_handles) = failover::StreamHandler::new(
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
                            settings.health_check_active,
                            dns_client.clone(),
                        );
                        let (datagram, mut datagram_abort_handles) = failover::DatagramHandler::new(
                            actors,
                            settings.fail_timeout,
                            settings.health_check,
                            settings.check_interval,
                            settings.failover,
                            last_resort,
                            settings.health_check_timeout,
                            settings.health_check_delay,
                            settings.health_check_active,
                            dns_client.clone(),
                        );
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .stream_handler(Box::new(stream))
                            .datagram_handler(Box::new(datagram))
                            .build();
                        handlers.insert(tag.clone(), handler);
                        abort_handles.append(&mut stream_abort_handles);
                        abort_handles.append(&mut datagram_abort_handles);
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
                        let (stream, mut stream_abort_handles) = amux::outbound::StreamHandler::new(
                            settings.address.clone(),
                            settings.port as u16,
                            actors.clone(),
                            settings.max_accepts as usize,
                            settings.concurrency as usize,
                            dns_client.clone(),
                        );
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .stream_handler(Box::new(stream))
                            .build();
                        handlers.insert(tag.clone(), handler);
                        abort_handles.append(&mut stream_abort_handles);
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
                        let stream = Box::new(chain::outbound::StreamHandler {
                            actors: actors.clone(),
                        });
                        let datagram = Box::new(chain::outbound::DatagramHandler {
                            actors: actors.clone(),
                        });
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .stream_handler(stream)
                            .datagram_handler(datagram)
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
                        let stream = Box::new(super::plugin::ExternalOutboundStreamHandlerProxy(
                            external_handlers.get_stream_handler(&tag).unwrap(),
                        ));
                        let datagram =
                            Box::new(super::plugin::ExternalOutboundDatagramHandlerProxy(
                                external_handlers.get_datagram_handler(&tag).unwrap(),
                            ));
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .stream_handler(stream)
                            .datagram_handler(datagram)
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
        outbounds: &Vec<Outbound>,
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

                        let stream = Box::new(select::StreamHandler {
                            actors: actors.clone(),
                            selected: selected.clone(),
                        });
                        let datagram = Box::new(select::DatagramHandler { actors, selected });
                        selectors.insert(tag.clone(), selector);
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .stream_handler(stream)
                            .datagram_handler(datagram)
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
        outbounds: &Vec<Outbound>,
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

    pub fn new(outbounds: &Vec<Outbound>, dns_client: SyncDnsClient) -> Result<Self> {
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
