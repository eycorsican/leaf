use std::{
    collections::{hash_map, HashMap},
    convert::From,
    sync::Arc,
};

#[cfg(feature = "outbound-select")]
use tokio::sync::RwLock;

use anyhow::{anyhow, Result};
use futures::future::AbortHandle;
use protobuf::Message;
use tracing::{debug, trace};

#[cfg(feature = "outbound-chain")]
use crate::proxy::chain;
#[cfg(feature = "outbound-failover")]
use crate::proxy::failover;
#[cfg(feature = "outbound-mptp")]
use crate::proxy::mptp;
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
#[cfg(feature = "outbound-obfs")]
use crate::proxy::obfs;
#[cfg(feature = "outbound-quic")]
use crate::proxy::quic;
#[cfg(feature = "outbound-reality")]
use crate::proxy::reality;
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
    app::SyncDnsClient,
    config::{self, Outbound},
    proxy::{outbound::HandlerBuilder, *},
};

#[cfg(feature = "outbound-select")]
use super::selector::OutboundSelector;

pub struct OutboundManager {
    handlers: HashMap<String, AnyOutboundHandler>,
    #[cfg(feature = "plugin")]
    external_handlers: super::plugin::ExternalHandlers,
    #[cfg(feature = "outbound-select")]
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
        outbounds: &[Outbound],
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
                if e.protocol == outbound.protocol && e.settings == &outbound.settings {
                    trace!("add handler [{}] cloned from [{}]", &tag, &e.tag);
                    handlers.insert(tag.clone(), e.handler.clone());
                    continue 'loop1;
                }
            }

            let h: AnyOutboundHandler = match outbound.protocol.as_str() {
                #[cfg(feature = "outbound-direct")]
                "direct" => HandlerBuilder::default()
                    .tag(tag.clone())
                    .stream_handler(Arc::new(direct::StreamHandler))
                    .datagram_handler(Arc::new(direct::DatagramHandler))
                    .build(),
                #[cfg(feature = "outbound-drop")]
                "drop" => HandlerBuilder::default()
                    .tag(tag.clone())
                    .stream_handler(Arc::new(drop::StreamHandler))
                    .datagram_handler(Arc::new(drop::DatagramHandler))
                    .build(),
                #[cfg(feature = "outbound-redirect")]
                "redirect" => {
                    let settings =
                        config::RedirectOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let stream = Arc::new(redirect::StreamHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                    });
                    let datagram = Arc::new(redirect::DatagramHandler {
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
                    let stream = Arc::new(socks::outbound::StreamHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        username: settings.username.clone(),
                        password: settings.password.clone(),
                    });
                    let datagram = Arc::new(socks::outbound::DatagramHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        username: settings.username.clone(),
                        password: settings.password.clone(),
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
                    let stream = Arc::new(shadowsocks::outbound::StreamHandler::new(
                        settings.address.clone(),
                        settings.port as u16,
                        settings.method.clone(),
                        settings.password.clone(),
                        settings.prefix.as_ref().cloned(),
                    )?);
                    let datagram = Arc::new(shadowsocks::outbound::DatagramHandler {
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
                #[cfg(feature = "outbound-obfs")]
                "obfs" => {
                    let settings =
                        config::ObfsOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let stream = match &*settings.method {
                        "http" => Arc::new(obfs::HttpObfsStreamHandler::new(
                            settings.path.as_bytes(),
                            settings.host.as_bytes(),
                        )) as _,
                        "tls" => {
                            Arc::new(obfs::TlsObfsStreamHandler::new(settings.host.as_bytes())) as _
                        }
                        method => {
                            return Err(anyhow!(
                                "invalid [{}] outbound settings: unknown obfs method {}",
                                &tag,
                                method
                            ))
                        }
                    };
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .stream_handler(stream)
                        .build()
                }
                #[cfg(feature = "outbound-trojan")]
                "trojan" => {
                    let settings =
                        config::TrojanOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let stream = Arc::new(trojan::outbound::StreamHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        password: settings.password.clone(),
                    });
                    let datagram = Arc::new(trojan::outbound::DatagramHandler {
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
                    let stream = Arc::new(vmess::outbound::StreamHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        uuid: settings.uuid.clone(),
                        security: settings.security.clone(),
                    });
                    let datagram = Arc::new(vmess::outbound::DatagramHandler {
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
                #[cfg(feature = "outbound-vless")]
                "vless" => {
                    let settings =
                        config::VlessOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let stream = Arc::new(vless::outbound::StreamHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        uuid: settings.uuid.clone(),
                    });
                    let datagram = Arc::new(vless::outbound::DatagramHandler {
                        address: settings.address.clone(),
                        port: settings.port as u16,
                        uuid: settings.uuid.clone(),
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .stream_handler(stream)
                        .datagram_handler(datagram)
                        .build()
                }
                #[cfg(feature = "outbound-reality")]
                "reality" => {
                    let settings =
                        config::RealityOutboundSettings::parse_from_bytes(&outbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] outbound settings: {}", &tag, e))?;
                    let stream = Arc::new(reality::outbound::StreamHandler {
                        server_name: settings.server_name.clone(),
                        public_key: settings.public_key.clone(),
                        short_id: settings.short_id.clone(),
                    });
                    HandlerBuilder::default()
                        .tag(tag.clone())
                        .stream_handler(stream)
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
                    let stream = Arc::new(tls::outbound::StreamHandler::new(
                        settings.server_name.clone(),
                        settings.alpn.clone(),
                        certificate,
                        settings.insecure,
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
                    let stream = Arc::new(ws::outbound::StreamHandler {
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
                    let stream = Arc::new(quic::outbound::StreamHandler::new(
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
                        let stream = Arc::new(tryall::StreamHandler {
                            actors: actors.clone(),
                            delay_base: settings.delay_base,
                            dns_client: dns_client.clone(),
                        });
                        let datagram = Arc::new(tryall::DatagramHandler {
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
                        let stream = Arc::new(r#static::StreamHandler::new(
                            actors.clone(),
                            &settings.method,
                        )?);
                        let datagram =
                            Arc::new(r#static::DatagramHandler::new(actors, &settings.method)?);
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
                        let last_resort =
                            if let Some(last_resort_tag) = settings.last_resort.as_ref() {
                                handlers.get(last_resort_tag).cloned()
                            } else {
                                None
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
                            settings.health_check_prefers.clone(),
                            settings.health_check_on_start,
                            settings.health_check_wait,
                            settings.health_check_attempts,
                            settings.health_check_success_percentage,
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
                            settings.health_check_prefers,
                            settings.health_check_on_start,
                            settings.health_check_wait,
                            settings.health_check_attempts,
                            settings.health_check_success_percentage,
                            dns_client.clone(),
                        );
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .stream_handler(Arc::new(stream))
                            .datagram_handler(Arc::new(datagram))
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
                            settings.max_recv_bytes as usize,
                            settings.max_lifetime,
                            dns_client.clone(),
                        );
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .stream_handler(Arc::new(stream))
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
                        let stream = Arc::new(chain::outbound::StreamHandler {
                            actors: actors.clone(),
                        });
                        let datagram = Arc::new(chain::outbound::DatagramHandler {
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
                    #[cfg(feature = "outbound-mptp")]
                    "mptp" => {
                        let settings =
                            config::MptpOutboundSettings::parse_from_bytes(&outbound.settings)
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
                        let stream = Arc::new(mptp::outbound::stream::Handler {
                            actors: actors.clone(),
                            address: settings.address.clone(),
                            port: settings.port as u16,
                            dns_client: dns_client.clone(),
                        });
                        let handler = HandlerBuilder::default()
                            .tag(tag.clone())
                            .stream_handler(stream.clone())
                            .datagram_handler(stream)
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
                        let stream = Arc::new(super::plugin::ExternalOutboundStreamHandlerProxy(
                            external_handlers.get_stream_handler(&tag).unwrap(),
                        ));
                        let datagram =
                            Arc::new(super::plugin::ExternalOutboundDatagramHandlerProxy(
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
        outbounds: &[Outbound],
        handlers: &mut HashMap<String, AnyOutboundHandler>,
        #[cfg(feature = "plugin")] external_handlers: &mut super::plugin::ExternalHandlers,

        #[cfg(feature = "outbound-select")] selectors: &mut super::Selectors,
    ) -> Result<()> {
        // FIXME a better way to find outbound deps?
        for _i in 0..8 {
            #[allow(unused_labels)]
            'outbounds: for outbound in outbounds.iter() {
                let tag = String::from(&outbound.tag);
                if handlers.contains_key(&tag) {
                    continue;
                }
                #[cfg(feature = "outbound-select")]
                {
                    if selectors.contains_key(&tag) {
                        continue;
                    }
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

                        let stream = Arc::new(select::StreamHandler {
                            actors: actors.clone(),
                            selected: selected.clone(),
                        });
                        let datagram = Arc::new(select::DatagramHandler { actors, selected });

                        #[cfg(feature = "outbound-select")]
                        {
                            selectors.insert(tag.clone(), selector);
                        }

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
        outbounds: &[Outbound],
        dns_client: SyncDnsClient,
    ) -> Result<()> {
        // Save outound select states.
        #[cfg(feature = "outbound-select")]
        let selected_outbounds: HashMap<String, String> = {
            let mut m = HashMap::new();
            for (k, v) in self.selectors.iter() {
                m.insert(k.to_owned(), v.read().await.get_selected_tag());
            }
            m
        };

        // Load new outbounds.
        let mut handlers: HashMap<String, AnyOutboundHandler> = HashMap::new();

        #[cfg(feature = "plugin")]
        let mut external_handlers = super::plugin::ExternalHandlers::new();
        let mut default_handler: Option<String> = None;
        let mut abort_handles: Vec<AbortHandle> = Vec::new();

        #[cfg(feature = "outbound-select")]
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
                #[cfg(feature = "outbound-select")]
                &mut selectors,
            )?;
        }

        // Restore outbound select states.
        #[cfg(feature = "outbound-select")]
        {
            for (k, v) in selected_outbounds.iter() {
                for (k2, v2) in selectors.iter_mut() {
                    if k == k2 {
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

        #[cfg(feature = "plugin")]
        {
            self.external_handlers = external_handlers;
        }
        #[cfg(feature = "outbound-select")]
        {
            self.selectors = Arc::new(selectors);
        }

        self.default_handler = default_handler;
        self.abort_handles = abort_handles;
        Ok(())
    }

    pub fn new(outbounds: &[Outbound], dns_client: SyncDnsClient) -> Result<Self> {
        let mut handlers: HashMap<String, AnyOutboundHandler> = HashMap::new();
        #[cfg(feature = "plugin")]
        let mut external_handlers = super::plugin::ExternalHandlers::new();
        let mut default_handler: Option<String> = None;
        let mut abort_handles: Vec<AbortHandle> = Vec::new();
        #[cfg(feature = "outbound-select")]
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
                #[cfg(feature = "outbound-select")]
                &mut selectors,
            )?;
        }

        Ok(OutboundManager {
            handlers,
            #[cfg(feature = "plugin")]
            external_handlers,

            #[cfg(feature = "outbound-select")]
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
        self.default_handler.clone()
    }

    pub fn handlers(&self) -> Handlers<'_> {
        Handlers {
            inner: self.handlers.values(),
        }
    }

    #[cfg(feature = "outbound-select")]
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
