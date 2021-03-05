use std::collections::HashMap;
use std::sync::Arc;

use protobuf::Message;

use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::NatManager;
use crate::config::{
    AMuxInboundSettings, ChainInboundSettings, Inbound, ShadowsocksInboundSettings,
    TrojanInboundSettings, WebSocketInboundSettings,
};
use crate::proxy;
use crate::proxy::InboundHandler;
use crate::Runner;

#[cfg(feature = "inbound-amux")]
use crate::proxy::amux;
#[cfg(feature = "inbound-http")]
use crate::proxy::http;
#[cfg(feature = "inbound-shadowsocks")]
use crate::proxy::shadowsocks;
#[cfg(feature = "inbound-socks")]
use crate::proxy::socks;
#[cfg(feature = "inbound-trojan")]
use crate::proxy::trojan;
#[cfg(feature = "inbound-ws")]
use crate::proxy::ws;

#[cfg(feature = "inbound-chain")]
use crate::proxy::chain;

use super::network_listener::NetworkInboundListener;
use super::InboundListener;

#[cfg(all(
    feature = "inbound-tun",
    any(target_os = "ios", target_os = "macos", target_os = "linux")
))]
use super::tun_listener::TUNInboundListener;

pub struct InboundManager {
    listeners: HashMap<String, Arc<dyn InboundListener>>,
}

impl InboundManager {
    pub fn new(
        inbounds: &protobuf::RepeatedField<Inbound>,
        dispatcher: Arc<Dispatcher>,
        nat_manager: Arc<NatManager>,
    ) -> Self {
        let mut handlers: HashMap<String, Arc<dyn InboundHandler>> = HashMap::new();

        for inbound in inbounds.iter() {
            match inbound.protocol.as_str() {
                #[cfg(feature = "inbound-socks")]
                "socks" => {
                    let tcp = Arc::new(socks::inbound::TcpHandler);
                    let udp = Arc::new(socks::inbound::UdpHandler);
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        inbound.tag.clone(),
                        Some(tcp),
                        Some(udp),
                    ));
                    handlers.insert(inbound.tag.clone(), handler);
                }
                #[cfg(feature = "inbound-http")]
                "http" => {
                    let tcp = Arc::new(http::inbound::TcpHandler);
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        inbound.tag.clone(),
                        Some(tcp),
                        None,
                    ));
                    handlers.insert(inbound.tag.clone(), handler);
                }
                #[cfg(feature = "inbound-shadowsocks")]
                "shadowsocks" => {
                    let settings =
                        ShadowsocksInboundSettings::parse_from_bytes(&inbound.settings).unwrap();
                    let tcp = Arc::new(shadowsocks::inbound::TcpHandler {
                        cipher: settings.method.clone(),
                        password: settings.password.clone(),
                    });
                    let udp = Arc::new(shadowsocks::inbound::UdpHandler {
                        cipher: settings.method.clone(),
                        password: settings.password.clone(),
                    });
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        inbound.tag.clone(),
                        Some(tcp),
                        Some(udp),
                    ));
                    handlers.insert(inbound.tag.clone(), handler);
                }
                #[cfg(feature = "inbound-trojan")]
                "trojan" => {
                    let settings =
                        TrojanInboundSettings::parse_from_bytes(&inbound.settings).unwrap();
                    let tcp = Arc::new(trojan::inbound::TcpHandler::new(&settings.password));
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        inbound.tag.clone(),
                        Some(tcp),
                        None,
                    ));
                    handlers.insert(inbound.tag.clone(), handler);
                }
                #[cfg(feature = "inbound-ws")]
                "ws" => {
                    let settings =
                        WebSocketInboundSettings::parse_from_bytes(&inbound.settings).unwrap();
                    let tcp = Arc::new(ws::inbound::TcpHandler::new(settings.path.clone()));
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        inbound.tag.clone(),
                        Some(tcp),
                        None,
                    ));
                    handlers.insert(inbound.tag.clone(), handler);
                }
                _ => (),
            }
        }

        for _i in 0..4 {
            for inbound in inbounds.iter() {
                #[allow(clippy::single_match)]
                match inbound.protocol.as_str() {
                    #[cfg(feature = "inbound-amux")]
                    "amux" => {
                        let mut actors = Vec::new();
                        if let Ok(settings) =
                            AMuxInboundSettings::parse_from_bytes(&inbound.settings)
                        {
                            for actor in settings.actors.iter() {
                                if let Some(a) = handlers.get(actor) {
                                    actors.push(a.clone());
                                }
                            }
                        }
                        let tcp = Arc::new(amux::inbound::TcpHandler {
                            actors: actors.clone(),
                        });
                        let handler = Arc::new(proxy::inbound::Handler::new(
                            inbound.tag.clone(),
                            Some(tcp),
                            None,
                        ));
                        handlers.insert(inbound.tag.clone(), handler);
                    }
                    #[cfg(feature = "inbound-chain")]
                    "chain" => {
                        let settings =
                            ChainInboundSettings::parse_from_bytes(&inbound.settings).unwrap();
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let tcp = Arc::new(chain::inbound::TcpHandler {
                            actors: actors.clone(),
                        });
                        let udp = Arc::new(chain::inbound::UdpHandler { actors });
                        let handler = Arc::new(proxy::inbound::Handler::new(
                            inbound.tag.clone(),
                            Some(tcp),
                            Some(udp),
                        ));
                        handlers.insert(inbound.tag.clone(), handler);
                    }
                    _ => (),
                }
            }
        }

        let mut listeners: HashMap<String, Arc<dyn InboundListener>> = HashMap::new();

        for inbound in inbounds.iter() {
            match inbound.protocol.as_str() {
                #[cfg(all(
                    feature = "inbound-tun",
                    any(target_os = "ios", target_os = "macos", target_os = "linux")
                ))]
                "tun" => {
                    let listener = Arc::new(TUNInboundListener {
                        inbound: inbound.clone(),
                        dispatcher: dispatcher.clone(),
                        nat_manager: nat_manager.clone(),
                    });
                    listeners.insert(inbound.tag.clone(), listener);
                }
                _ => {
                    if inbound.port != 0 {
                        if let Some(h) = handlers.get(&inbound.tag) {
                            let listener = Arc::new(NetworkInboundListener {
                                address: inbound.address.clone(),
                                port: inbound.port as u16,
                                handler: h.clone(),
                                dispatcher: dispatcher.clone(),
                                nat_manager: nat_manager.clone(),
                            });
                            listeners.insert(inbound.tag.clone(), listener);
                        }
                    }
                }
            }
        }

        InboundManager { listeners }
    }

    pub fn get_runners(self) -> Vec<Runner> {
        let mut runners: Vec<Runner> = Vec::new();
        for (_, listener) in self.listeners {
            runners.append(&mut listener.listen());
        }
        runners
    }
}
