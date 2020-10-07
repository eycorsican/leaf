use std::sync::Arc;

use anyhow::Result;
use log::*;
use tokio::runtime;

#[cfg(feature = "socks")]
use crate::proxy::socks;

use crate::{
    app::{
        dispatcher::Dispatcher, handler_manager::HandlerManager, nat_manager::NatManager,
        router::Router,
    },
    config::Config,
    proxy::http,
    Runner,
};

#[cfg(any(target_os = "ios", target_os = "macos", target_os = "linux"))]
use crate::proxy::tun;

pub fn create_runners(config: Config) -> Result<Vec<Runner>> {
    let handler_manager = HandlerManager::new(&config.outbounds, config.dns.as_ref().unwrap());
    let router = Router::new(&config.routing_rules);
    let dispatcher = Arc::new(Dispatcher::new(handler_manager, router));
    let nat_manager = Arc::new(NatManager::new(dispatcher.clone()));
    let mut runners: Vec<Runner> = Vec::new();
    for inbound in config.inbounds.into_iter() {
        match inbound.protocol.as_str() {
            "http" => {
                if let Ok(r) = http::inbound::new(inbound, dispatcher.clone()) {
                    runners.push(r);
                }
            }
            #[cfg(feature = "socks")]
            "socks" => {
                if let Ok(r) =
                    socks::inbound::new(&inbound, dispatcher.clone(), nat_manager.clone())
                {
                    runners.push(r);
                }
            }
            #[cfg(any(target_os = "ios", target_os = "macos", target_os = "linux"))]
            "tun" => {
                if let Ok(r) = tun::inbound::new(inbound, dispatcher.clone(), nat_manager.clone()) {
                    runners.push(Box::pin(r));
                }
            }
            _ => {
                warn!("unknown protocol {:?}", inbound.protocol);
            }
        }
    }
    Ok(runners)
}

pub fn run_with_config(config: Config) -> Result<()> {
    let mut rt = runtime::Builder::new()
        .basic_scheduler()
        .enable_all()
        .build()
        .unwrap();
    let runners = create_runners(config)?;
    rt.block_on(futures::future::join_all(runners));
    Ok(())
}
