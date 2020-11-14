use std::sync::Arc;

use anyhow::Result;
use log::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime;

#[cfg(feature = "inbound-socks")]
use crate::proxy::socks;

#[cfg(feature = "feature-http")]
use crate::proxy::http;

use crate::{
    app::{
        dispatcher::Dispatcher, handler_manager::HandlerManager, nat_manager::NatManager,
        router::Router,
    },
    config::Config,
    session::{Session, SocksAddr},
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
            #[cfg(feature = "feature-http")]
            "http" => {
                if let Ok(r) = http::inbound::new(inbound, dispatcher.clone()) {
                    runners.push(r);
                }
            }
            #[cfg(feature = "inbound-socks")]
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

pub async fn test_outbound(tag: &str, config: &Config) {
    let handler_manager = HandlerManager::new(&config.outbounds, config.dns.as_ref().unwrap());
    let handler = if let Some(v) = handler_manager.get(tag) {
        v
    } else {
        println!("outbound {} not found", tag);
        return;
    };
    let sess = Session {
        source: "0.0.0.0:0".parse().unwrap(),
        destination: SocksAddr::Domain("www.google.com".to_string(), 80),
    };
    println!("testing outbound {}", &handler.tag());
    let start = tokio::time::Instant::now();
    match handler.handle(&sess, None).await {
        Ok(mut stream) => {
            if let Err(e) = stream.write_all(b"HEAD / HTTP/1.1\r\n\r\n").await {
                println!("write to outbound {} failed: {}", &handler.tag(), e);
                return;
            }
            let mut buf = vec![0u8; 1];
            match stream.read_exact(&mut buf).await {
                Ok(_) => {
                    let elapsed = tokio::time::Instant::now().duration_since(start);
                    println!(
                        "received response from outbound {} in {}ms",
                        &handler.tag(),
                        elapsed.as_millis()
                    );
                }
                Err(e) => {
                    println!("read from outbound {} failed: {}", &handler.tag(), e);
                }
            }
        }
        Err(e) => {
            println!("dispatch to outbound {} failed: {}", &handler.tag(), e);
        }
    }
}
