use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime;

use crate::{
    app::{
        dispatcher::Dispatcher, inbound::manager::InboundManager, nat_manager::NatManager,
        outbound::manager::OutboundManager, router::Router,
    },
    config::Config,
    session::{Session, SocksAddr},
    Runner,
};

pub fn create_runners(config: Config) -> Result<Vec<Runner>> {
    let outbound_manager = OutboundManager::new(&config.outbounds, config.dns.as_ref().unwrap());
    let router = Router::new(&config.routing_rules);
    let dispatcher = Arc::new(Dispatcher::new(outbound_manager, router));
    let nat_manager = Arc::new(NatManager::new(dispatcher.clone()));
    let inbound_manager = InboundManager::new(&config.inbounds, dispatcher, nat_manager);
    let runners = inbound_manager.get_runners();
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
    let outbound_manager = OutboundManager::new(&config.outbounds, config.dns.as_ref().unwrap());
    let handler = if let Some(v) = outbound_manager.get(tag) {
        v
    } else {
        println!("outbound {} not found", tag);
        return;
    };
    let sess = Session {
        source: "0.0.0.0:0".parse().unwrap(),
        local_addr: "0.0.0.0:0".parse().unwrap(),
        destination: SocksAddr::Domain("www.google.com".to_string(), 80),
    };
    println!("testing outbound {}", &handler.tag());
    let start = tokio::time::Instant::now();
    match handler.handle_tcp(&sess, None).await {
        Ok(mut stream) => {
            if let Err(e) = stream.write_all(b"HEAD / HTTP/1.1\r\n\r\n").await {
                println!("write to outbound {} failed: {}", &handler.tag(), e);
                return;
            }
            let mut buf = vec![0u8; 30];
            match stream.read_exact(&mut buf).await {
                Ok(_) => {
                    let elapsed = tokio::time::Instant::now().duration_since(start);
                    println!(
                        "received response from outbound {} in {}ms",
                        &handler.tag(),
                        elapsed.as_millis()
                    );
                    println!("truncated response:\n{}", String::from_utf8_lossy(&buf))
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
