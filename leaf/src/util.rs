use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    app::{
        dispatcher::Dispatcher, dns_client::DnsClient, inbound::manager::InboundManager,
        nat_manager::NatManager, outbound::manager::OutboundManager, router::Router,
    },
    config::Config,
    session::{Session, SocksAddr},
    Runner,
};

#[cfg(any(target_os = "ios", target_os = "android"))]
use super::mobile;
use super::{common, config};

pub fn create_runners(config: Config) -> Result<Vec<Runner>> {
    let dns_client = Arc::new(DnsClient::new(&config.dns)?);
    let outbound_manager = OutboundManager::new(&config.outbounds, dns_client.clone())?;
    let router = Router::new(&config.routing_rules, dns_client);
    let dispatcher = Arc::new(Dispatcher::new(outbound_manager, router));
    let nat_manager = Arc::new(NatManager::new(dispatcher.clone()));
    let inbound_manager = InboundManager::new(&config.inbounds, dispatcher, nat_manager);
    let runners = inbound_manager.get_runners();
    Ok(runners)
}

pub fn prepare(config: config::Config) -> Result<Vec<Runner>> {
    let loglevel = if let Some(log) = config.log.as_ref() {
        match log.level {
            config::Log_Level::TRACE => log::LevelFilter::Trace,
            config::Log_Level::DEBUG => log::LevelFilter::Debug,
            config::Log_Level::INFO => log::LevelFilter::Info,
            config::Log_Level::WARN => log::LevelFilter::Warn,
            config::Log_Level::ERROR => log::LevelFilter::Error,
        }
    } else {
        log::LevelFilter::Info
    };
    let mut logger = common::log::setup_logger(loglevel);
    if let Some(log) = config.log.as_ref() {
        match log.output {
            config::Log_Output::CONSOLE => {
                #[cfg(any(target_os = "ios", target_os = "android"))]
                {
                    let console_output = fern::Output::writer(
                        Box::new(mobile::logger::ConsoleWriter::default()),
                        "\n",
                    );
                    logger = logger.chain(console_output);
                }
                #[cfg(not(any(target_os = "ios", target_os = "android")))]
                {
                    logger = logger.chain(fern::Output::stdout("\n"));
                }
            }
            config::Log_Output::FILE => {
                let f = fern::log_file(&log.output_file).expect("open log file failed");
                let file_output = fern::Output::file(f, "\n");
                logger = logger.chain(file_output);
            }
        }
    }
    common::log::apply_logger(logger);

    create_runners(config).map_err(|e| anyhow!("create runners fialed: {}", e))
}

pub async fn test_outbound(tag: &str, config: &Config) {
    let dns_client = Arc::new(DnsClient::new(&config.dns).unwrap());
    let outbound_manager = OutboundManager::new(&config.outbounds, dns_client).unwrap();
    let handler = if let Some(v) = outbound_manager.get(tag) {
        v
    } else {
        println!("outbound {} not found", tag);
        return;
    };
    let sess = Session {
        destination: SocksAddr::Domain("www.google.com".to_string(), 80),
        ..Default::default()
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
