use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

use crate::{
    app::{dns_client::DnsClient, outbound::manager::OutboundManager},
    config::Config,
    session::{Session, SocksAddr},
};

fn get_start_options(
    config_path: String,
    #[cfg(feature = "auto-reload")] auto_reload: bool,
    multi_thread: bool,
    auto_threads: bool,
    threads: usize,
    stack_size: usize,
) -> crate::StartOptions {
    if !multi_thread {
        return crate::StartOptions {
            config: crate::Config::File(config_path),
            #[cfg(feature = "auto-reload")]
            auto_reload,
            #[cfg(target_os = "android")]
            socket_protect_path: None,
            runtime_opt: crate::RuntimeOption::SingleThread,
        };
    }
    if auto_threads {
        return crate::StartOptions {
            config: crate::Config::File(config_path),
            #[cfg(feature = "auto-reload")]
            auto_reload,
            #[cfg(target_os = "android")]
            socket_protect_path: None,
            runtime_opt: crate::RuntimeOption::MultiThreadAuto(stack_size),
        };
    }
    crate::StartOptions {
        config: crate::Config::File(config_path),
        #[cfg(feature = "auto-reload")]
        auto_reload,
        #[cfg(target_os = "android")]
        socket_protect_path: None,
        runtime_opt: crate::RuntimeOption::MultiThread(threads, stack_size),
    }
}

pub fn run_with_options(
    rt_id: crate::RuntimeId,
    config_path: String,
    #[cfg(feature = "auto-reload")] auto_reload: bool,
    multi_thread: bool,
    auto_threads: bool,
    threads: usize,
    stack_size: usize,
) -> Result<(), crate::Error> {
    let opts = get_start_options(
        config_path,
        #[cfg(feature = "auto-reload")]
        auto_reload,
        multi_thread,
        auto_threads,
        threads,
        stack_size,
    );
    crate::start(rt_id, opts)
}

pub async fn test_outbound(tag: &str, config: &Config) {
    let dns_client = Arc::new(RwLock::new(DnsClient::new(&config.dns).unwrap()));
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
