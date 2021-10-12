use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tokio::time::timeout;

use crate::{
    app::{dns_client::DnsClient, outbound::manager::OutboundManager, SyncDnsClient},
    config::Config,
    proxy::{AnyOutboundHandler, TcpOutboundHandler, UdpOutboundHandler},
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
            runtime_opt: crate::RuntimeOption::SingleThread,
        };
    }
    if auto_threads {
        return crate::StartOptions {
            config: crate::Config::File(config_path),
            #[cfg(feature = "auto-reload")]
            auto_reload,
            runtime_opt: crate::RuntimeOption::MultiThreadAuto(stack_size),
        };
    }
    crate::StartOptions {
        config: crate::Config::File(config_path),
        #[cfg(feature = "auto-reload")]
        auto_reload,
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

async fn test_tcp_outbound(
    sess: &Session,
    dns_client: SyncDnsClient,
    handler: &AnyOutboundHandler,
) {
    let start = tokio::time::Instant::now();
    match crate::proxy::connect_tcp_outbound(sess, dns_client, handler).await {
        Ok(stream) => match TcpOutboundHandler::handle(handler.as_ref(), &sess, stream).await {
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
        },
        Err(e) => {
            println!("dispatch to outbound {} failed: {}", &handler.tag(), e);
        }
    }
}

async fn test_udp_outbound(
    sess: &Session,
    dns_client: SyncDnsClient,
    handler: &AnyOutboundHandler,
) {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use trust_dns_proto::{
        op::{header::MessageType, op_code::OpCode, query::Query, Message},
        rr::{record_type::RecordType, Name},
    };
    let start = tokio::time::Instant::now();
    match crate::proxy::connect_udp_outbound(sess, dns_client, handler).await {
        Ok(transport) => {
            match UdpOutboundHandler::handle(handler.as_ref(), sess, transport).await {
                Ok(socket) => {
                    let addr =
                        SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
                    let mut msg = Message::new();
                    let name = Name::from_str("www.google.com.").unwrap();
                    let query = Query::query(name, RecordType::A);
                    msg.add_query(query);
                    let mut rng = StdRng::from_entropy();
                    let id: u16 = rng.gen();
                    msg.set_id(id);
                    msg.set_op_code(OpCode::Query);
                    msg.set_message_type(MessageType::Query);
                    msg.set_recursion_desired(true);
                    let msg_buf = msg.to_vec().unwrap();
                    let (mut recv, mut send) = socket.split();
                    if let Err(e) = send.send_to(&msg_buf, &addr).await {
                        println!("send message to {} failed: {}", &handler.tag(), e);
                    }
                    let mut buf = [0u8; 1500];
                    match recv.recv_from(&mut buf).await {
                        Ok(_) => {
                            let elapsed = tokio::time::Instant::now().duration_since(start);
                            println!(
                                "received response from outbound {} in {}ms",
                                &handler.tag(),
                                elapsed.as_millis()
                            );
                        }
                        Err(e) => {
                            println!("receive from outbound {} failed: {}", &handler.tag(), e);
                        }
                    }
                }
                Err(e) => {
                    println!("dispatch to outbound {} failed: {}", &handler.tag(), e);
                }
            }
        }
        Err(e) => {
            println!("dispatch to outbound {} failed: {}", &handler.tag(), e);
        }
    }
}

pub async fn test_outbound(tag: &str, config: &Config) {
    let dns_client = Arc::new(RwLock::new(DnsClient::new(&config.dns).unwrap()));
    let outbound_manager = OutboundManager::new(&config.outbounds, dns_client.clone()).unwrap();
    let handler = if let Some(v) = outbound_manager.get(tag) {
        v
    } else {
        println!("outbound {} not found", tag);
        return;
    };
    println!("testing outbound {}", &handler.tag());

    println!();

    println!("testing TCP...");
    let sess = Session {
        destination: SocksAddr::Domain("www.google.com".to_string(), 80),
        ..Default::default()
    };
    if let Err(e) = timeout(
        Duration::from_secs(4),
        test_tcp_outbound(&sess, dns_client.clone(), &handler),
    )
    .await
    {
        println!("test outbound {} failed: {}", &handler.tag(), e);
    }

    println!();

    println!("testing UDP...");
    let sess = Session {
        destination: SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)),
        ..Default::default()
    };
    if let Err(e) = timeout(
        Duration::from_secs(4),
        test_udp_outbound(&sess, dns_client.clone(), &handler),
    )
    .await
    {
        println!("test outbound {} failed: {}", &handler.tag(), e);
    }
}
