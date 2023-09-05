use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tokio::time::timeout;

use crate::{
    app::{dns_client::DnsClient, outbound::manager::OutboundManager, SyncDnsClient},
    config::Config,
    proxy::*,
    session::*,
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
    dns_client: SyncDnsClient,
    handler: AnyOutboundHandler,
) -> Result<Duration> {
    let sess = Session {
        destination: SocksAddr::Domain("www.google.com".to_string(), 80),
        new_conn_once: true,
        ..Default::default()
    };
    let start = tokio::time::Instant::now();
    let stream = crate::proxy::connect_stream_outbound(&sess, dns_client, &handler).await?;
    let mut stream = handler.stream()?.handle(&sess, None, stream).await?;
    stream.write_all(b"HEAD / HTTP/1.1\r\n\r\n").await?;
    let mut buf = Vec::new();
    let n = stream.read_buf(&mut buf).await?;
    if n == 0 {
        Err(anyhow!("EOF"))
    } else {
        Ok(tokio::time::Instant::now().duration_since(start))
    }
}

async fn test_udp_outbound(
    dns_client: SyncDnsClient,
    handler: AnyOutboundHandler,
) -> Result<Duration> {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use trust_dns_proto::{
        op::{header::MessageType, op_code::OpCode, query::Query, Message},
        rr::{record_type::RecordType, Name},
    };
    let addr = SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
    let sess = Session {
        destination: addr.clone(),
        new_conn_once: true,
        ..Default::default()
    };
    let start = tokio::time::Instant::now();
    let dgram = crate::proxy::connect_datagram_outbound(&sess, dns_client, &handler).await?;
    let dgram = handler.datagram()?.handle(&sess, dgram).await?;
    let mut msg = Message::new();
    let name = Name::from_str("www.google.com.")?;
    let query = Query::query(name, RecordType::A);
    msg.add_query(query);
    let mut rng = StdRng::from_entropy();
    let id: u16 = rng.gen();
    msg.set_id(id);
    msg.set_op_code(OpCode::Query);
    msg.set_message_type(MessageType::Query);
    msg.set_recursion_desired(true);
    let msg_buf = msg.to_vec()?;
    let (mut recv, mut send) = dgram.split();
    send.send_to(&msg_buf, &addr).await?;
    let mut buf = [0u8; 1500];
    let _ = recv.recv_from(&mut buf).await?;
    Ok(tokio::time::Instant::now().duration_since(start))
}

pub async fn test_outbound(
    tag: &str,
    config: &Config,
    to: Option<Duration>,
) -> Result<(Result<Duration>, Result<Duration>)> {
    let to = to.unwrap_or(Duration::from_secs(4));
    let dns_client = Arc::new(RwLock::new(DnsClient::new(&config.dns)?));
    let outbound_manager = OutboundManager::new(&config.outbounds, dns_client.clone())?;
    let handler = outbound_manager
        .get(tag)
        .ok_or_else(|| anyhow!("outbound {} not found", tag))?;
    let (tcp_res, udp_res) = futures::future::join(
        timeout(to, test_tcp_outbound(dns_client.clone(), handler.clone())),
        timeout(to, test_udp_outbound(dns_client, handler)),
    )
    .await;
    let tcp_res = match tcp_res.map_err(|e| e.into()) {
        Err(e) => Err(e),
        Ok(res) => match res {
            Err(e) => Err(e),
            Ok(duration) => Ok(duration),
        },
    };
    let udp_res = match udp_res.map_err(|e| e.into()) {
        Err(e) => Err(e),
        Ok(res) => match res {
            Err(e) => Err(e),
            Ok(duration) => Ok(duration),
        },
    };
    Ok((tcp_res, udp_res))
}
