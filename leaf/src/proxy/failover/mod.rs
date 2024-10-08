use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{sync::Arc, time::Duration};

use bytes::BytesMut;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, Notify};
use tokio::time::{timeout, Instant};
use tracing::{debug, trace, warn};
use trust_dns_proto::{
    op::{header::MessageType, op_code::OpCode, query::Query, Message},
    rr::{record_type::RecordType, Name},
};

use crate::{app::SyncDnsClient, proxy::*, session::*};

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Measure {
    idx: usize,
    rtt: u128,
    tag: String,
}

impl Measure {
    fn new(idx: usize, rtt: u128, tag: String) -> Self {
        Self { idx, rtt, tag }
    }
}

async fn single_health_check(
    network: Network,
    idx: usize,
    tag: String,
    h: AnyOutboundHandler,
    dns_client: SyncDnsClient,
    delay: u32,
) -> Measure {
    tokio::time::sleep(Duration::from_millis(
        StdRng::from_entropy().gen_range(0..=delay) as u64,
    ))
    .await;

    let dest = match network {
        Network::Tcp => SocksAddr::Domain("www.google.com".to_string(), 443),
        Network::Udp => SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)),
    };

    let sess = Session {
        destination: dest,
        new_conn_once: true,
        ..Default::default()
    };

    let start = Instant::now();

    match network {
        Network::Tcp => {
            let stream = match crate::proxy::connect_stream_outbound(&sess, dns_client, &h).await {
                Ok(s) => s,
                Err(_) => return Measure::new(idx, u128::MAX, tag),
            };
            let m: Measure;

            let Ok(h) = h.stream() else {
                return Measure::new(idx, u128::MAX, tag);
            };

            // TODO Mock an LHS stream with the given payload.
            match h.handle(&sess, None, stream).await {
                Ok(stream) => {
                    let Ok(tls_handler) = crate::proxy::tls::outbound::StreamHandler::new(
                        String::from(""),
                        vec![],
                        None,
                        false,
                    ) else {
                        return Measure::new(idx, u128::MAX, tag);
                    };

                    let Ok(mut stream) = tls_handler.handle(&sess, None, Some(stream)).await else {
                        return Measure::new(idx, u128::MAX - 1, tag);
                    };

                    if stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.is_err() {
                        return Measure::new(idx, u128::MAX - 2, tag);
                    }
                    let mut buf = BytesMut::with_capacity(2 * 1024);
                    match stream.read_buf(&mut buf).await {
                        Ok(n) => {
                            let elapsed = Instant::now().duration_since(start);
                            debug!(
                                "received {} bytes tcp health check response from {} in {} ms: {}",
                                n,
                                &tag,
                                elapsed.as_millis(),
                                String::from_utf8_lossy(&buf[..n.min(12)]),
                            );
                            m = Measure::new(idx, elapsed.as_millis(), tag);
                        }
                        Err(_) => {
                            m = Measure::new(idx, u128::MAX - 3, tag);
                        }
                    }
                    let _ = stream.shutdown().await;
                }
                Err(_) => {
                    m = Measure::new(idx, u128::MAX, tag);
                }
            }
            m
        }
        Network::Udp => {
            let transport =
                match crate::proxy::connect_datagram_outbound(&sess, dns_client, &h).await {
                    Ok(t) => t,
                    Err(_) => return Measure::new(idx, u128::MAX, tag),
                };
            let h = if let Ok(h) = h.datagram() {
                h
            } else {
                return Measure::new(idx, u128::MAX, tag);
            };
            match h.handle(&sess, transport).await {
                Ok(socket) => {
                    let addr =
                        SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53));
                    let mut msg = Message::new();
                    let name = match Name::from_str("www.google.com.") {
                        Ok(n) => n,
                        Err(e) => {
                            warn!("invalid domain name: {}", e);
                            return Measure::new(idx, u128::MAX, tag);
                        }
                    };
                    let query = Query::query(name, RecordType::A);
                    msg.add_query(query);
                    let mut rng = StdRng::from_entropy();
                    let id: u16 = rng.gen();
                    msg.set_id(id);
                    msg.set_op_code(OpCode::Query);
                    msg.set_message_type(MessageType::Query);
                    msg.set_recursion_desired(true);
                    let msg_buf = match msg.to_vec() {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("encode message to buffer failed: {}", e);
                            return Measure::new(idx, u128::MAX, tag);
                        }
                    };

                    let (mut recv, mut send) = socket.split();

                    if send.send_to(&msg_buf, &addr).await.is_err() {
                        return Measure::new(idx, u128::MAX - 2, tag);
                    }
                    let mut buf = vec![0u8; 1500];
                    match recv.recv_from(&mut buf).await {
                        Ok((n, _)) => {
                            let elapsed = tokio::time::Instant::now().duration_since(start);
                            debug!(
                                "received {} bytes udp health check response from {} in {} ms",
                                n,
                                &tag,
                                elapsed.as_millis()
                            );
                            Measure::new(idx, elapsed.as_millis(), tag)
                        }
                        Err(_) => Measure::new(idx, u128::MAX - 3, tag),
                    }
                }
                Err(_) => Measure::new(idx, u128::MAX, tag),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn health_check(
    network: Network,
    idx: usize,
    tag: String,
    h: AnyOutboundHandler,
    dns_client: SyncDnsClient,
    delay: u32,
    health_check_timeout: u64,
    health_check_attempts: u32,
    health_check_success_percentage: u32,
) -> Measure {
    debug!("health checking [{}] ({}) index ({})", &tag, &network, idx);
    let health_check_timeout = Duration::from_secs(health_check_timeout);
    let health_check_timeout_ms = health_check_timeout.as_millis();
    let mut attempts = Vec::new();
    for _ in 0..health_check_attempts {
        attempts.push(timeout(
            health_check_timeout,
            single_health_check(
                network,
                idx,
                tag.clone(),
                h.clone(),
                dns_client.clone(),
                delay,
            ),
        ));
    }
    let measures = futures::future::join_all(attempts).await;
    let measures = measures
        .into_iter()
        .map(|x| x.unwrap_or(Measure::new(idx, u128::MAX - 1, tag.clone())))
        .collect::<Vec<_>>();

    let n_success = measures
        .iter()
        .filter(|x| x.rtt < health_check_timeout_ms)
        .count();

    debug!(
        "{} out of {} successful checks for {} [{}]",
        n_success, health_check_attempts, &network, &tag
    );

    use std::ops::Div;
    let success_percentage = ((n_success as f32).div(health_check_attempts as f32) * 100.) as u32;
    if success_percentage < health_check_success_percentage {
        return Measure::new(idx, u128::MAX, tag);
    }

    let mean_rtt = measures
        .iter()
        .filter(|x| x.rtt < health_check_timeout_ms)
        .map(|x| x.rtt)
        .sum::<u128>()
        .div_euclid(n_success as u128);

    Measure::new(idx, mean_rtt, tag)
}

#[allow(clippy::too_many_arguments)]
async fn health_check_task(
    network: Network,
    schedule: Arc<Mutex<Vec<usize>>>,
    actors: Vec<AnyOutboundHandler>,
    dns_client: SyncDnsClient,
    check_interval: u32,
    failover: bool,
    last_resort: Option<AnyOutboundHandler>,
    health_check_timeout: u32,
    health_check_delay: u32,
    health_check_active: u32,
    health_check_prefers: Vec<String>,
    last_active: Arc<Mutex<Instant>>,
    is_first_health_check_done: Arc<AtomicBool>,
    wait_for_health_check: Option<Arc<Notify>>,
    health_check_attempts: u32,
    health_check_success_percentage: u32,
) {
    loop {
        let last_active = Instant::now()
            .duration_since(*last_active.lock().await)
            .as_secs();

        if last_active < health_check_active.into() {
            let mut checks = Vec::new();
            for (i, a) in actors.iter().enumerate() {
                let dns_client_cloned = dns_client.clone();
                checks.push(Box::pin(health_check(
                    network,
                    i,
                    a.tag().to_owned(),
                    a.clone(),
                    dns_client_cloned,
                    health_check_delay,
                    health_check_timeout as u64,
                    health_check_attempts,
                    health_check_success_percentage,
                )));
            }
            let mut measures = futures::future::join_all(checks).await;

            measures.sort_by(|a, b| a.rtt.cmp(&b.rtt));

            debug!("[{}] sorted health check results: {:?}", network, measures);

            if !health_check_prefers.is_empty() {
                // Find the minimal RTT among the preferred outbounds.
                let mut min_prefer_actor_rtt =
                    Duration::from_secs(health_check_timeout as u64).as_millis();
                for t in health_check_prefers.iter() {
                    if let Some(m) = measures.iter().find(|x| &x.tag == t) {
                        if m.rtt < min_prefer_actor_rtt {
                            min_prefer_actor_rtt = m.rtt;
                        }
                    }
                }

                fn is_preferred_actor(tag: &String, prefers: &[String]) -> bool {
                    prefers.iter().any(|x| x == tag)
                }

                // If an outbound is preferred, we subtract its RTT with the minimal
                // RTT, the result is the optimal preferred outbound has zero RTT.
                // The min RTT must not larger than the timeout value to avoid
                // preferring unavailable outbounds.
                for m in measures.iter_mut() {
                    if is_preferred_actor(&m.tag, &health_check_prefers) {
                        m.rtt -= min_prefer_actor_rtt;
                    }
                }

                measures.sort_by(|a, b| a.rtt.cmp(&b.rtt));

                debug!(
                    "[{}] sorted health check results after applying preferred actors: {:?}",
                    network, measures
                );
            }

            let priorities: Vec<String> = measures
                .iter()
                .map(|m| {
                    let mut repr = actors[m.idx].tag().to_owned();
                    repr.push('(');
                    repr.push_str(m.rtt.to_string().as_str());
                    repr.push(')');
                    repr
                })
                .collect();

            debug!(
                "[{}] priority after health check: {}",
                network,
                priorities.join(" > ")
            );

            let mut schedule = schedule.lock().await;
            schedule.clear();

            let all_failed = |measures: &Vec<Measure>| -> bool {
                let threshold = Duration::from_secs(health_check_timeout.into()).as_millis();
                for m in measures.iter() {
                    if m.rtt < threshold {
                        return false;
                    }
                }
                true
            };

            if !(last_resort.is_some() && all_failed(&measures)) {
                if !failover {
                    // if failover is disabled, put only 1 actor in schedule
                    schedule.push(measures[0].idx);
                    trace!("put {} in schedule", measures[0].idx);
                } else {
                    for m in measures {
                        schedule.push(m.idx);
                        trace!("put {} in schedule", m.idx);
                    }
                }
            }

            drop(schedule); // release
        } else {
            debug!("skip health check as no activities in {}s", last_active);
        }

        if !is_first_health_check_done.swap(true, Ordering::Relaxed) {
            debug!("initial health check done");
            if let Some(w) = wait_for_health_check.as_ref() {
                debug!("notify holding connections");
                w.notify_waiters();
            }
        }

        tokio::time::sleep(Duration::from_secs(check_interval as u64)).await;
    }
}
