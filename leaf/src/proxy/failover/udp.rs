use std::str::FromStr;
use std::sync::Arc;
use std::time;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use async_trait::async_trait;
use futures::future::BoxFuture;
use log::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;
use trust_dns_proto::{
    op::{header::MessageType, op_code::OpCode, query::Query, Message},
    rr::{record_type::RecordType, Name},
};

use crate::{
    proxy::{ProxyDatagram, ProxyHandler, ProxyStream, ProxyUdpHandler, UdpTransportType},
    session::{Session, SocksAddr},
};

pub struct Handler {
    pub actors: Vec<Arc<dyn ProxyHandler>>,
    pub fail_timeout: u32,
    pub schedule: Arc<TokioMutex<Vec<usize>>>,
    pub health_check_task: TokioMutex<Option<BoxFuture<'static, ()>>>,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Measure(usize, u128); // (index, duration in millis)

impl Handler {
    pub fn new(
        actors: Vec<Arc<dyn ProxyHandler>>,
        fail_timeout: u32,
        health_check: bool,
        check_interval: u32,
        failover: bool,
    ) -> Self {
        let mut schedule = Vec::new();
        for i in 0..actors.len() {
            schedule.push(i);
        }
        let schedule = Arc::new(TokioMutex::new(schedule));

        let schedule2 = schedule.clone();
        let actors2 = actors.clone();
        let task = if health_check {
            let health_check_task: BoxFuture<'static, ()> = Box::pin(async move {
                loop {
                    let mut measures: Vec<Measure> = Vec::new();
                    for (i, a) in (&actors2).iter().enumerate() {
                        debug!("health checking udp for [{}] index [{}]", a.tag(), i);
                        let single_measure = async move {
                            let sess = Session {
                                source: None,
                                destination: SocksAddr::Ip(SocketAddr::new(
                                    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                                    53,
                                )),
                            };
                            let start = tokio::time::Instant::now();
                            match a.connect(&sess, None, None).await {
                                Ok(socket) => {
                                    let addr =
                                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
                                    let mut msg = Message::new();
                                    let name = match Name::from_str("www.google.com.") {
                                        Ok(n) => n,
                                        Err(e) => {
                                            warn!("invalid domain name: {}", e);
                                            return Measure(i, u128::MAX);
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
                                            return Measure(i, u128::MAX);
                                        }
                                    };

                                    let (mut recv, mut send) = socket.split();

                                    if let Err(_) = send.send_to(&msg_buf, &addr).await {
                                        return Measure(i, u128::MAX - 2); // handshake is ok
                                    }
                                    let mut buf = [0u8; 1500];
                                    match recv.recv_from(&mut buf).await {
                                        // handshake, write and read are ok
                                        Ok(_) => {
                                            let elapsed =
                                                tokio::time::Instant::now().duration_since(start);
                                            return Measure(i, elapsed.as_millis());
                                        }
                                        // handshake and write are ok
                                        Err(_) => {
                                            return Measure(i, u128::MAX - 3);
                                        }
                                    }
                                }
                                // handshake not ok
                                Err(_) => {
                                    return Measure(i, u128::MAX);
                                }
                            }
                        };
                        match timeout(time::Duration::from_secs(10), single_measure).await {
                            Ok(m) => {
                                measures.push(m);
                            }
                            Err(_) => {
                                measures.push(Measure(i, u128::MAX - 1)); // timeout, better than handshake error
                            }
                        }
                    }

                    measures.sort_by(|a, b| a.1.cmp(&b.1));
                    trace!("sorted udp health check results:\n{:#?}", measures);

                    let priorities: Vec<String> = measures
                        .iter()
                        .map(|m| {
                            // construct tag(millis)
                            let mut repr = actors2[m.0].tag().to_owned();
                            repr.push_str("(");
                            repr.push_str(m.1.to_string().as_str());
                            repr.push_str(")");
                            repr
                        })
                        .collect();
                    debug!(
                        "udp priority after health check: {}",
                        priorities.join(" > ")
                    );

                    let mut schedule = schedule2.lock().await;
                    schedule.clear();
                    if !failover {
                        // if failover is disabled, put only 1 actor in schedule
                        schedule.push(measures[0].0);
                        trace!("put {} in schedule", measures[0].0);
                    } else {
                        for m in measures {
                            schedule.push(m.0);
                            trace!("put {} in schedule", m.0);
                        }
                    }

                    drop(schedule); // drop the guard, to release the lock

                    tokio::time::delay_for(time::Duration::from_secs(check_interval as u64)).await;
                }
            });
            Some(health_check_task)
        } else {
            None
        };

        Handler {
            actors,
            fail_timeout,
            schedule,
            health_check_task: TokioMutex::new(task),
        }
    }
}

#[async_trait]
impl ProxyUdpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn udp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        None
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Unknown
    }

    async fn connect<'a>(
        &'a self,
        sess: &'a Session,
        _datagram: Option<Box<dyn ProxyDatagram>>,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyDatagram>> {
        if self.health_check_task.lock().await.is_some() {
            if let Some(task) = self.health_check_task.lock().await.take() {
                tokio::spawn(task);
            }
        }

        let schedule = self.schedule.lock().await.clone();

        for i in schedule {
            if i >= self.actors.len() {
                return Err(io::Error::new(io::ErrorKind::Other, "invalid actor index"));
            }

            match timeout(
                time::Duration::from_secs(self.fail_timeout as u64),
                (&self.actors[i]).connect(sess, None, None),
            )
            .await
            {
                // return before timeout
                Ok(t) => match t {
                    // return ok
                    Ok(v) => return Ok(v),
                    // return err
                    Err(_) => continue,
                },
                // after timeout
                Err(_) => continue,
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Other,
            "all outbound attempts failed",
        ))
    }
}
