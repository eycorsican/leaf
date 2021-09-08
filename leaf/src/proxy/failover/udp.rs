use std::str::FromStr;
use std::sync::Arc;
use std::time;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use async_trait::async_trait;
use futures::future::BoxFuture;
use futures::future::{abortable, AbortHandle};
use futures::FutureExt;
use log::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;
use trust_dns_proto::{
    op::{header::MessageType, op_code::OpCode, query::Query, Message},
    rr::{record_type::RecordType, Name},
};

use crate::{
    app::SyncDnsClient,
    proxy::*,
    session::{Session, SocksAddr},
};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
    pub fail_timeout: u32,
    pub schedule: Arc<TokioMutex<Vec<usize>>>,
    pub health_check_task: TokioMutex<Option<BoxFuture<'static, ()>>>,
    pub dns_client: SyncDnsClient,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Measure(usize, u128); // (index, duration in millis)

async fn health_check_task(
    i: usize,
    h: AnyOutboundHandler,
    dns_client: SyncDnsClient,
    mut delay: Option<time::Duration>,
) -> Measure {
    if let Some(d) = delay.take() {
        tokio::time::sleep(d).await;
    }
    debug!("health checking udp for [{}] index [{}]", h.tag(), i);
    let measure = async move {
        let sess = Session {
            destination: SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)),
            ..Default::default()
        };
        let start = tokio::time::Instant::now();
        let transport = match crate::proxy::connect_udp_outbound(&sess, dns_client, &h).await {
            Ok(t) => t,
            Err(_) => return Measure(i, u128::MAX),
        };
        match UdpOutboundHandler::handle(h.as_ref(), &sess, transport).await {
            Ok(socket) => {
                let addr =
                    SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
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

                if send.send_to(&msg_buf, &addr).await.is_err() {
                    return Measure(i, u128::MAX - 2); // handshake is ok
                }
                let mut buf = [0u8; 1500];
                match recv.recv_from(&mut buf).await {
                    // handshake, write and read are ok
                    Ok(_) => {
                        let elapsed = tokio::time::Instant::now().duration_since(start);
                        Measure(i, elapsed.as_millis())
                    }
                    // handshake and write are ok
                    Err(_) => Measure(i, u128::MAX - 3),
                }
            }
            // handshake not ok
            Err(_) => Measure(i, u128::MAX),
        }
    };
    match timeout(time::Duration::from_secs(5), measure).await {
        Ok(m) => m,
        // timeout, better than handshake error
        Err(_) => Measure(i, u128::MAX - 1),
    }
}

impl Handler {
    pub fn new(
        actors: Vec<AnyOutboundHandler>,
        fail_timeout: u32,
        health_check: bool,
        check_interval: u32,
        failover: bool,
        dns_client: SyncDnsClient,
    ) -> (Self, Vec<AbortHandle>) {
        let mut abort_handles = Vec::new();
        let mut schedule = Vec::new();
        for i in 0..actors.len() {
            schedule.push(i);
        }
        let schedule = Arc::new(TokioMutex::new(schedule));

        let schedule2 = schedule.clone();
        let actors2 = actors.clone();
        let dns_client2 = dns_client.clone();
        let task = if health_check {
            let fut = async move {
                loop {
                    let mut checks = Vec::new();
                    let dns_client3 = dns_client2.clone();
                    let mut rng = StdRng::from_entropy();
                    for (i, a) in (&actors2).iter().enumerate() {
                        let dns_client4 = dns_client3.clone();
                        let delay: Option<time::Duration> = if actors2.len() >= 4 {
                            Some(time::Duration::from_millis(rng.gen_range(0..=1000) as u64))
                        } else {
                            None
                        };
                        checks.push(Box::pin(health_check_task(
                            i,
                            a.clone(),
                            dns_client4,
                            delay,
                        )));
                    }
                    let mut measures = futures::future::join_all(checks).await;

                    measures.sort_by(|a, b| a.1.cmp(&b.1));
                    trace!("sorted udp health check results:\n{:#?}", measures);

                    let priorities: Vec<String> = measures
                        .iter()
                        .map(|m| {
                            // construct tag(millis)
                            let mut repr = actors2[m.0].tag().to_owned();
                            repr.push('(');
                            repr.push_str(m.1.to_string().as_str());
                            repr.push(')');
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

                    tokio::time::sleep(time::Duration::from_secs(check_interval as u64)).await;
                }
            };
            let (abortable, abort_handle) = abortable(fut);
            abort_handles.push(abort_handle);
            let health_check_task: BoxFuture<'static, ()> = Box::pin(abortable.map(|_| ()));
            Some(health_check_task)
        } else {
            None
        };

        (
            Handler {
                actors,
                fail_timeout,
                schedule,
                health_check_task: TokioMutex::new(task),
                dns_client,
            },
            abort_handles,
        )
    }
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    type UStream = AnyStream;
    type Datagram = AnyOutboundDatagram;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Undefined
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<OutboundTransport<Self::UStream, Self::Datagram>>,
    ) -> io::Result<Self::Datagram> {
        if let Some(task) = self.health_check_task.lock().await.take() {
            tokio::spawn(task);
        }

        let schedule = self.schedule.lock().await.clone();

        for i in schedule {
            if i >= self.actors.len() {
                return Err(io::Error::new(io::ErrorKind::Other, "invalid actor index"));
            }

            debug!(
                "failover handles udp [{}] to [{}]",
                sess.destination,
                self.actors[i].tag()
            );

            let handle = async {
                let transport = crate::proxy::connect_udp_outbound(
                    sess,
                    self.dns_client.clone(),
                    &self.actors[i],
                )
                .await?;
                UdpOutboundHandler::handle(self.actors[i].as_ref(), sess, transport).await
            };
            match timeout(time::Duration::from_secs(self.fail_timeout as u64), handle).await {
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
