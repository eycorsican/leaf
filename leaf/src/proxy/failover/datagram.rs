use std::{io, sync::Arc, time::Duration};

use async_trait::async_trait;
use futures::future::BoxFuture;
use futures::future::{abortable, AbortHandle};
use futures::FutureExt;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, trace};

use crate::{app::SyncDnsClient, proxy::*, session::*};

pub struct Handler {
    actors: Vec<AnyOutboundHandler>,
    fail_timeout: u32,
    schedule: Arc<Mutex<Vec<usize>>>,
    health_check_task: Mutex<Option<BoxFuture<'static, ()>>>,
    last_resort: Option<AnyOutboundHandler>,
    dns_client: SyncDnsClient,
    last_active: Arc<Mutex<Instant>>,
}

impl Handler {
    pub fn new(
        actors: Vec<AnyOutboundHandler>,
        fail_timeout: u32,
        health_check: bool,
        check_interval: u32,
        failover: bool,
        last_resort: Option<AnyOutboundHandler>,
        health_check_timeout: u32,
        health_check_delay: u32,
        health_check_active: u32,
        dns_client: SyncDnsClient,
    ) -> (Self, Vec<AbortHandle>) {
        let mut abort_handles = Vec::new();
        let schedule = Arc::new(Mutex::new((0..actors.len()).collect()));
        let last_active = Arc::new(Mutex::new(Instant::now()));

        let task = if health_check {
            let (abortable, abort_handle) = abortable(super::health_check_task(
                Network::Udp,
                schedule.clone(),
                actors.clone(),
                dns_client.clone(),
                check_interval,
                failover,
                last_resort.clone(),
                health_check_timeout,
                health_check_delay,
                health_check_active,
                last_active.clone(),
            ));
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
                health_check_task: Mutex::new(task),
                last_resort,
                dns_client,
                last_active,
            },
            abort_handles,
        )
    }
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        *self.last_active.lock().await = Instant::now();

        if let Some(task) = self.health_check_task.lock().await.take() {
            tokio::spawn(task);
        }

        let schedule = self.schedule.lock().await.clone();

        // Use the last resort outbound if all outbounds have failed in
        // the last health check.
        if schedule.is_empty() && self.last_resort.is_some() {
            let a = &self.last_resort.as_ref().unwrap();
            debug!(
                "failover handles udp [{}] to last resort [{}]",
                sess.destination,
                a.tag()
            );
            return a
                .datagram()?
                .handle(
                    sess,
                    connect_datagram_outbound(sess, self.dns_client.clone(), a).await?,
                )
                .await;
        }

        for i in schedule {
            if i >= self.actors.len() {
                return Err(io::Error::new(io::ErrorKind::Other, "invalid actor index"));
            }

            let a = &self.actors[i];

            debug!(
                "[{}] handles [{}:{}] to [{}]",
                a.tag(),
                sess.network,
                sess.destination,
                a.tag()
            );

            let try_outbound = async move {
                a.datagram()?
                    .handle(
                        sess,
                        connect_datagram_outbound(sess, self.dns_client.clone(), a).await?,
                    )
                    .await
            };

            match timeout(Duration::from_secs(self.fail_timeout as u64), try_outbound).await {
                Ok(t) => match t {
                    Ok(v) => return Ok(v),
                    Err(e) => {
                        trace!(
                            "[{}] failed to handle [{}:{}]: {}",
                            a.tag(),
                            sess.network,
                            sess.destination,
                            e,
                        );
                        continue;
                    }
                },
                Err(e) => {
                    trace!(
                        "[{}] failed to handle [{}:{}]: {}",
                        a.tag(),
                        sess.network,
                        sess.destination,
                        e,
                    );
                    continue;
                }
            }
        }

        // Use the last resort outbound if all scheduled outbounds have
        // failed.
        if let Some(a) = self.last_resort.as_ref() {
            debug!(
                "failover handles udp [{}] to last resort [{}]",
                sess.destination,
                a.tag()
            );
            return a
                .datagram()?
                .handle(
                    sess,
                    connect_datagram_outbound(sess, self.dns_client.clone(), a).await?,
                )
                .await;
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "all outbound attempts failed",
        ))
    }
}
