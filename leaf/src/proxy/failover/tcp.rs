use std::{io, sync::Arc, time};

use async_trait::async_trait;
use futures::future::BoxFuture;
use futures::future::{abortable, AbortHandle};
use futures::FutureExt;
use log::*;
use lru_time_cache::LruCache;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;

use crate::{
    proxy::{OutboundConnect, OutboundHandler, ProxyStream, TcpOutboundHandler},
    session::{Session, SocksAddr},
};

pub struct Handler {
    pub actors: Vec<Arc<dyn OutboundHandler>>,
    pub fail_timeout: u32,
    pub schedule: Arc<TokioMutex<Vec<usize>>>,
    pub health_check_task: TokioMutex<Option<BoxFuture<'static, ()>>>,
    pub cache: Option<Arc<TokioMutex<LruCache<String, usize>>>>,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Measure(usize, u128); // (index, duration in millis)

impl Handler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actors: Vec<Arc<dyn OutboundHandler>>,
        fail_timeout: u32, // in secs
        health_check: bool,
        check_interval: u32, // in secs
        failover: bool,
        fallback_cache: bool,
        cache_size: usize,
        cache_timeout: u64, // in minutes
    ) -> (Self, Vec<AbortHandle>) {
        let mut abort_handles = Vec::new();
        let mut schedule = Vec::new();
        for i in 0..actors.len() {
            schedule.push(i);
        }
        let schedule = Arc::new(TokioMutex::new(schedule));

        let schedule2 = schedule.clone();
        let actors2 = actors.clone();
        let task = if health_check {
            let fut = async move {
                loop {
                    let mut measures: Vec<Measure> = Vec::new();
                    for (i, a) in (&actors2).iter().enumerate() {
                        debug!("health checking tcp for [{}] index [{}]", a.tag(), i);
                        let single_measure = async move {
                            let sess = Session {
                                destination: SocksAddr::Domain("www.google.com".to_string(), 80),
                                ..Default::default()
                            };
                            let start = tokio::time::Instant::now();
                            match a.handle_tcp(&sess, None).await {
                                Ok(mut stream) => {
                                    if stream.write_all(b"HEAD / HTTP/1.1\r\n\r\n").await.is_err() {
                                        return Measure(i, u128::MAX - 2); // handshake is ok
                                    }
                                    let mut buf = vec![0u8; 1];
                                    match stream.read_exact(&mut buf).await {
                                        // handshake, write and read are ok
                                        Ok(_) => {
                                            let elapsed =
                                                tokio::time::Instant::now().duration_since(start);
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
                    trace!("sorted tcp health check results:\n{:#?}", measures);

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
                        "tcp priority after health check: {}",
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

        let cache = if fallback_cache {
            Some(Arc::new(TokioMutex::new(
                LruCache::with_expiry_duration_and_capacity(
                    time::Duration::from_secs(cache_timeout * 60),
                    cache_size,
                ),
            )))
        } else {
            None
        };

        (
            Handler {
                actors,
                fail_timeout,
                schedule,
                health_check_task: TokioMutex::new(task),
                cache,
            },
            abort_handles,
        )
    }
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        if let Some(task) = self.health_check_task.lock().await.take() {
            tokio::spawn(task);
        }

        if let Some(cache) = &self.cache {
            // Try the cached actor first if exists.
            let cache_key = sess.destination.to_string();
            if let Some(idx) = cache.lock().await.get(&cache_key) {
                debug!(
                    "failover handles tcp [{}] to cached [{}]",
                    sess.destination,
                    self.actors[*idx].tag()
                );
                // TODO Remove the entry immediately if timeout or fail?
                let task = timeout(
                    time::Duration::from_secs(self.fail_timeout as u64),
                    (&self.actors[*idx]).handle_tcp(sess, None),
                );
                if let Ok(Ok(v)) = task.await {
                    return Ok(v);
                }
            };
        }

        let schedule = self.schedule.lock().await.clone();

        for (sche_idx, actor_idx) in schedule.into_iter().enumerate() {
            if actor_idx >= self.actors.len() {
                return Err(io::Error::new(io::ErrorKind::Other, "invalid actor index"));
            }

            debug!(
                "failover handles tcp [{}] to [{}]",
                sess.destination,
                self.actors[actor_idx].tag()
            );
            match timeout(
                time::Duration::from_secs(self.fail_timeout as u64),
                (&self.actors[actor_idx]).handle_tcp(sess, None),
            )
            .await
            {
                // return before timeout
                Ok(t) => match t {
                    Ok(v) => {
                        // Only cache for fallback actors.
                        if let Some(cache) = &self.cache {
                            if sche_idx > 0 {
                                let cache_key = sess.destination.to_string();
                                trace!(
                                    "failover inserts {} -> {} to cache",
                                    cache_key,
                                    self.actors[actor_idx].tag()
                                );
                                cache.lock().await.insert(cache_key, actor_idx);
                            }
                        }
                        return Ok(v);
                    }
                    Err(e) => {
                        trace!(
                            "[{}] failed to handle [{}]: {}",
                            self.actors[actor_idx].tag(),
                            sess.destination,
                            e,
                        );
                        continue;
                    }
                },
                Err(e) => {
                    trace!(
                        "[{}] failed to handle [{}]: {}",
                        self.actors[actor_idx].tag(),
                        sess.destination,
                        e,
                    );
                    continue;
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Other,
            "all outbound attempts failed",
        ))
    }
}
