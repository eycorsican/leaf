use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{app::SyncDnsClient, proxy::*, session::Session};

use super::Method;

pub struct Handler {
    actors: Vec<AnyOutboundHandler>,
    method: Method,
    next: Option<AtomicUsize>,
    dns_client: SyncDnsClient,
}

impl Handler {
    pub fn new(
        actors: Vec<AnyOutboundHandler>,
        dns_client: SyncDnsClient,
        method: &str,
    ) -> Result<Self> {
        let (method, next) = match method {
            "random" => (Method::Random, None),
            "rr" => (Method::RoundRobin, Some(AtomicUsize::new(0))),
            _ => return Err(anyhow!("unknown method")),
        };
        Ok(Handler {
            actors,
            method,
            next,
            dns_client,
        })
    }
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    type Stream = AnyStream;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _stream: Option<Self::Stream>,
    ) -> io::Result<Self::Stream> {
        match self.method {
            Method::Random => {
                let mut rng = StdRng::from_entropy();
                let i: usize = rng.gen_range(0..self.actors.len());
                let stream = crate::proxy::connect_tcp_outbound(
                    sess,
                    self.dns_client.clone(),
                    &self.actors[i],
                )
                .await?;
                TcpOutboundHandler::handle(self.actors[i].as_ref(), sess, stream).await
            }
            Method::RoundRobin => {
                let current = self.next.as_ref().unwrap().load(Ordering::Relaxed);
                let a = &self.actors[current];
                let next = if current >= self.actors.len() - 1 {
                    0
                } else {
                    current + 1
                };
                self.next.as_ref().unwrap().store(next, Ordering::Relaxed);
                let stream =
                    crate::proxy::connect_tcp_outbound(sess, self.dns_client.clone(), a).await?;
                TcpOutboundHandler::handle(a.as_ref(), sess, stream).await
            }
        }
    }
}
