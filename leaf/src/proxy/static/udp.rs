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
        match self.method {
            Method::Random => {
                let mut rng = StdRng::from_entropy();
                let i: usize = rng.gen_range(0..self.actors.len());
                let t = crate::proxy::connect_udp_outbound(
                    sess,
                    self.dns_client.clone(),
                    &self.actors[i],
                )
                .await?;
                UdpOutboundHandler::handle(self.actors[i].as_ref(), sess, t).await
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
                let t =
                    crate::proxy::connect_udp_outbound(sess, self.dns_client.clone(), a).await?;
                UdpOutboundHandler::handle(a.as_ref(), sess, t).await
            }
        }
    }
}
