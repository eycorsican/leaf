use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{proxy::*, session::Session};

use super::Method;

pub struct Handler {
    actors: Vec<AnyOutboundHandler>,
    method: Method,
    next: AtomicUsize,
}

impl Handler {
    pub fn new(actors: Vec<AnyOutboundHandler>, method: &str) -> Result<Self> {
        let (method, next) = match method {
            "random" => {
                let mut rng = StdRng::from_entropy();
                let i: usize = rng.gen_range(0..actors.len());
                (Method::Random, AtomicUsize::new(i))
            }
            "random-once" => {
                let mut rng = StdRng::from_entropy();
                let i: usize = rng.gen_range(0..actors.len());
                (Method::RandomOnce, AtomicUsize::new(i))
            }
            "rr" => (Method::RoundRobin, AtomicUsize::new(0)),
            _ => return Err(anyhow!("unknown method")),
        };
        Ok(Handler {
            actors,
            method,
            next,
        })
    }
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        let a = &self.actors[self.next.load(Ordering::Relaxed)];
        match a.datagram() {
            Ok(h) => return h.connect_addr(),
            _ => {
                if let Ok(h) = a.stream() {
                    return h.connect_addr();
                }
            }
        }
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        let a = &self.actors[self.next.load(Ordering::Relaxed)];
        a.datagram()
            .map(|x| x.transport_type())
            .unwrap_or(DatagramTransportType::Unknown)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        match self.method {
            Method::Random => {
                let current = self.next.load(Ordering::Relaxed);
                let mut rng = StdRng::from_entropy();
                let next: usize = rng.gen_range(0..self.actors.len());
                self.next.store(next, Ordering::Relaxed);
                self.actors[current]
                    .datagram()?
                    .handle(sess, transport)
                    .await
            }
            Method::RandomOnce => {
                let current = self.next.load(Ordering::Relaxed);
                self.actors[current]
                    .datagram()?
                    .handle(sess, transport)
                    .await
            }
            Method::RoundRobin => {
                let current = self.next.load(Ordering::Relaxed);
                let next = if current >= self.actors.len() - 1 {
                    0
                } else {
                    current + 1
                };
                self.next.store(next, Ordering::Relaxed);
                self.actors[current]
                    .datagram()?
                    .handle(sess, transport)
                    .await
            }
        }
    }
}
