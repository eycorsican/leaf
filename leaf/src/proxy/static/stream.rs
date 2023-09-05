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
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        let a = &self.actors[self.next.load(Ordering::Relaxed)];
        match a.stream() {
            Ok(h) => return h.connect_addr(),
            _ => match a.datagram() {
                Ok(h) => return h.connect_addr(),
                _ => (),
            },
        }
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        match self.method {
            Method::Random => {
                let current = self.next.load(Ordering::Relaxed);
                let mut rng = StdRng::from_entropy();
                let next: usize = rng.gen_range(0..self.actors.len());
                self.next.store(next, Ordering::Relaxed);
                self.actors[current]
                    .stream()?
                    .handle(sess, lhs, stream)
                    .await
            }
            Method::RandomOnce => {
                let current = self.next.load(Ordering::Relaxed);
                self.actors[current]
                    .stream()?
                    .handle(sess, lhs, stream)
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
                    .stream()?
                    .handle(sess, lhs, stream)
                    .await
            }
        }
    }
}
