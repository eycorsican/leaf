use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use futures::TryFutureExt;
use rand::prelude::SliceRandom;
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::app::SyncDnsClient;
use crate::proxy::DialOrder;

pub struct Resolver {
    addrs: Vec<SocketAddr>,
}

impl Resolver {
    pub async fn new<'a>(
        dns_client: SyncDnsClient,
        address: &'a String,
        port: &'a u16,
    ) -> Result<Self> {
        let mut ips = {
            dns_client
                .read()
                .await
                .direct_lookup(address)
                .map_err(|e| anyhow!("lookup {} failed: {}", address, e))
                .await?
        };
        match *crate::option::OUTBOUND_DIAL_ORDER {
            DialOrder::Ordered => ips.reverse(),
            DialOrder::Random => ips.shuffle(&mut StdRng::from_entropy()),
            DialOrder::PartialRandom => {
                let head = ips.remove(0);
                ips.shuffle(&mut StdRng::from_entropy());
                ips.push(head);
            }
        }
        Ok(Resolver {
            addrs: ips.into_iter().map(|x| SocketAddr::new(x, *port)).collect(),
        })
    }
}

impl Iterator for Resolver {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.addrs.pop()
    }
}
