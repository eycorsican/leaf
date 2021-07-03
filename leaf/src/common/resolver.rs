use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, Result};
use futures::TryFutureExt;

use crate::app::SyncDnsClient;

pub struct Resolver {
    ips: Vec<IpAddr>,
    port: u16,
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
                .lookup(address)
                .map_err(|e| anyhow!("lookup {} failed: {}", address, e))
                .await?
        };
        ips.reverse();
        Ok(Resolver {
            ips,
            port: port.to_owned(),
        })
    }
}

impl Iterator for Resolver {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.ips.pop().map(|ip| SocketAddr::new(ip, self.port))
    }
}
