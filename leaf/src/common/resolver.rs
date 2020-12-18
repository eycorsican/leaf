use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::TryFutureExt;

use crate::app::dns_client::DnsClient;

pub struct Resolver {
    ips: Vec<IpAddr>,
    port: u16,
}

impl Resolver {
    pub async fn new<'a>(
        client: Arc<DnsClient>,
        bind_addr: &'a SocketAddr,
        address: &'a str,
        port: &'a u16,
    ) -> Result<Self> {
        let mut ips = client
            .lookup_with_bind(String::from(address), bind_addr)
            .map_err(|e| anyhow!("lookup {} failed: {}", address, e))
            .await?;
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
