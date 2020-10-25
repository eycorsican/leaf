use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::TryFutureExt;

use crate::common::dns_client::DnsClient;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[tokio::test]
    async fn test_resolver() {
        let dns_client = Arc::new(DnsClient::default());
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let address = "localhost".to_string();
        let port: u16 = 443;
        let resolver = Resolver::new(dns_client, &bind_addr, &address, &port)
            .await
            .unwrap();
        let addrs: Vec<SocketAddr> = resolver.collect();
        assert!(addrs.len() > 0);
        // let addr = addrs.pop().unwrap();
        // let result = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        // assert!(
        //     addr == result,
        //     "resolved unexpected addr {} != {} for {}",
        //     &addr,
        //     &result,
        //     &address
        // );
    }
}
