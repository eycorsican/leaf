use std::net::{SocketAddr, SocketAddrV6};

use anyhow::{anyhow, Result};

pub fn parse_bind_addr(bind: &str) -> Result<SocketAddr> {
    let mut split = bind.split('%');
    let ip_addr = split.next().ok_or_else(|| anyhow!("Empty bind address"))?;
    match split.next() {
        Some(scope_id) => {
            let _: Option<()> = split
                .next()
                .map(|_| Err(anyhow!("Unexpected % in bind address")))
                .transpose()?;
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip_addr.parse()?,
                0,
                0,
                scope_id.parse()?,
            )))
        }
        None => Ok(SocketAddr::new(ip_addr.parse()?, 0)),
    }
}
