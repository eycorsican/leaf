use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn get_default_interface_ips() -> String {
    let adapters = match ipconfig::get_adapters() {
        Ok(adapters) => adapters,
        Err(_) => return String::new(),
    };

    let candidate = adapters.iter()
        .find(|a| !a.gateways().is_empty());

    let adapter = match candidate {
        Some(adapter) => adapter,
        None => return String::new(),
    };

    let (mut ipv4, mut ipv6) = (None, None);

    for ip in adapter.ip_addresses() {
        match ip {
            IpAddr::V4(v4) if !is_ipv4_link_local(v4) && ipv4.is_none() => {
                ipv4 = Some(v4.to_string());
            }
            IpAddr::V6(v6) if !is_ipv6_link_local(v6) && ipv6.is_none() => {
                ipv6 = Some(v6.to_string());
            }
            _ => {}
        }

        if ipv4.is_some() && ipv6.is_some() {
            break;
        }
    }

    match (ipv4, ipv6) {
        (Some(v4), Some(v6)) => format!("{},{}", v4, v6),
        (Some(v4), None) => v4,
        (None, Some(v6)) => v6,
        (None, None) => String::new(),
    }
}

fn is_ipv4_link_local(addr: &Ipv4Addr) -> bool {
    addr.octets()[0] == 169 && addr.octets()[1] == 254
}

fn is_ipv6_link_local(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}
