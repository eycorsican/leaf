use super::common;
use super::option;

pub struct NetInfo {
    pub default_ipv4_gateway: Option<String>,
    pub default_ipv6_gateway: Option<String>,
    pub default_ipv4_address: Option<String>,
    pub default_ipv6_address: Option<String>,
    pub default_interface: Option<String>,
}

impl Default for NetInfo {
    fn default() -> Self {
        Self {
            default_ipv4_gateway: None,
            default_ipv6_gateway: None,
            default_ipv4_address: None,
            default_ipv6_address: None,
            default_interface: None,
        }
    }
}

pub fn get_net_info() -> NetInfo {
    let iface = common::cmd::get_default_interface().unwrap();
    std::env::set_var("OUTBOUND_INTERFACE", iface.clone());

    let ipv4_gw = common::cmd::get_default_ipv4_gateway().unwrap();
    let ipv6_gw = if *option::ENABLE_IPV6 {
        Some(common::cmd::get_default_ipv6_gateway().unwrap())
    } else {
        None
    };

    let all_interfaces = pnet_datalink::interfaces();
    let ipv4_addr = if let Some(ifa) = all_interfaces
        .iter()
        .find(|ifa| ifa.name == iface && !ifa.ips.is_empty())
    {
        if let Some(ipn) = ifa.ips.iter().find(|ipn| ipn.is_ipv4()) {
            Some(ipn.ip().to_string())
        } else {
            None
        }
    } else {
        None
    };
    let ipv6_addr = if *option::ENABLE_IPV6 {
        if let Some(ifa) = all_interfaces
            .iter()
            .find(|ifa| ifa.name == iface && !ifa.ips.is_empty())
        {
            if let Some(ipn) = ifa.ips.iter().find(|ipn| ipn.is_ipv6()) {
                Some(ipn.ip().to_string())
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    NetInfo {
        default_ipv4_gateway: Some(ipv4_gw),
        default_ipv6_gateway: ipv6_gw,
        default_ipv4_address: ipv4_addr,
        default_ipv6_address: ipv6_addr,
        default_interface: Some(iface),
    }
}

pub fn post_tun_creation_setup(net_info: &NetInfo) {
    if let NetInfo {
        default_ipv4_gateway: Some(ipv4_gw),
        default_ipv6_gateway: ipv6_gw,
        default_ipv4_address: ipv4_addr,
        default_ipv6_address: ipv6_addr,
        default_interface: Some(iface),
    } = net_info
    {
        use std::net::{Ipv4Addr, Ipv6Addr};
        common::cmd::add_interface_ipv4_address(
            option::DEFAULT_TUN_NAME,
            option::DEFAULT_TUN_IPV4_ADDR.parse::<Ipv4Addr>().unwrap(),
            option::DEFAULT_TUN_IPV4_GW.parse::<Ipv4Addr>().unwrap(),
            option::DEFAULT_TUN_IPV4_MASK.parse::<Ipv4Addr>().unwrap(),
        )
        .unwrap();
        common::cmd::delete_default_ipv4_route(None).unwrap();
        common::cmd::delete_default_ipv4_route(Some(iface.clone())).unwrap();
        common::cmd::add_default_ipv4_route(
            option::DEFAULT_TUN_IPV4_GW.parse::<Ipv4Addr>().unwrap(),
            None,
        )
        .unwrap();
        common::cmd::add_default_ipv4_route(
            ipv4_gw.parse::<Ipv4Addr>().unwrap(),
            Some(iface.clone()),
        )
        .unwrap();

        #[cfg(target_os = "linux")]
        {
            if let Some(a) = ipv4_addr {
                common::cmd::add_default_ipv4_rule(a.parse::<Ipv4Addr>().unwrap()).unwrap();
            }
        }

        if *option::ENABLE_IPV6 {
            if let Some(ipv6_gw) = ipv6_gw {
                common::cmd::add_interface_ipv6_address(
                    option::DEFAULT_TUN_NAME,
                    option::DEFAULT_TUN_IPV6_ADDR.parse::<Ipv6Addr>().unwrap(),
                    option::DEFAULT_TUN_IPV6_PREFIXLEN,
                )
                .unwrap();
                common::cmd::delete_default_ipv6_route(None).unwrap();
                common::cmd::delete_default_ipv6_route(Some(iface.clone())).unwrap();
                common::cmd::add_default_ipv6_route(
                    option::DEFAULT_TUN_IPV6_GW.parse::<Ipv6Addr>().unwrap(),
                    None,
                )
                .unwrap();
                common::cmd::add_default_ipv6_route(
                    ipv6_gw.parse::<Ipv6Addr>().unwrap(),
                    Some(iface.clone()),
                )
                .unwrap();
            }

            #[cfg(target_os = "linux")]
            {
                if let Some(a) = ipv6_addr {
                    common::cmd::add_default_ipv6_rule(a.parse::<Ipv6Addr>().unwrap()).unwrap();
                }
            }
        }
    }
}

pub fn post_tun_completion_setup(net_info: &NetInfo) {
    if let NetInfo {
        default_ipv4_gateway: Some(ipv4_gw),
        default_ipv6_gateway: ipv6_gw,
        default_ipv4_address: ipv4_addr,
        default_ipv6_address: ipv6_addr,
        default_interface: Some(iface),
    } = &net_info
    {
        use std::net::{Ipv4Addr, Ipv6Addr};
        common::cmd::delete_default_ipv4_route(None).unwrap();
        common::cmd::delete_default_ipv4_route(Some(iface.clone())).unwrap();
        common::cmd::add_default_ipv4_route(ipv4_gw.parse::<Ipv4Addr>().unwrap(), None).unwrap();
        #[cfg(target_os = "linux")]
        {
            if let Some(a) = ipv4_addr {
                common::cmd::delete_default_ipv4_rule(a.parse::<Ipv4Addr>().unwrap()).unwrap();
            }
        }

        if *option::ENABLE_IPV6 {
            if let Some(ipv6_gw) = ipv6_gw {
                common::cmd::delete_default_ipv6_route(None).unwrap();
                common::cmd::delete_default_ipv6_route(Some(iface.clone())).unwrap();
                common::cmd::add_default_ipv6_route(ipv6_gw.parse::<Ipv6Addr>().unwrap(), None)
                    .unwrap();
            }

            #[cfg(target_os = "linux")]
            {
                if let Some(a) = ipv6_addr {
                    common::cmd::delete_default_ipv6_rule(a.parse::<Ipv6Addr>().unwrap()).unwrap();
                }
            }
        }
    }
}
