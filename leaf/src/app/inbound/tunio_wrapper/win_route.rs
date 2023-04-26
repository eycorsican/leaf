use anyhow::{anyhow, Result};
use ipnet::IpNet;
use netconfig::{sys::InterfaceExt, Interface};
use std::{
    mem::transmute_copy,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};
use windows::{
    core::{GUID, PWSTR},
    Win32::{
        NetworkManagement::IpHelper::{
            CreateIpForwardEntry2, GetBestInterfaceEx, InitializeIpForwardEntry,
            SetInterfaceDnsSettings, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
            DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2,
        },
        Networking::WinSock::SOCKADDR_INET,
    },
};

pub trait Routable {
    fn add_route(&self, dest: IpNet, next_hop: IpNet, metric: u32) -> Result<()>;
}

// add_route method adds a route to the interface. Corresponds to CreateIpForwardEntry2 function, with added splitDefault feature.
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createipforwardentry2)
impl Routable for Interface {
    fn add_route(&self, dest: IpNet, next_hop: IpNet, metric: u32) -> Result<()> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe {
            InitializeIpForwardEntry(&mut row);
        }

        row.InterfaceIndex = self.index().map_err(|err| anyhow!(err.to_string()))?;
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: SocketAddr::new(dest.addr(), 0).into(),
            PrefixLength: dest.prefix_len(),
        };
        row.NextHop = SocketAddr::new(next_hop.addr(), 0).into();
        row.Metric = metric;

        unsafe { CreateIpForwardEntry2(&mut row) }
            .to_hresult()
            .ok()
            .map_err(|e| anyhow::anyhow!(e))
    }
}

// GetBestInterfaceEx()
// See https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getbestinterfaceex
pub fn get_best_interface_ex(dest: IpNet) -> Result<Interface> {
    let mut if_index: u32 = 0;
    let sock_addr: SOCKADDR_INET = SocketAddr::new(dest.addr(), 0).into();

    let ret_val = unsafe { GetBestInterfaceEx(&mut transmute_copy(&sock_addr), &mut if_index) };
    if ret_val != 0 {
        return Err(anyhow!("best interface not found"));
    }
    Interface::try_from_index(if_index).map_err(|err| anyhow!("best interface not found"))
}

// SetInterfaceDnsSettings()
// See https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings
pub fn set_ipv4_dns(alias: &str, name_servers: Vec<Ipv4Addr>) -> Result<()> {
    let mut dns_wstr = name_servers
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(",")
        .encode_utf16()
        .collect::<Vec<u16>>();
    dns_wstr.push(0); // ensure ending with null

    let dns_settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_NAMESERVER as u64,
        NameServer: PWSTR::from_raw(dns_wstr.as_mut_ptr()),
        ..Default::default()
    };
    let guid = Interface::try_from_alias(&alias)
        .map_err(|err| anyhow!("interface not found: {}", err.to_string()))?
        .guid()
        .map_err(|err| anyhow!("interface guid not found: {}", err.to_string()))?;

    unsafe { SetInterfaceDnsSettings(GUID::from_u128(guid), &dns_settings) }
        .to_hresult()
        .ok()
        .map_err(|e| anyhow::anyhow!(e))
}

// SetInterfaceDnsSettings()
// See https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings
pub fn set_ipv6_dns(alias: &str, name_servers: Vec<Ipv6Addr>) -> Result<()> {
    let mut dns_wstr = name_servers
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(",")
        .encode_utf16()
        .collect::<Vec<u16>>();
    dns_wstr.push(0); // ensure ending with null

    let dns_settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: (DNS_SETTING_NAMESERVER | DNS_SETTING_IPV6) as u64,
        NameServer: PWSTR::from_raw(dns_wstr.as_mut_ptr()),
        ..Default::default()
    };
    let guid = Interface::try_from_alias(&alias)
        .map_err(|err| anyhow!("interface not found: {}", err.to_string()))?
        .guid()
        .map_err(|err| anyhow!("interface guid not found: {}", err.to_string()))?;

    unsafe { SetInterfaceDnsSettings(GUID::from_u128(guid), &dns_settings) }
        .to_hresult()
        .ok()
        .map_err(|e| anyhow::anyhow!(e))
}
