use anyhow::{anyhow, Result};
use ipnet::IpNet;
use netconfig::Interface;
use std::{mem::transmute_copy, net::SocketAddr};
use windows::Win32::{
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, GetBestInterfaceEx, InitializeIpForwardEntry, IP_ADDRESS_PREFIX,
        MIB_IPFORWARD_ROW2,
    },
    Networking::WinSock::SOCKADDR_INET,
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

        unsafe { CreateIpForwardEntry2(&mut row) }.map_err((anyhow::Error::from))
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
