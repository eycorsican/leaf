use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use anyhow::{anyhow, Result};

use crate::app::inbound::tunio_wrapper::win_route::{Routable,get_best_interface_ex};
use crate::option;
use netconfig::sys::InterfaceExt;
use netconfig::Interface;
// TODO
// This source file is not completed yet

pub fn get_default_ipv4_gateway() -> Result<String> {
    // Get-NetRoute -DestinationPrefix "0.0.0.0/0" I asked new bing.
    let out = Command::new("powershell")
        .arg("-Command")
        .arg("Get-NetRoute")
        .arg("-DestinationPrefix")
        .arg("0.0.0.0/0")
        .output()
        .expect("failed to execute command");

    assert!(out.status.success());

    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let mut cols = out
        .lines()
        .filter(|l| l.contains("0.0.0.0"))
        .map(|l| {
            l.split_whitespace()
                .map(str::trim)
                .nth(2)
                .expect("can't find default route")
        })
        .filter(|s| {
            let addr: Result<Ipv4Addr, _> = s.parse(); // In case it's on-link
            addr.is_ok()
        });

    let addr: String = cols.next().expect("can't find default route").into();

    Ok(addr)
}

pub fn get_default_ipv6_gateway() -> Result<String> {
    // Get-NetRoute -DestinationPrefix "::/0"
    let out = Command::new("powershell")
        .arg("-Command")
        .arg("Get-NetRoute")
        .arg("-DestinationPrefix")
        .arg("::/0")
        .output()
        .expect("failed to execute command");

    assert!(out.status.success());

    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let mut cols = out
        .lines()
        .filter(|l| l.contains("::/0"))
        .map(|l| {
            l.split_whitespace()
                .map(str::trim)
                .nth(2)
                .expect("can't find default route")
        })
        .filter(|s| {
            // In case it's on-link
            let addr: Result<Ipv6Addr, _> = s.parse();
            addr.is_ok()
        });

    let addr: String = cols.next().expect("can't find default route").into();
    Ok(addr)
}

pub fn get_default_ipv4_address() -> Result<String> {
    Ok("".into())
}

pub fn get_default_ipv6_address() -> Result<String> {
    Ok("".into())
}

pub fn get_default_interface() -> Result<String> {
    let iface = get_best_interface_ex("0.0.0.0/32".parse().unwrap())?;

    let alias:String = iface.alias().map_err(|err|anyhow!("Default interface not found"))?.into();
    log::debug!("tun: default interface: {:?}", alias);
    Ok(alias)
}

pub fn add_interface_ipv4_address(
    name: &str,
    addr: Ipv4Addr,
    gw: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<()> {
    // Tun ip is configured in the creation process of tun device.
    Ok(())
}

pub fn add_interface_ipv6_address(name: &str, addr: Ipv6Addr, prefixlen: i32) -> Result<()> {
    Ok(())
}

pub fn add_default_ipv4_route(gateway: Ipv4Addr, interface: String, primary: bool) -> Result<()> {
    //Set-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias utun233 -RouteMetric 10
    if primary {
        // Fixme: use a better method to get the interface alias of tun
        let ifa = Interface::try_from_alias(&*option::DEFAULT_TUN_NAME)
            .map_err(|err| anyhow!(err.to_string()))?;
        ifa.add_route("0.0.0.0/0".parse()?, format!("0.0.0.0/0").parse()?, 0)?
    }
    Ok(())
}

pub fn add_default_ipv6_route(gateway: Ipv6Addr, interface: String, primary: bool) -> Result<()> {
    if primary {
        // Fixme: use a better method to get the interface alias of tun
        let ifa = Interface::try_from_alias(&*option::DEFAULT_TUN_NAME)
            .map_err(|err| anyhow!(err.to_string()))?;
        ifa.add_route("::/0".parse()?, format!("::/0").parse()?, 0)?
    }
    Ok(())
}

pub fn delete_default_ipv4_route(ifscope: Option<String>) -> Result<()> {
    Ok(())
}

pub fn delete_default_ipv6_route(ifscope: Option<String>) -> Result<()> {
    Ok(())
}

pub fn add_default_ipv4_rule(addr: Ipv4Addr) -> Result<()> {
    Ok(())
}

pub fn add_default_ipv6_rule(addr: Ipv6Addr) -> Result<()> {
    Ok(())
}

pub fn delete_default_ipv4_rule(addr: Ipv4Addr) -> Result<()> {
    Ok(())
}

pub fn delete_default_ipv6_rule(addr: Ipv6Addr) -> Result<()> {
    Ok(())
}

pub fn get_ipv4_forwarding() -> Result<bool> {
    Ok(false)
}

pub fn get_ipv6_forwarding() -> Result<bool> {
    Ok(false)
}

pub fn set_ipv4_forwarding(val: bool) -> Result<()> {
    Ok(())
}

pub fn set_ipv6_forwarding(val: bool) -> Result<()> {
    Ok(())
}

pub fn add_iptable_forward(interface: &str) -> Result<()> {
    Ok(())
}

pub fn delete_iptable_forward(interface: &str) -> Result<()> {
    Ok(())
}
