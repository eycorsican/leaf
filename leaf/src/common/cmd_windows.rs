use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use anyhow::Result;

// TODO
// This source file is not completed yes 

pub fn get_default_ipv4_gateway() -> Result<String> {
    Ok("".into())
}

pub fn get_default_ipv6_gateway() -> Result<String> {
    Ok("".into())
}

pub fn get_default_ipv4_address() -> Result<String> {
    Ok("".into())
}

pub fn get_default_ipv6_address() -> Result<String> {
    Ok("".into())
}

pub fn get_default_interface() -> Result<String> {
    Ok("".into())
}

pub fn add_interface_ipv4_address(
    name: &str,
    addr: Ipv4Addr,
    gw: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<()> {
    Ok(())
}

pub fn add_interface_ipv6_address(name: &str, addr: Ipv6Addr, prefixlen: i32) -> Result<()> {
    Ok(())
}

pub fn add_default_ipv4_route(gateway: Ipv4Addr, interface: String, primary: bool) -> Result<()> {
    Ok(())
}

pub fn add_default_ipv6_route(gateway: Ipv6Addr, interface: String, primary: bool) -> Result<()> { 
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
    Ok(true)
}

pub fn get_ipv6_forwarding() -> Result<bool> {
    Ok(true)
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
