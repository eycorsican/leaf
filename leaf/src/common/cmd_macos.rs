use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use anyhow::Result;

pub fn get_default_ipv4_gateway() -> Result<String> {
    let out = Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("1")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .find(|l| l.contains("gateway"))
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() == 2);
    let res = cols[1].to_string();
    Ok(res)
}

pub fn get_default_ipv6_gateway() -> Result<String> {
    let out = Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("-inet6")
        .arg("::2")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .find(|l| l.contains("gateway"))
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() == 2);
    let parts: Vec<&str> = cols[1].split('%').map(str::trim).collect();
    assert!(!parts.is_empty());
    let res = parts[0].to_string();
    Ok(res)
}

pub fn get_default_interface() -> Result<String> {
    let out = Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("1")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .find(|l| l.contains("interface"))
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() == 2);
    let res = cols[1].to_string();
    Ok(res)
}

pub fn add_interface_ipv4_address(
    name: &str,
    addr: Ipv4Addr,
    gw: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<()> {
    Command::new("ifconfig")
        .arg(name)
        .arg("inet")
        .arg(addr.to_string())
        .arg("netmask")
        .arg(mask.to_string())
        .arg(gw.to_string())
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn add_interface_ipv6_address(name: &str, addr: Ipv6Addr, prefixlen: i32) -> Result<()> {
    Command::new("ifconfig")
        .arg(name)
        .arg("inet6")
        .arg(addr.to_string())
        .arg("prefixlen")
        .arg(prefixlen.to_string())
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn add_default_ipv4_route(gateway: Ipv4Addr, interface: String, primary: bool) -> Result<()> {
    if primary {
        Command::new("route")
            .arg("add")
            .arg("-inet")
            .arg("default")
            .arg(gateway.to_string())
            .status()
            .expect("failed to execute command");
    } else {
        Command::new("route")
            .arg("add")
            .arg("-inet")
            .arg("default")
            .arg(gateway.to_string())
            .arg("-ifscope")
            .arg(interface)
            .status()
            .expect("failed to execute command");
    };
    Ok(())
}

pub fn add_default_ipv6_route(gateway: Ipv6Addr, interface: String, primary: bool) -> Result<()> {
    // FIXME https://doc.rust-lang.org/std/net/struct.Ipv6Addr.html#method.is_global
    let gw = if (gateway.segments()[0] & 0xffc0) == 0xfe80 {
        format!("{}%{}", gateway.to_string(), interface)
    } else {
        gateway.to_string()
    };
    if primary {
        Command::new("route")
            .arg("add")
            .arg("-inet6")
            .arg("default")
            .arg(gw)
            .status()
            .expect("failed to execute command");
    } else {
        Command::new("route")
            .arg("add")
            .arg("-inet6")
            .arg("default")
            .arg(gw)
            .arg("-ifscope")
            .arg(interface)
            .status()
            .expect("failed to execute command");
    };
    Ok(())
}

pub fn delete_default_ipv4_route(ifscope: Option<String>) -> Result<()> {
    if let Some(ifscope) = ifscope {
        Command::new("route")
            .arg("delete")
            .arg("-inet")
            .arg("default")
            .arg("-ifscope")
            .arg(ifscope)
            .status()
            .expect("failed to execute command");
    } else {
        Command::new("route")
            .arg("delete")
            .arg("-inet")
            .arg("default")
            .status()
            .expect("failed to execute command");
    };
    Ok(())
}

pub fn delete_default_ipv6_route(ifscope: Option<String>) -> Result<()> {
    if let Some(ifscope) = ifscope {
        Command::new("route")
            .arg("delete")
            .arg("-inet6")
            .arg("default")
            .arg("-ifscope")
            .arg(ifscope)
            .status()
            .expect("failed to execute command");
    } else {
        Command::new("route")
            .arg("delete")
            .arg("-inet6")
            .arg("default")
            .status()
            .expect("failed to execute command");
    };
    Ok(())
}

pub fn get_ipv4_forwarding() -> Result<bool> {
    let out = Command::new("sysctl")
        .arg("-n")
        .arg("net.inet.ip.forwarding")
        .output()
        .expect("failed to execute command");
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    Ok(out
        .trim()
        .parse::<i8>()
        .expect("unexpected ip_forward value")
        != 0)
}

pub fn get_ipv6_forwarding() -> Result<bool> {
    let out = Command::new("sysctl")
        .arg("-n")
        .arg("net.inet6.ip6.forwarding")
        .output()
        .expect("failed to execute command");
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    Ok(out
        .trim()
        .parse::<i8>()
        .expect("unexpected ip_forward value")
        != 0)
}

pub fn set_ipv4_forwarding(val: bool) -> Result<()> {
    Command::new("sysctl")
        .arg("-w")
        .arg(format!(
            "net.inet.ip.forwarding={}",
            if val { "1" } else { "0" }
        ))
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn set_ipv6_forwarding(val: bool) -> Result<()> {
    Command::new("sysctl")
        .arg("-w")
        .arg(format!(
            "net.inet6.ip6.forwarding={}",
            if val { "1" } else { "0" }
        ))
        .status()
        .expect("failed to execute command");
    Ok(())
}
