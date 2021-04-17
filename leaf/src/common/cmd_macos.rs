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
        .filter(|l| l.contains("gateway"))
        .next()
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
        .arg("get")
        .arg("-inet6")
        .arg("::2")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("gateway"))
        .next()
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() == 2);
    let res = cols[1].to_string();
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
        .filter(|l| l.contains("interface"))
        .next()
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

pub fn add_default_ipv4_route(gateway: Ipv4Addr, ifscope: Option<String>) -> Result<()> {
    if let Some(ifscope) = ifscope {
        Command::new("route")
            .arg("add")
            .arg("-inet")
            .arg("default")
            .arg(gateway.to_string())
            .arg("-ifscope")
            .arg(ifscope)
            .status()
            .expect("failed to execute command");
    } else {
        Command::new("route")
            .arg("add")
            .arg("-inet")
            .arg("default")
            .arg(gateway.to_string())
            .status()
            .expect("failed to execute command");
    };
    Ok(())
}

pub fn add_default_ipv6_route(gateway: String, ifscope: Option<String>) -> Result<()> {
    if let Some(ifscope) = ifscope {
        Command::new("route")
            .arg("add")
            .arg("-inet6")
            .arg("default")
            .arg(gateway)
            .arg("-ifscope")
            .arg(ifscope)
            .status()
            .expect("failed to execute command");
    } else {
        Command::new("route")
            .arg("add")
            .arg("-inet6")
            .arg("default")
            .arg(gateway)
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
