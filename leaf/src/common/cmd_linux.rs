use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use anyhow::Result;

pub fn get_default_ipv4_gateway() -> Result<String> {
    let out = Command::new("ip")
        .arg("route")
        .arg("get")
        .arg("1")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("via"))
        .next()
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() >= 3);
    let res = cols[2].to_string();
    Ok(res)
}

pub fn get_default_ipv6_gateway() -> Result<String> {
    let out = Command::new("ip")
        .arg("-6")
        .arg("route")
        .arg("get")
        .arg("::2")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("via"))
        .next()
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() >= 5);
    let res = cols[4].to_string();
    Ok(res)
}

pub fn get_default_ipv4_address() -> Result<String> {
    let out = Command::new("ip")
        .arg("route")
        .arg("get")
        .arg("1")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("via"))
        .next()
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() >= 7);
    let res = cols[6].to_string();
    Ok(res)
}

pub fn get_default_ipv6_address() -> Result<String> {
    let out = Command::new("ip")
        .arg("-6")
        .arg("route")
        .arg("get")
        .arg("::2")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("via"))
        .next()
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() >= 11);
    let res = cols[10].to_string();
    Ok(res)
}

pub fn get_default_interface() -> Result<String> {
    let out = Command::new("ip")
        .arg("route")
        .arg("get")
        .arg("1")
        .output()
        .expect("failed to execute command");
    assert!(out.status.success());
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let cols: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("via"))
        .next()
        .unwrap()
        .split_whitespace()
        .map(str::trim)
        .collect();
    assert!(cols.len() >= 5);
    let res = cols[4].to_string();
    Ok(res)
}

pub fn add_interface_ipv4_address(
    name: &str,
    addr: Ipv4Addr,
    gw: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<()> {
    Command::new("ip")
        .arg("addr")
        .arg("add")
        .arg(format!("{}/{}", addr.to_string(), mask.to_string()))
        .arg("dev")
        .arg(name.to_string())
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn add_interface_ipv6_address(name: &str, addr: Ipv6Addr, prefixlen: i32) -> Result<()> {
    Command::new("ip")
        .arg("-6")
        .arg("addr")
        .arg("add")
        .arg(format!("{}/{}", addr.to_string(), prefixlen))
        .arg("dev")
        .arg(name.to_string())
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn add_default_ipv4_route(gateway: Ipv4Addr, ifscope: Option<String>) -> Result<()> {
    if let Some(ifscope) = ifscope {
        Command::new("ip")
            .arg("route")
            .arg("add")
            .arg("default")
            .arg("via")
            .arg(gateway.to_string())
            .arg("dev")
            .arg(ifscope)
            .arg("table")
            .arg("default")
            .status()
            .expect("failed to execute command");
    } else {
        Command::new("ip")
            .arg("route")
            .arg("add")
            .arg("default")
            .arg("via")
            .arg(gateway.to_string())
            .arg("table")
            .arg("main")
            .status()
            .expect("failed to execute command");
    };
    Ok(())
}

pub fn add_default_ipv6_route(gateway: Ipv6Addr, ifscope: Option<String>) -> Result<()> {
    if let Some(ifscope) = ifscope {
        Command::new("ip")
            .arg("-6")
            .arg("route")
            .arg("add")
            .arg("default")
            .arg("via")
            .arg(gateway.to_string())
            .arg("dev")
            .arg(ifscope)
            .arg("table")
            .arg("default")
            .status()
            .expect("failed to execute command");
    } else {
        Command::new("ip")
            .arg("-6")
            .arg("route")
            .arg("add")
            .arg("default")
            .arg("via")
            .arg(gateway.to_string())
            .arg("table")
            .arg("main")
            .status()
            .expect("failed to execute command");
    };
    Ok(())
}

pub fn delete_default_ipv4_route(ifscope: Option<String>) -> Result<()> {
    if let Some(ifscope) = ifscope {
        Command::new("ip")
            .arg("route")
            .arg("del")
            .arg("default")
            .arg("table")
            .arg("default")
            .status()
            .expect("failed to execute command");
    } else {
        Command::new("ip")
            .arg("route")
            .arg("del")
            .arg("default")
            .arg("table")
            .arg("main")
            .status()
            .expect("failed to execute command");
    };
    Ok(())
}

pub fn delete_default_ipv6_route(ifscope: Option<String>) -> Result<()> {
    if let Some(ifscope) = ifscope {
        Command::new("ip")
            .arg("-6")
            .arg("route")
            .arg("del")
            .arg("default")
            .arg("table")
            .arg("default")
            .status()
            .expect("failed to execute command");
    } else {
        Command::new("ip")
            .arg("-6")
            .arg("route")
            .arg("del")
            .arg("default")
            .arg("table")
            .arg("main")
            .status()
            .expect("failed to execute command");
    };
    Ok(())
}

pub fn add_default_ipv4_rule(addr: Ipv4Addr) -> Result<()> {
    Command::new("ip")
        .arg("rule")
        .arg("add")
        .arg("from")
        .arg(addr.to_string())
        .arg("table")
        .arg("default")
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn add_default_ipv6_rule(addr: Ipv6Addr) -> Result<()> {
    Command::new("ip")
        .arg("-6")
        .arg("rule")
        .arg("add")
        .arg("from")
        .arg(addr.to_string())
        .arg("table")
        .arg("default")
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn delete_default_ipv4_rule(addr: Ipv4Addr) -> Result<()> {
    Command::new("ip")
        .arg("rule")
        .arg("del")
        .arg("from")
        .arg(addr.to_string())
        .arg("table")
        .arg("default")
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn delete_default_ipv6_rule(addr: Ipv6Addr) -> Result<()> {
    Command::new("ip")
        .arg("-6")
        .arg("rule")
        .arg("del")
        .arg("from")
        .arg(addr.to_string())
        .arg("table")
        .arg("default")
        .status()
        .expect("failed to execute command");
    Ok(())
}
