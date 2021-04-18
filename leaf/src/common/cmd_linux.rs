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

pub fn add_default_ipv4_route(gateway: Ipv4Addr, interface: String, primary: bool) -> Result<()> {
    if primary {
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
    } else {
        Command::new("ip")
            .arg("route")
            .arg("add")
            .arg("default")
            .arg("via")
            .arg(gateway.to_string())
            .arg("dev")
            .arg(interface)
            .arg("table")
            .arg("default")
            .status()
            .expect("failed to execute command");
    };
    Ok(())
}

pub fn add_default_ipv6_route(gateway: Ipv6Addr, interface: String, primary: bool) -> Result<()> {
    if primary {
        Command::new("ip")
            .arg("-6")
            .arg("route")
            .arg("add")
            .arg("default")
            .arg("via")
            .arg(gateway.to_string())
            .arg("dev")
            .arg(interface)
            .arg("table")
            .arg("main")
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
            .arg("dev")
            .arg(interface)
            .arg("table")
            .arg("default")
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

pub fn get_ipv4_forwarding() -> Result<bool> {
    let out = Command::new("sysctl")
        .arg("-n")
        .arg("net.ipv4.ip_forward")
        .output()
        .expect("failed to execute command");
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let res = if out
        .trim()
        .parse::<i8>()
        .expect("unexpected ip_forward value")
        == 0
    {
        false
    } else {
        true
    };
    Ok(res)
}

pub fn get_ipv6_forwarding() -> Result<bool> {
    let out = Command::new("sysctl")
        .arg("-n")
        .arg("net.ipv6.conf.all.forwarding")
        .output()
        .expect("failed to execute command");
    let out = String::from_utf8_lossy(&out.stdout).to_string();
    let res = if out
        .trim()
        .parse::<i8>()
        .expect("unexpected ip_forward value")
        == 0
    {
        false
    } else {
        true
    };
    Ok(res)
}

pub fn set_ipv4_forwarding(val: bool) -> Result<()> {
    Command::new("sysctl")
        .arg("-w")
        .arg(format!(
            "net.ipv4.ip_forward={}",
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
            "net.ipv6.conf.all.forwarding={}",
            if val { "1" } else { "0" }
        ))
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn add_iptable_forward(interface: &str) -> Result<()> {
    Command::new("iptables")
        .arg("-I")
        .arg("FORWARD")
        .arg("-o")
        .arg(interface)
        .arg("-j")
        .arg("ACCEPT")
        .status()
        .expect("failed to execute command");
    Ok(())
}

pub fn delete_iptable_forward(interface: &str) -> Result<()> {
    Command::new("iptables")
        .arg("-D")
        .arg("FORWARD")
        .arg("-o")
        .arg(interface)
        .arg("-j")
        .arg("ACCEPT")
        .status()
        .expect("failed to execute command");
    Ok(())
}
