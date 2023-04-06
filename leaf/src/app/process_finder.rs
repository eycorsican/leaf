use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;
use log::debug;
use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo,
};
use sysinfo::{Pid, PidExt, ProcessExt, ProcessRefreshKind, System, SystemExt};

lazy_static! {
    pub static ref SYSTEM: Arc<Mutex<System>> = {
        let system = System::new_all();
        Arc::new(Mutex::new(system))
    };
}

#[derive(Debug)]
pub struct PortInfo {
    pub address: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub process_info: Option<ProcessInfo>,
}

#[derive(Debug)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub process_path: String,
}

impl From<SocketInfo> for PortInfo {
    fn from(socket_info: SocketInfo) -> Self {
        let protocol = match socket_info.protocol_socket_info {
            ProtocolSocketInfo::Tcp(_) => "TCP",
            ProtocolSocketInfo::Udp(_) => "UDP",
        };
        let pid = socket_info.associated_pids.first().unwrap();
        let mut system = SYSTEM.lock().unwrap();
        system.refresh_processes_specifics(ProcessRefreshKind::default());
        let process_info =
            system
                .process(Pid::from(pid.to_owned() as usize))
                .map(|p| ProcessInfo {
                    name: p.name().to_owned(),
                    pid: p.pid().as_u32(),
                    process_path: p.exe().to_string_lossy().to_string(),
                });
        Self {
            address: socket_info.local_addr(),
            port: socket_info.local_port(),
            protocol: protocol.to_string(),
            process_info,
        }
    }
}

fn get_socket_info(protocol: &str, ip: &IpAddr, port: u16) -> Option<SocketInfo> {
    let mut af_flags: AddressFamilyFlags = AddressFamilyFlags::from_bits(0).unwrap();
    if ip.is_ipv6() {
        af_flags |= AddressFamilyFlags::IPV6;
    }
    if ip.is_ipv4() {
        af_flags |= AddressFamilyFlags::IPV4;
    }
    let mut proto_flags: ProtocolFlags = ProtocolFlags::from_bits(0).unwrap();
    if protocol == "udp" {
        proto_flags |= ProtocolFlags::UDP;
    }
    if protocol == "tcp" {
        proto_flags |= ProtocolFlags::TCP;
    }
    let sockets = get_sockets_info(af_flags, proto_flags).unwrap_or_default();
    let socket_info = sockets
        .into_iter()
        .find(|p| p.local_addr() == ip.to_owned() && p.local_port() == port);
    return socket_info;
}

pub fn find_process_id(protocol: &str, ip: &IpAddr, port: u16) -> Option<u32> {
    let start_time = tokio::time::Instant::now();
    let socket_info = get_socket_info(protocol, ip, port);
    let pid = socket_info.map(|s| s.associated_pids.first().unwrap().to_owned());
    if let Some(ref pid) = pid {
        let elapsed = tokio::time::Instant::now().duration_since(start_time);
        debug!("found process id [{}ms] {:?}", elapsed.as_millis(), pid);
    }
    pid
}

pub fn find_process(protocol: &str, ip: &IpAddr, port: u16) -> Option<PortInfo> {
    let start_time = tokio::time::Instant::now();
    let socket_info = get_socket_info(protocol, ip, port);
    let port_info = socket_info.map(|socket_info| PortInfo::from(socket_info));
    if let Some(ref p) = port_info {
        let elapsed = tokio::time::Instant::now().duration_since(start_time);
        debug!("found process [{}ms] {:?}", elapsed.as_millis(), p);
    }
    return port_info;
}
