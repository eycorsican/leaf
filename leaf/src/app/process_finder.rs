use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, SocketInfo};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

lazy_static! {
    static ref SYSTEM: Arc<Mutex<System>> = {
        let system = System::new_all();
        Arc::new(Mutex::new(system))
    };
    static ref CACHE: Mutex<Option<Vec<SocketInfo>>> = Mutex::new(None);
}

#[derive(Debug)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub process_path: String,
}

impl ProcessInfo {
    fn from_socket_info(socket_info: SocketInfo) -> Option<Self> {
        let pid = socket_info.associated_pids.first()?.to_owned();
        let mut system = SYSTEM.lock().ok()?;
        let the_pid = Pid::from(pid.to_owned() as usize);
        let mut process = system.process(the_pid);
        if process.is_none() {
            system.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[the_pid]),
                true,
                ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
            );
            process = system.process(the_pid);
        }
        let process = process?;
        let name = process.name().to_string_lossy().to_string();
        let process_path = process.exe()?.to_string_lossy().to_string();
        Some(ProcessInfo {
            name,
            pid,
            process_path,
        })
    }
}

fn get_socket_info(protocol: &str, ip: &IpAddr, port: u16) -> Option<SocketInfo> {
    let af_flags = match ip {
        IpAddr::V4(_) => AddressFamilyFlags::IPV4,
        IpAddr::V6(_) => AddressFamilyFlags::IPV6,
    };

    let proto_flags = match protocol {
        "udp" => ProtocolFlags::UDP,
        "tcp" => ProtocolFlags::TCP,
        _ => ProtocolFlags::from_bits(0).unwrap(),
    };

    let mut cache = CACHE.lock().unwrap();
    let sockets = cache.clone().unwrap_or_else(|| {
        let new_sockets = get_sockets_info(af_flags, proto_flags).unwrap_or_default();
        *cache = Some(new_sockets.clone());
        new_sockets
    });

    sockets
        .into_iter()
        .find(|p| p.local_addr() == ip.to_owned() && p.local_port() == port)
        .or_else(|| {
            let new_sockets = get_sockets_info(af_flags, proto_flags).unwrap_or_default();
            *cache = Some(new_sockets.clone());
            new_sockets
                .into_iter()
                .find(|p| p.local_addr() == ip.to_owned() && p.local_port() == port)
        })
}

pub fn find_pid(protocol: &str, ip: &IpAddr, port: u16) -> Option<u32> {
    let socket_info = get_socket_info(protocol, ip, port);
    socket_info.map(|s| s.associated_pids.first().unwrap().to_owned())
}

pub fn find_process(protocol: &str, ip: &IpAddr, port: u16) -> Option<ProcessInfo> {
    let socket_info = get_socket_info(protocol, ip, port);
    socket_info
        .map(|s| ProcessInfo::from_socket_info(s))
        .flatten()
}
