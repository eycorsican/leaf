use std::net;
use std::net::IpAddr;
use log::debug;
use netstat2::{AddressFamilyFlags, get_sockets_info, ProtocolFlags, ProtocolSocketInfo, TcpState};
use sysinfo::{ProcessExt, System, SystemExt, Pid, PidExt};

#[derive(Debug)]
pub struct PortInfo {
    pub address: net::IpAddr,
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

impl From<netstat2::SocketInfo> for PortInfo {
    fn from(socket_info: netstat2::SocketInfo) -> Self {
        let protocol = match socket_info.protocol_socket_info {
            ProtocolSocketInfo::Tcp(_) => "TCP",
            ProtocolSocketInfo::Udp(_) => "UDP",
        };
        let system = System::new_all();
        // system.refresh_system();
        let pid = socket_info.associated_pids.first().unwrap();
        let process_info = system
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

pub fn find_process(protocol: &str, ip: IpAddr, port: u16) -> Option<PortInfo> {
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
    let mut ports = sockets
        .into_iter()
        .filter(|socket_info| match &socket_info.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => tcp.state != TcpState::Closed,
            ProtocolSocketInfo::Udp(_) => true,
        })
        .map(|socket_info| PortInfo::from(socket_info));
    let port = ports.find(|p| p.port == port);
    if let Some(ref p) = port {
        debug!("find process port {:?}", p);
    }
    return port;
}
