#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::collections::{hash_map::Entry, HashMap};
use std::ffi::CString;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::mem::transmute;
use std::net::{IpAddr, SocketAddr};
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use std::ptr::{addr_of, addr_of_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::thread;

mod datagram;
mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

use anyhow::{anyhow, Result};
use bytes::{BufMut, BytesMut};
use parking_lot::RwLock;
use tracing::{debug, instrument, trace, warn};

use packed::{SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6};

const MAX_PATH: usize = 260;
const IPPROTO_TCP: i32 = 6;

pub const NF_STATUS_SUCCESS: NfStatus = 0;

#[allow(dead_code)]
#[derive(Debug)]
enum NfDirection {
    In,
    Out,
    Both,
    Unknown(u8),
}

impl NfDirection {
    fn value(&self) -> u8 {
        match self {
            Self::In => 1,
            Self::Out => 2,
            Self::Both => 3,
            Self::Unknown(v) => *v,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
enum NfFilteringFlag {
    NfAllow,                     // Allow the activity without filtering transmitted packets
    NfBlock,                     // Block the activity
    NfFilter,                    // Filter the transmitted packets
    NfSuspended,                 // Suspend receives from server and sends from client
    NfOffline,                   // Emulate establishing a TCP connection with remote server
    NfIndicateConnectRequests,   // Indicate outgoing connect requests to API
    NfDisableRedirectProtection, // Disable blocking indicating connect requests for outgoing connections of local proxies
    NfPendConnectRequest, // Pend outgoing connect request to complete it later using nf_complete(TCP|UDP)ConnectRequest
    NfFilterAsIpPackets,  // Indicate the traffic as IP packets via ipSend/ipReceive
    NfReadonly, // Don't block the IP packets and indicate them to ipSend/ipReceive only for monitoring
    NfControlFlow, // Use the flow limit rules even without NF_FILTER flag
    NfRedirect, // Redirect the outgoing TCP connections to address specified in redirectTo
    NfBypassIpPackets, // Bypass the traffic as IP packets, when used with NF_FILTER_AS_IP_PACKETS flag
    Unknown(u32),
}

impl NfFilteringFlag {
    fn value(&self) -> u32 {
        match self {
            Self::NfAllow => 0,
            Self::NfBlock => 1,
            Self::NfFilter => 2,
            Self::NfSuspended => 4,
            Self::NfOffline => 8,
            Self::NfIndicateConnectRequests => 16,
            Self::NfDisableRedirectProtection => 32,
            Self::NfPendConnectRequest => 64,
            Self::NfFilterAsIpPackets => 128,
            Self::NfReadonly => 256,
            Self::NfControlFlow => 512,
            Self::NfRedirect => 1024,
            Self::NfBypassIpPackets => 2048,
            Self::Unknown(v) => *v,
        }
    }
}

pub type NfStatus = i32;

type NfInitFn = unsafe extern "C" fn(*const u8, *const NfEventHandler) -> NfStatus;
type NfFreeFn = unsafe extern "C" fn();
type NfAddRuleFn = unsafe extern "C" fn(*const NfRule, i32) -> NfStatus;
type NfTcpPostReceiveFn = unsafe extern "C" fn(EndpointId, *const u8, i32) -> NfStatus;
type NfTcpPostSendFn = unsafe extern "C" fn(EndpointId, *const u8, i32) -> NfStatus;
type NfUdpPostReceiveFn =
    unsafe extern "C" fn(EndpointId, *const u8, *const u8, i32, *mut NfUdpOptions) -> NfStatus;
type NfUdpPostSendFn =
    unsafe extern "C" fn(EndpointId, *const u8, *const u8, i32, *mut NfUdpOptions) -> NfStatus;
type NfTcpDisableFilteringFn = unsafe extern "C" fn(EndpointId);
type NfUdpDisableFilteringFn = unsafe extern "C" fn(EndpointId);
type NfAdjustProcessPriviledgesFn = unsafe extern "C" fn();
type NfGetUdpConnInfoFn = unsafe extern "C" fn(EndpointId, *mut NfUdpConnInfo) -> NfStatus;

// FIXME Ensure no concurrent access to these fns from different threads.
static NFAPI: RwLock<Option<libloading::Library>> = RwLock::new(None);
static mut NF_INIT: Option<NfInitFn> = None;
static mut NF_FREE: Option<NfFreeFn> = None;
static mut NF_ADD_RULE: Option<NfAddRuleFn> = None;
static mut NF_TCP_POST_RECEIVE: Option<NfTcpPostReceiveFn> = None;
static mut NF_TCP_POST_SEND: Option<NfTcpPostSendFn> = None;
static mut NF_UDP_POST_RECEIVE: Option<NfUdpPostReceiveFn> = None;
static mut NF_UDP_POST_SEND: Option<NfUdpPostSendFn> = None;
static mut NF_TCP_DISABLE_FILTERING: Option<NfTcpDisableFilteringFn> = None;
static mut NF_UDP_DISABLE_FILTERING: Option<NfUdpDisableFilteringFn> = None;
static mut NF_ADJUST_PROCESS_PRIVILEDGES: Option<NfAdjustProcessPriviledgesFn> = None;
static mut NF_GET_UDP_CONN_INFO: Option<NfGetUdpConnInfoFn> = None;

static mut TX: Option<std::sync::mpsc::Sender<bool>> = None;
static UDP_SEND_SOCKET: RwLock<Option<std::net::UdpSocket>> = RwLock::new(None);

struct ConnInfo {
    remote_addr: SocketAddr,
}

#[derive(Debug)]
pub struct UdpLocalInfo {
    local_address: SocketAddr,
}

pub static UDP_LOCAL_INFO: LazyLock<Mutex<HashMap<EndpointId, UdpLocalInfo>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static UDP_ENDPOINT: LazyLock<Mutex<HashMap<SocketAddr, EndpointId>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static UDP_OPTIONS: LazyLock<Mutex<HashMap<EndpointId, Vec<u8>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static TCP_INFO: LazyLock<Mutex<HashMap<u16, ConnInfo>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

type EndpointId = u64;

#[repr(C, packed)]
#[derive(Default)]
struct NfRule {
    protocol: i32,
    processId: u32,
    direction: u8,
    localPort: u16,
    remotePort: u16,
    ip_family: u16,
    localIpAddress: [u8; 16],
    localIpAddressMask: [u8; 16],
    remoteIpAddress: [u8; 16],
    remoteIpAddressMask: [u8; 16],
    filteringFlag: u32,
}

#[repr(C, packed)]
struct NfTcpConnInfo {
    filteringFlag: u32,
    processId: u32,
    direction: u8,
    ip_family: u16,
    localAddress: [u8; 28],
    remoteAddress: [u8; 28],
}

impl NfTcpConnInfo {
    unsafe fn get_local_address(info: *const NfTcpConnInfo) -> Result<SocketAddr> {
        sockaddr_to_socketaddr(
            &addr_of!((*info).localAddress).read_unaligned() as *const [u8; 28] as *const SOCKADDR,
        )
    }

    unsafe fn get_remote_address(info: *const NfTcpConnInfo) -> Result<SocketAddr> {
        sockaddr_to_socketaddr(
            &addr_of!((*info).remoteAddress).read_unaligned() as *const [u8; 28] as *const SOCKADDR,
        )
    }
}

#[repr(C, packed)]
struct NfUdpConnInfo {
    processId: u32,
    ip_family: u16,
    localAddress: [u8; 28],
}

impl NfUdpConnInfo {
    unsafe fn get_local_address(info: *const NfUdpConnInfo) -> Result<SocketAddr> {
        sockaddr_to_socketaddr(
            &addr_of!((*info).localAddress).read_unaligned() as *const [u8; 28] as *const SOCKADDR,
        )
    }
}

impl Default for NfUdpConnInfo {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C, packed)]
struct NfUdpConnRequest {
    filteringFlag: u32,
    processId: u32,
    ip_family: u16,
    localAddress: [u8; 28],
    remoteAddress: [u8; 28],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct NfUdpOptions {
    flags: u32,
    optionsLength: i32,
    options: [u8; 1],
}

#[repr(C, packed)]
struct NfEventHandler {
    threadStart: unsafe extern "C" fn(),
    threadEnd: unsafe extern "C" fn(),
    tcpConnectRequest: unsafe extern "C" fn(EndpointId, *mut NfTcpConnInfo),
    tcpConnected: unsafe extern "C" fn(EndpointId, *mut NfTcpConnInfo),
    tcpClosed: unsafe extern "C" fn(EndpointId, *mut NfTcpConnInfo),
    tcpReceive: unsafe extern "C" fn(EndpointId, *const u8, i32),
    tcpSend: unsafe extern "C" fn(EndpointId, *const u8, i32),
    tcpCanReceive: unsafe extern "C" fn(EndpointId),
    tcpCanSend: unsafe extern "C" fn(EndpointId),
    udpCreated: unsafe extern "C" fn(EndpointId, *mut NfUdpConnInfo),
    udpConnectRequest: unsafe extern "C" fn(EndpointId, *mut NfUdpConnRequest),
    udpClosed: unsafe extern "C" fn(EndpointId, *mut NfUdpConnInfo),
    udpReceive: unsafe extern "C" fn(EndpointId, *const u8, *const u8, i32, *mut NfUdpOptions),
    udpSend: unsafe extern "C" fn(EndpointId, *const u8, *const u8, i32, *mut NfUdpOptions),
    udpCanReceive: unsafe extern "C" fn(EndpointId),
    udpCanSend: unsafe extern "C" fn(EndpointId),
}

unsafe extern "C" fn threadStart() {
    trace!("threadStart tid={:?}", thread::current().id());
}

unsafe extern "C" fn threadEnd() {
    trace!("threadEnd tid={:?}", thread::current().id());
}

unsafe extern "C" fn tcpConnectRequest(id: EndpointId, conn_info: *mut NfTcpConnInfo) {
    let Ok(local_addr) = NfTcpConnInfo::get_local_address(conn_info) else {
        debug!("unable to get local address");
        return;
    };
    let Ok(remote_addr) = NfTcpConnInfo::get_remote_address(conn_info) else {
        debug!("unable to get remote address");
        return;
    };

    trace!(
        "tcpConnectRequest id={} local={} remote={}",
        id,
        &local_addr,
        &remote_addr
    );

    if remote_addr.is_ipv6() {
        // Block IPv6.
        addr_of_mut!((*conn_info).filteringFlag).write_unaligned(NfFilteringFlag::NfBlock.value());
        return;
    }

    if remote_addr.ip().is_loopback() {
        return;
    }

    // TODO Remove timeout items.
    if TCP_INFO
        .lock()
        .unwrap()
        .insert(local_addr.port(), ConnInfo { remote_addr })
        .is_some()
    {
        warn!("duplicated local_addr.port={}", local_addr.port());
    }

    let tag = "nf";
    let network = crate::session::Network::Tcp;
    let Some(new_remote_addr) = crate::app::inbound::get_network_listen_addr(tag, network) else {
        debug!("cannot get listen address, tag={} network={}", tag, network);
        return;
    };

    match new_remote_addr {
        SocketAddr::V4(addr) => {
            let new_remote_addr: SOCKADDR_IN = addr.into();
            let addr_ptr = &new_remote_addr as *const SOCKADDR_IN as *const u8;
            let addr_len = std::mem::size_of::<packed::SOCKADDR_IN>();
            let new_remote_addr_data = std::slice::from_raw_parts(addr_ptr, addr_len);
            let mut write_buf = [0u8; 28];
            write_buf[..addr_len].copy_from_slice(&new_remote_addr_data[..addr_len]);
            addr_of_mut!((*conn_info).remoteAddress).write_unaligned(write_buf);
        }
        SocketAddr::V6(addr) => {
            let new_remote_addr: SOCKADDR_IN6 = addr.into();
            let addr_ptr = &new_remote_addr as *const SOCKADDR_IN6 as *const u8;
            let addr_len = std::mem::size_of::<SOCKADDR_IN6>();
            let new_remote_addr_data = std::slice::from_raw_parts(addr_ptr, addr_len);
            let mut write_buf = [0u8; 28];
            write_buf[..addr_len].copy_from_slice(&new_remote_addr_data[..addr_len]);
            addr_of_mut!((*conn_info).remoteAddress).write_unaligned(write_buf);
        }
    }

    NF_TCP_DISABLE_FILTERING.unwrap()(id);
}

unsafe extern "C" fn tcpConnected(id: EndpointId, _conn_info: *mut NfTcpConnInfo) {
    trace!("tcpConnected id={}", id);
}

unsafe extern "C" fn tcpClosed(id: EndpointId, _conn_info: *mut NfTcpConnInfo) {
    trace!("tcpClosed id={}", id);
}

unsafe extern "C" fn tcpReceive(id: EndpointId, buf: *const u8, len: i32) {
    trace!(
        "tcpReceive tid={:?} id={} len={}",
        thread::current().id(),
        id,
        len
    );
    NF_TCP_POST_RECEIVE.unwrap()(id, buf, len);
}

unsafe extern "C" fn tcpSend(id: EndpointId, _buf: *const u8, len: i32) {
    trace!(
        "tcpSend tid={:?} id={} len={}",
        thread::current().id(),
        id,
        len
    );
}

unsafe extern "C" fn tcpCanReceive(id: EndpointId) {
    trace!("tcpCanReceive id={}", id);
}

unsafe extern "C" fn tcpCanSend(id: EndpointId) {
    trace!("tcpCanSend id={}", id);
}

unsafe extern "C" fn udpCreated(id: EndpointId, conn_info: *mut NfUdpConnInfo) {
    let Ok(local_address) = NfUdpConnInfo::get_local_address(conn_info) else {
        debug!("unable to get local address");
        return;
    };
    trace!("udpCreated id={} local={}", id, &local_address);
    // The local address here can be 0.0.0.0:0, we will check and override in udpSend.
    UDP_LOCAL_INFO
        .lock()
        .unwrap()
        .insert(id, UdpLocalInfo { local_address });
    UDP_ENDPOINT.lock().unwrap().insert(local_address, id);
}

unsafe extern "C" fn udpConnectRequest(id: EndpointId, _conn_req: *mut NfUdpConnRequest) {
    trace!("udpConnectRequest id={}", id);
}

unsafe extern "C" fn udpClosed(id: EndpointId, _conn_info: *mut NfUdpConnInfo) {
    UDP_OPTIONS.lock().unwrap().remove(&id);
    if let Some(info) = UDP_LOCAL_INFO.lock().unwrap().remove(&id) {
        UDP_ENDPOINT.lock().unwrap().remove(&info.local_address);
    }
}

unsafe extern "C" fn udpReceive(
    id: EndpointId,
    remote_address: *const u8,
    buf: *const u8,
    len: i32,
    options: *mut NfUdpOptions,
) {
    trace!("udpReceive id={}", id);
    NF_UDP_POST_RECEIVE.unwrap()(id, remote_address, buf, len, options);
}

unsafe extern "C" fn udpSend(
    id: EndpointId,
    remote_address: *const u8,
    buf: *const u8,
    len: i32,
    options: *mut NfUdpOptions,
) {
    let Ok(remote_addr) =
        sockaddr_to_socketaddr(transmute::<*const u8, *const SOCKADDR>(remote_address))
    else {
        debug!("unable to get remote address");
        return;
    };

    trace!("udpSend id={} remote={} len={}", id, &remote_addr, len);

    // Drop IPv6
    if remote_addr.is_ipv6() {
        trace!("Pass IPv6");
        let status = NF_UDP_POST_SEND.unwrap()(id, remote_address, buf, len, options);
        if status != NF_STATUS_SUCCESS {
            debug!("send to local failed, status={}", status);
        }
        return;
    }

    if remote_addr.ip().is_loopback() {
        NF_UDP_DISABLE_FILTERING.unwrap()(id);
        return;
    }

    let mut conn_info = NfUdpConnInfo::default();
    let status = NF_GET_UDP_CONN_INFO.unwrap()(id, &mut conn_info as *mut _);
    if status != NF_STATUS_SUCCESS {
        debug!("get udp conn info failed id={} status={}", id, status);
        return;
    }
    let Ok(local_address) = NfUdpConnInfo::get_local_address(&conn_info as *const NfUdpConnInfo)
    else {
        debug!("unable to get local address");
        return;
    };

    UDP_LOCAL_INFO.lock().unwrap().entry(id).and_modify(|x| {
        if x.local_address.port() == 0 {
            x.local_address = local_address;
            UDP_ENDPOINT.lock().unwrap().insert(local_address, id);
        }
    });

    UDP_OPTIONS.lock().unwrap().entry(id).or_insert_with(|| {
        let opts_len = (*options).optionsLength;
        let opts_data_len = std::mem::size_of::<NfUdpOptions>() - 1 + opts_len as usize;
        let mut opts_buf = vec![0u8; opts_data_len];
        let options_data = std::slice::from_raw_parts(options as *mut u8, opts_data_len);
        opts_buf[..opts_data_len]
            .as_mut()
            .copy_from_slice(&options_data[..opts_data_len]);
        opts_buf
    });

    let Ok(original_remote_addr) =
        sockaddr_to_socketaddr(transmute::<*const u8, *const SOCKADDR>(remote_address))
    else {
        debug!("unable to get original remote address");
        return;
    };

    let mut new_buf = BytesMut::new();
    let dst_addr = crate::session::SocksAddr::from(original_remote_addr);
    dst_addr.write_buf(&mut new_buf, crate::session::SocksAddrWireType::PortLast);
    new_buf.put_u64(id);
    let buf = std::slice::from_raw_parts(buf, len as _);
    new_buf.put_slice(buf);

    // FIXME retrieve from inbound settings
    let tag = "nf";
    let network = crate::session::Network::Udp;
    let Some(new_remote_addr) = crate::app::inbound::get_network_listen_addr(tag, network) else {
        debug!("cannot get listen address tag={} network={}", tag, network);
        return;
    };

    if let Err(e) = UDP_SEND_SOCKET
        .read()
        .as_ref()
        .unwrap()
        .send_to(&new_buf, new_remote_addr)
    {
        debug!("send to local failed: {}", e);
    }
}

unsafe extern "C" fn udpCanReceive(id: EndpointId) {
    trace!("udpCanReceive id={}", id);
}

unsafe extern "C" fn udpCanSend(id: EndpointId) {
    trace!("udpCanSend id={}", id);
}

pub mod packed {
    pub type ADDRESS_FAMILY = u16;

    pub const AF_INET: ADDRESS_FAMILY = 2u16;
    pub const AF_INET6: ADDRESS_FAMILY = 23u16;

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct SOCKADDR {
        pub sa_family: ADDRESS_FAMILY,
        pub sa_data: [i8; 14],
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct IN_ADDR_0_0 {
        pub s_b1: u8,
        pub s_b2: u8,
        pub s_b3: u8,
        pub s_b4: u8,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct IN_ADDR_0_1 {
        pub s_w1: u16,
        pub s_w2: u16,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub union IN_ADDR_0 {
        pub S_un_b: IN_ADDR_0_0,
        pub S_un_w: IN_ADDR_0_1,
        pub S_addr: u32,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct IN_ADDR {
        pub S_un: IN_ADDR_0,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct SOCKADDR_IN {
        pub sin_family: ADDRESS_FAMILY,
        pub sin_port: u16,
        pub sin_addr: IN_ADDR,
        pub sin_zero: [i8; 8],
    }

    impl Default for SOCKADDR_IN {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub union IN6_ADDR_0 {
        pub Byte: [u8; 16],
        pub Word: [u16; 8],
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct SCOPE_ID_0_0 {
        pub _bitfield: u32,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub union SCOPE_ID_0 {
        pub Anonymous: SCOPE_ID_0_0,
        pub Value: u32,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct SCOPE_ID {
        pub Anonymous: SCOPE_ID_0,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub union SOCKADDR_IN6_0 {
        pub sin6_scope_id: u32,
        pub sin6_scope_struct: SCOPE_ID,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct IN6_ADDR {
        pub u: IN6_ADDR_0,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct SOCKADDR_IN6 {
        pub sin6_family: ADDRESS_FAMILY,
        pub sin6_port: u16,
        pub sin6_flowinfo: u32,
        pub sin6_addr: IN6_ADDR,
        pub Anonymous: SOCKADDR_IN6_0,
    }

    impl Default for SOCKADDR_IN6 {
        fn default() -> Self {
            unsafe { core::mem::zeroed() }
        }
    }

    impl From<std::net::SocketAddrV4> for SOCKADDR_IN {
        fn from(addr: std::net::SocketAddrV4) -> Self {
            // addr.port() is in host byte order
            // sin_port must be big-endian, network byte order
            SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: addr.port().to_be(),
                sin_addr: (*addr.ip()).into(),
                ..Default::default()
            }
        }
    }

    impl From<std::net::SocketAddrV6> for SOCKADDR_IN6 {
        fn from(addr: std::net::SocketAddrV6) -> Self {
            // addr.port() and addr.flowinfo() are in host byte order
            // sin6_port and sin6_flowinfo must be big-endian, network byte order
            // sin6_scope_id is a bitfield without endianness
            SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo().to_be(),
                sin6_addr: (*addr.ip()).into(),
                Anonymous: SOCKADDR_IN6_0 {
                    sin6_scope_id: addr.scope_id(),
                },
            }
        }
    }

    impl From<IN_ADDR> for std::net::Ipv4Addr {
        fn from(in_addr: IN_ADDR) -> Self {
            // SAFETY: this is safe because the union variants are just views of the same exact data
            // in_addr.S_un.S_addr is big-endian, network byte order
            // Ipv4Addr::new() expects the parameter in host byte order
            Self::from(u32::from_be(unsafe { in_addr.S_un.S_addr }))
        }
    }

    impl From<std::net::Ipv4Addr> for IN_ADDR {
        fn from(addr: std::net::Ipv4Addr) -> Self {
            // u32::from(addr) is in host byte order
            // S_addr must be big-endian, network byte order
            Self {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from(addr).to_be(),
                },
            }
        }
    }

    impl From<IN6_ADDR> for std::net::Ipv6Addr {
        fn from(in6_addr: IN6_ADDR) -> Self {
            // SAFETY: this is safe because the union variants are just views of the same exact data
            Self::from(unsafe { in6_addr.u.Byte })
        }
    }

    impl From<std::net::Ipv6Addr> for IN6_ADDR {
        fn from(addr: std::net::Ipv6Addr) -> Self {
            Self {
                u: IN6_ADDR_0 {
                    Byte: addr.octets(),
                },
            }
        }
    }
}

unsafe fn sockaddr_to_socketaddr(addr: *const packed::SOCKADDR) -> Result<SocketAddr> {
    match addr_of!((*addr).sa_family).read_unaligned() {
        packed::AF_INET => {
            let addr: *const packed::SOCKADDR_IN = transmute(addr);
            Ok(SocketAddr::new(
                IpAddr::V4(addr_of!((*addr).sin_addr).read_unaligned().into()),
                u16::from_be(addr_of!((*addr).sin_port).read_unaligned()),
            ))
        }
        packed::AF_INET6 => {
            let addr: *const packed::SOCKADDR_IN6 = transmute(addr);
            Ok(SocketAddr::new(
                IpAddr::V6(addr_of!((*addr).sin6_addr).read_unaligned().into()),
                u16::from_be(addr_of!((*addr).sin6_port).read_unaligned()),
            ))
        }
        _ => Err(anyhow!("unknown address family")),
    }
}

#[allow(clippy::missing_transmute_annotations)]
unsafe fn init_nf_fns<P: AsRef<OsStr>>(nfapi: P) -> Result<()> {
    let nfapi = libloading::Library::new(nfapi)?;

    NF_INIT = Some(transmute(
        nfapi
            .get::<libloading::Symbol<NfInitFn>>(b"nf_init\0")?
            .into_raw(),
    ));

    let nf_free: libloading::Symbol<NfFreeFn> = nfapi.get(b"nf_free\0")?;
    NF_FREE = Some(transmute(nf_free.into_raw()));

    let nf_add_rule: libloading::Symbol<NfAddRuleFn> = nfapi.get(b"nf_addRule\0")?;
    NF_ADD_RULE = Some(transmute(nf_add_rule.into_raw()));

    let nf_tcp_post_receive: libloading::Symbol<NfTcpPostReceiveFn> =
        nfapi.get(b"nf_tcpPostReceive\0")?;
    NF_TCP_POST_RECEIVE = Some(transmute(nf_tcp_post_receive.into_raw()));

    let nf_tcp_post_send: libloading::Symbol<NfTcpPostSendFn> = nfapi.get(b"nf_tcpPostSend\0")?;
    NF_TCP_POST_SEND = Some(transmute(nf_tcp_post_send.into_raw()));

    let nf_udp_post_receive: libloading::Symbol<NfUdpPostReceiveFn> =
        nfapi.get(b"nf_udpPostReceive\0")?;
    NF_UDP_POST_RECEIVE = Some(transmute(nf_udp_post_receive.into_raw()));

    let nf_udp_post_send: libloading::Symbol<NfUdpPostSendFn> = nfapi.get(b"nf_udpPostSend\0")?;
    NF_UDP_POST_SEND = Some(transmute(nf_udp_post_send.into_raw()));

    NF_TCP_DISABLE_FILTERING = Some(std::mem::transmute(
        nfapi
            .get::<libloading::Symbol<NfTcpDisableFilteringFn>>(b"nf_tcpDisableFiltering\0")?
            .into_raw(),
    ));

    NF_UDP_DISABLE_FILTERING = Some(std::mem::transmute(
        nfapi
            .get::<libloading::Symbol<NfUdpDisableFilteringFn>>(b"nf_udpDisableFiltering\0")?
            .into_raw(),
    ));

    let nf_adjust_process_priviledges: libloading::Symbol<NfAdjustProcessPriviledgesFn> =
        nfapi.get(b"nf_adjustProcessPriviledges\0")?;
    NF_ADJUST_PROCESS_PRIVILEDGES = Some(transmute(nf_adjust_process_priviledges.into_raw()));

    NF_GET_UDP_CONN_INFO = Some(transmute(
        nfapi
            .get::<libloading::Symbol<NfGetUdpConnInfoFn>>(b"nf_getUDPConnInfo\0")?
            .into_raw(),
    ));

    *NFAPI.write() = Some(nfapi);

    Ok(())
}

unsafe fn init_nf<P: AsRef<OsStr>>(
    driver_name: String,
    nfapi: P,
    res_tx: std::sync::mpsc::Sender<bool>,
) -> Result<()> {
    init_nf_fns(nfapi)?;

    NF_ADJUST_PROCESS_PRIVILEDGES.unwrap()();

    let eh = NfEventHandler {
        threadStart,
        threadEnd,
        tcpConnectRequest,
        tcpConnected,
        tcpClosed,
        tcpReceive,
        tcpSend,
        tcpCanReceive,
        tcpCanSend,
        udpCreated,
        udpConnectRequest,
        udpClosed,
        udpReceive,
        udpSend,
        udpCanReceive,
        udpCanSend,
    };

    let status = NF_INIT.unwrap()(
        CString::new(driver_name)
            .unwrap()
            .as_bytes_with_nul()
            .as_ptr(),
        &eh as *const _,
    );
    if status != NF_STATUS_SUCCESS {
        return Err(anyhow!("nf_init failed, status={}", status));
    }

    // Required for the `tcpConnectRequest` handler to be called.
    let rule = NfRule {
        protocol: IPPROTO_TCP,
        direction: NfDirection::Out.value(),
        filteringFlag: NfFilteringFlag::NfIndicateConnectRequests.value(),
        ..Default::default()
    };
    let status = NF_ADD_RULE.unwrap()(&rule as *const _, 0);
    if status != NF_STATUS_SUCCESS {
        return Err(anyhow!("adding rule failed: {}", status));
    }

    let rule = NfRule {
        filteringFlag: NfFilteringFlag::NfFilter.value(),
        ..Default::default()
    };
    let status = NF_ADD_RULE.unwrap()(&rule as *const _, 0);
    if status != NF_STATUS_SUCCESS {
        return Err(anyhow!("adding rule failed: {}", status));
    }

    *UDP_SEND_SOCKET.write() = Some(std::net::UdpSocket::bind("0.0.0.0:0")?);

    let (tx, rx) = std::sync::mpsc::channel();
    TX = Some(tx);

    if let Err(e) = res_tx.send(true) {
        debug!("unable to send nf init result: {}", e);
    }

    let _ = rx.recv();

    Ok(())
}

fn init_if_needed<P: AsRef<OsStr>>(driver_name: String, nfapi: P) -> Result<()> {
    let nfapi = nfapi.as_ref().to_string_lossy().to_string();
    let (res_tx, res_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        unsafe {
            if let Err(e) = init_nf(driver_name, nfapi, res_tx.clone()) {
                debug!("initialize nf failed: {}", e);
                let _ = res_tx.send(false);
            }
        };
    });
    if let Ok(res) = res_rx.recv() {
        if res {
            return Ok(());
        }
    }
    Err(anyhow!("initialize nf failed"))
}

static IS_NF_INITIALIZED: AtomicBool = AtomicBool::new(false);

// TODO Guard initializing.
pub fn init<P: AsRef<OsStr>>(driver_name: String, nfapi: P) -> Result<()> {
    if !IS_NF_INITIALIZED.load(Ordering::Relaxed) {
        init_if_needed(driver_name, nfapi)?;
        IS_NF_INITIALIZED.store(true, Ordering::Relaxed);
    }
    Ok(())
}

unsafe fn uninit_nf() {
    if IS_NF_INITIALIZED.load(Ordering::Relaxed) {
        NF_FREE.unwrap()();
        if let Some(nfapi) = NFAPI.write().take() {
            if let Err(e) = nfapi.close() {
                debug!("close nf failed: {}", e);
            }
        }
        IS_NF_INITIALIZED.store(false, Ordering::Relaxed);
    }
}

pub fn uninit() {
    unsafe { uninit_nf() };
}
