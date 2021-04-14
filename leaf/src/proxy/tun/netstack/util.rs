use std::{
    ffi, mem,
    net::{IpAddr, SocketAddr},
};

use anyhow::anyhow;
use anyhow::Result;

use super::lwip::*;

// TODO optimize

pub fn to_socket_addr(addr: &ip_addr_t, port: u16_t) -> Result<SocketAddr> {
    unsafe {
        let src_ip = ffi::CStr::from_ptr(ipaddr_ntoa(addr))
            .to_str()
            .map_err(|_| anyhow!("to_sockset_addr failed"))?;
        Ok(SocketAddr::new(src_ip.parse::<IpAddr>()?, port as u16))
    }
}

pub fn to_ip_addr_t(ip: &IpAddr) -> Result<ip_addr_t> {
    let mut ip_addr = ip_addr_t {
        u_addr: unsafe { mem::zeroed() },
        type_: unsafe { mem::zeroed() },
    };
    let addr_str = ip.to_string();
    let addr_str_bytes = addr_str.as_bytes();
    let addr_cstring =
        ffi::CString::new(addr_str_bytes).map_err(|_| anyhow!("to_ip_addr_t failed"))?;
    let addr_cstring_bytes = addr_cstring.to_bytes_with_nul();
    let cp = unsafe { ffi::CStr::from_bytes_with_nul_unchecked(addr_cstring_bytes).as_ptr() };
    let ret = unsafe { ipaddr_aton(cp, &mut ip_addr as *mut ip_addr_t) };
    if ret == 0 {
        return Err(anyhow!("ipaddr_aton failed"));
    }
    Ok(ip_addr)
}
