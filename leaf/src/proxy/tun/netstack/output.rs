use std::os::raw;
use std::sync::atomic::Ordering;

use super::lwip::*;
use super::stack_impl::NetStackImpl;

pub static mut OUTPUT_CB_PTR: usize = 0x0;

fn output(netif: *mut netif, p: *mut pbuf) -> err_t {
    unsafe {
        if super::STACK_CLOSED.load(Ordering::Relaxed) {
            return err_enum_t_ERR_OK as err_t;
        }
        let pbuflen = (*p).tot_len;
        let mut buf = Vec::with_capacity((*netif).mtu as usize);
        pbuf_copy_partial(p, buf.as_mut_ptr() as *mut raw::c_void, pbuflen, 0);
        buf.set_len(pbuflen as usize);
        let stack = &mut *(OUTPUT_CB_PTR as *mut NetStackImpl);
        let _ = stack.output((&buf[0..pbuflen as usize]).to_vec());
        err_enum_t_ERR_OK as err_t
    }
}

#[allow(unused_variables)]
pub extern "C" fn output_ip4(netif: *mut netif, p: *mut pbuf, ipaddr: *const ip4_addr_t) -> err_t {
    output(netif, p)
}

#[allow(unused_variables)]
#[allow(unused)]
pub extern "C" fn output_ip6(netif: *mut netif, p: *mut pbuf, ipaddr: *const ip6_addr_t) -> err_t {
    output(netif, p)
}
