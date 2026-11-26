//! IP-layer parsing and building shared by every backend: telling TCP from
//! UDP, finding fragments, and writing the UDP datagrams that go back out.
//!
//! Everything here takes bytes straight off a TUN device, so nothing may
//! panic on malformed input — every length is checked before it is used.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::proxy::tun::netstack::wire::{
    self, Ipv4Fields, IPV4_HEADER_LEN, IPV6_HEADER_LEN, UDP_HEADER_LEN,
};

pub use crate::proxy::tun::netstack::wire::{PROTO_TCP, PROTO_UDP};

const IPV6_FRAGMENT_HEADER_LEN: usize = 8;
const IPV6_NEXT_HOP_BY_HOP: u8 = 0;
const IPV6_NEXT_ROUTING: u8 = 43;
const IPV6_NEXT_FRAGMENT: u8 = 44;
const IPV6_NEXT_DEST_OPTIONS: u8 = 60;
const DEFAULT_TTL: u8 = 64;

/// Where a fragment sits in its datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub id: u32,
    /// Byte offset of this fragment's payload within the datagram's payload.
    pub offset: usize,
    pub more: bool,
}

/// A parsed IP packet. `payload` is what follows every IP header, extension
/// headers included: the transport header and data, or a fragment of them.
#[derive(Debug)]
pub struct IpView<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub payload: &'a [u8],
    pub fragment: Option<Fragment>,
}

impl IpView<'_> {
    pub fn is_fragment(&self) -> bool {
        self.fragment.is_some()
    }
}

pub fn parse(packet: &[u8]) -> Option<IpView<'_>> {
    match packet.first()? >> 4 {
        4 => parse_v4(packet),
        6 => parse_v6(packet),
        _ => None,
    }
}

fn parse_v4(packet: &[u8]) -> Option<IpView<'_>> {
    let ip = wire::read_ipv4(packet)?;
    let payload = packet.get(ip.header_len..ip.total_len)?;
    let fragment = (ip.more_fragments || ip.fragment_offset != 0).then_some(Fragment {
        id: u32::from(ip.ident),
        offset: ip.fragment_offset,
        more: ip.more_fragments,
    });
    Some(IpView {
        src: IpAddr::V4(ip.src),
        dst: IpAddr::V4(ip.dst),
        protocol: ip.protocol,
        payload,
        fragment,
    })
}

fn parse_v6(packet: &[u8]) -> Option<IpView<'_>> {
    let ip = wire::read_ipv6(packet)?;
    let mut rest = packet.get(IPV6_HEADER_LEN..IPV6_HEADER_LEN + ip.payload_len)?;
    let mut next = ip.next_header;
    let mut fragment = None;
    loop {
        match next {
            IPV6_NEXT_HOP_BY_HOP | IPV6_NEXT_ROUTING | IPV6_NEXT_DEST_OPTIONS => {
                let header_len = (usize::from(*rest.get(1)?) + 1) * 8;
                next = *rest.first()?;
                rest = rest.get(header_len..)?;
            }
            IPV6_NEXT_FRAGMENT => {
                let header = rest.get(..IPV6_FRAGMENT_HEADER_LEN)?;
                next = header[0];
                let offset_and_flags = u16::from_be_bytes([header[2], header[3]]);
                let id = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
                let offset = usize::from(offset_and_flags & !0x7);
                let more = offset_and_flags & 1 == 1;
                rest = &rest[IPV6_FRAGMENT_HEADER_LEN..];
                // An atomic fragment (offset 0, no more) is a whole datagram.
                if offset != 0 || more {
                    fragment = Some(Fragment { id, offset, more });
                    break;
                }
            }
            _ => break,
        }
    }
    Some(IpView {
        src: IpAddr::V6(ip.src),
        dst: IpAddr::V6(ip.dst),
        protocol: next,
        payload: rest,
        fragment,
    })
}

fn v4_fields(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, total_len: u16) -> Ipv4Fields {
    Ipv4Fields {
        src,
        dst,
        protocol,
        total_len,
        ident: 0,
        dont_fragment: false,
        more_fragments: false,
        fragment_offset: 0,
        ttl: DEFAULT_TTL,
    }
}

/// A whole IP packet carrying `payload` as `protocol`, with no options or
/// extension headers. Used to rebuild a reassembled datagram.
pub fn build_packet(src: IpAddr, dst: IpAddr, protocol: u8, payload: &[u8]) -> Option<Vec<u8>> {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let total = IPV4_HEADER_LEN + payload.len();
            let total_u16 = u16::try_from(total).ok()?;
            let mut buf = vec![0u8; total];
            wire::write_ipv4(&mut buf, &v4_fields(src, dst, protocol, total_u16));
            buf[IPV4_HEADER_LEN..].copy_from_slice(payload);
            Some(buf)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let payload_len = u16::try_from(payload.len()).ok()?;
            let mut buf = vec![0u8; IPV6_HEADER_LEN + payload.len()];
            wire::write_ipv6(&mut buf, src, dst, protocol, payload_len, DEFAULT_TTL);
            buf[IPV6_HEADER_LEN..].copy_from_slice(payload);
            Some(buf)
        }
        _ => None,
    }
}

/// Why a datagram could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// Source and destination are of different IP families.
    MixedFamilies,
    /// More than an IP datagram can carry.
    TooLarge,
}

/// Writes `payload` as a UDP datagram from `src` to `dst`, fragmented to fit
/// `mtu`, appending one IP packet per fragment to `out`. `next_id` numbers
/// the fragmented datagrams.
pub fn build_udp(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    mtu: usize,
    next_id: &mut u32,
    out: &mut Vec<Vec<u8>>,
) -> Result<(), BuildError> {
    if src.is_ipv4() != dst.is_ipv4() {
        return Err(BuildError::MixedFamilies);
    }
    let udp_len = UDP_HEADER_LEN + payload.len();
    if udp_len > usize::from(u16::MAX) {
        return Err(BuildError::TooLarge);
    }
    let mut segment = vec![0u8; udp_len];
    segment[UDP_HEADER_LEN..].copy_from_slice(payload);
    wire::write_udp(&mut segment, src.ip(), dst.ip(), src.port(), dst.port());

    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => fragment_v4(s, d, PROTO_UDP, &segment, mtu, next_id, out),
        (IpAddr::V6(s), IpAddr::V6(d)) => fragment_v6(s, d, PROTO_UDP, &segment, mtu, next_id, out),
        _ => Err(BuildError::MixedFamilies),
    }
}

fn fragment_v4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    segment: &[u8],
    mtu: usize,
    next_id: &mut u32,
    out: &mut Vec<Vec<u8>>,
) -> Result<(), BuildError> {
    if IPV4_HEADER_LEN + segment.len() > usize::from(u16::MAX) {
        return Err(BuildError::TooLarge);
    }
    let ident = (*next_id & 0xffff) as u16;
    *next_id = next_id.wrapping_add(1);
    // Every fragment but the last carries a multiple of 8 bytes.
    let per_fragment = (mtu.max(68) - IPV4_HEADER_LEN) & !7;
    let mut offset = 0;
    loop {
        let end = (offset + per_fragment).min(segment.len());
        let more = end < segment.len();
        let chunk = &segment[offset..end];
        let total = IPV4_HEADER_LEN + chunk.len();
        let mut buf = vec![0u8; total];
        let fields = Ipv4Fields {
            ident,
            more_fragments: more,
            // Both fit: the datagram's size was checked above.
            fragment_offset: u16::try_from(offset).map_err(|_| BuildError::TooLarge)?,
            ..v4_fields(
                src,
                dst,
                protocol,
                u16::try_from(total).map_err(|_| BuildError::TooLarge)?,
            )
        };
        wire::write_ipv4(&mut buf, &fields);
        buf[IPV4_HEADER_LEN..].copy_from_slice(chunk);
        out.push(buf);
        if !more {
            return Ok(());
        }
        offset = end;
    }
}

fn fragment_v6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    protocol: u8,
    segment: &[u8],
    mtu: usize,
    next_id: &mut u32,
    out: &mut Vec<Vec<u8>>,
) -> Result<(), BuildError> {
    let mtu = mtu.max(1280);
    if IPV6_HEADER_LEN + segment.len() <= mtu {
        let payload_len = u16::try_from(segment.len()).map_err(|_| BuildError::TooLarge)?;
        let mut buf = vec![0u8; IPV6_HEADER_LEN + segment.len()];
        wire::write_ipv6(&mut buf, src, dst, protocol, payload_len, DEFAULT_TTL);
        buf[IPV6_HEADER_LEN..].copy_from_slice(segment);
        out.push(buf);
        return Ok(());
    }
    if segment.len() > usize::from(u16::MAX) {
        return Err(BuildError::TooLarge);
    }
    let ident = *next_id;
    *next_id = next_id.wrapping_add(1);
    let per_fragment = (mtu - IPV6_HEADER_LEN - IPV6_FRAGMENT_HEADER_LEN) & !7;
    let mut offset = 0;
    loop {
        let end = (offset + per_fragment).min(segment.len());
        let more = end < segment.len();
        let chunk = &segment[offset..end];
        let payload_len = IPV6_FRAGMENT_HEADER_LEN + chunk.len();
        let payload_len_u16 = u16::try_from(payload_len).map_err(|_| BuildError::TooLarge)?;
        let offset_u16 = u16::try_from(offset).map_err(|_| BuildError::TooLarge)?;
        let mut buf = vec![0u8; IPV6_HEADER_LEN + payload_len];
        wire::write_ipv6(
            &mut buf,
            src,
            dst,
            IPV6_NEXT_FRAGMENT,
            payload_len_u16,
            DEFAULT_TTL,
        );
        let frag = &mut buf[IPV6_HEADER_LEN..IPV6_HEADER_LEN + IPV6_FRAGMENT_HEADER_LEN];
        frag[0] = protocol;
        frag[1] = 0;
        frag[2..4].copy_from_slice(&(offset_u16 | u16::from(more)).to_be_bytes());
        frag[4..8].copy_from_slice(&ident.to_be_bytes());
        buf[IPV6_HEADER_LEN + IPV6_FRAGMENT_HEADER_LEN..].copy_from_slice(chunk);
        out.push(buf);
        if !more {
            return Ok(());
        }
        offset = end;
    }
}

/// The UDP datagram in a whole (unfragmented) IP payload, as
/// `(src port, dst port, data)`. A datagram whose length field disagrees
/// with the packet, or whose checksum is wrong, is `None`.
pub fn parse_udp<'a>(view: &IpView<'a>) -> Option<(u16, u16, &'a [u8])> {
    let udp = wire::read_udp(view.payload)?;
    let segment = &view.payload[..udp.len];
    // A zero checksum means "none", over IPv4 only.
    let checksum_absent = udp.checksum == 0 && view.src.is_ipv4();
    if !checksum_absent && !wire::transport_checksum_ok(view.src, view.dst, PROTO_UDP, segment) {
        return None;
    }
    Some((udp.src_port, udp.dst_port, &segment[UDP_HEADER_LEN..]))
}
