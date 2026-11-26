//! Header layouts and the Internet checksum: reading and writing IPv4,
//! IPv6, TCP and UDP headers by byte offset.
//!
//! Readers take untrusted bytes and check every length before using it;
//! writers take buffers their caller sized for them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV6_HEADER_LEN: usize = 40;
pub const TCP_HEADER_LEN: usize = 20;
pub const UDP_HEADER_LEN: usize = 8;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

// ---- Checksum ----------------------------------------------------------

/// The one's-complement sum of RFC 1071, fed in any number of pieces.
#[derive(Default)]
pub struct Checksum {
    sum: u64,
    /// The first byte of a 16-bit word whose second byte has not come yet.
    pending: Option<u8>,
}

impl Checksum {
    pub fn new() -> Self {
        Checksum::default()
    }

    pub fn add(&mut self, mut data: &[u8]) {
        if let Some(high) = self.pending.take() {
            match data.split_first() {
                Some((&low, rest)) => {
                    self.sum += u64::from(u16::from_be_bytes([high, low]));
                    data = rest;
                }
                None => {
                    self.pending = Some(high);
                    return;
                }
            }
        }
        let (words, remainder) = data.as_chunks::<2>();
        for w in words {
            self.sum += u64::from(u16::from_be_bytes(*w));
        }
        if let [last] = remainder {
            self.pending = Some(*last);
        }
    }

    /// The pseudo-header of RFC 9293 §3.1 / RFC 8200 §8.1.
    pub fn add_pseudo_header(&mut self, src: IpAddr, dst: IpAddr, protocol: u8, len: usize) {
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                self.add(&s.octets());
                self.add(&d.octets());
                self.add(&[0, protocol]);
                self.add(&(len as u16).to_be_bytes());
            }
            _ => {
                self.add(&ipv6_of(src).octets());
                self.add(&ipv6_of(dst).octets());
                self.add(&(len as u32).to_be_bytes());
                self.add(&[0, 0, 0, protocol]);
            }
        }
    }

    pub fn finish(mut self) -> u16 {
        if let Some(high) = self.pending.take() {
            self.sum += u64::from(u16::from_be_bytes([high, 0]));
        }
        while self.sum >> 16 != 0 {
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }
        !(self.sum as u16)
    }
}

fn ipv6_of(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V6(v6) => v6,
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
    }
}

/// Whether a TCP or UDP segment's checksum is right.
pub fn transport_checksum_ok(src: IpAddr, dst: IpAddr, protocol: u8, segment: &[u8]) -> bool {
    let mut sum = Checksum::new();
    sum.add_pseudo_header(src, dst, protocol, segment.len());
    sum.add(segment);
    sum.finish() == 0
}

/// Fills in the checksum of the TCP or UDP segment in `segment`, whose
/// checksum field is at `field`.
pub fn fill_transport_checksum(
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    segment: &mut [u8],
    field: usize,
) {
    segment[field..field + 2].copy_from_slice(&[0, 0]);
    let mut sum = Checksum::new();
    sum.add_pseudo_header(src, dst, protocol, segment.len());
    sum.add(segment);
    let mut value = sum.finish();
    if protocol == PROTO_UDP && value == 0 {
        // Zero means "no checksum" in UDP; its one's-complement twin is sent.
        value = 0xffff;
    }
    segment[field..field + 2].copy_from_slice(&value.to_be_bytes());
}

// ---- IPv4 / IPv6 -------------------------------------------------------

/// The fields of an IPv4 header the stack uses.
pub struct Ipv4Header {
    pub header_len: usize,
    pub total_len: usize,
    pub ident: u16,
    pub more_fragments: bool,
    /// In bytes.
    pub fragment_offset: usize,
    pub protocol: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

pub fn read_ipv4(packet: &[u8]) -> Option<Ipv4Header> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(be16(packet, 2));
    if header_len < IPV4_HEADER_LEN || total_len < header_len || total_len > packet.len() {
        return None;
    }
    let flags_offset = be16(packet, 6);
    Some(Ipv4Header {
        header_len,
        total_len,
        ident: be16(packet, 4),
        more_fragments: flags_offset & 0x2000 != 0,
        fragment_offset: usize::from(flags_offset & 0x1fff) * 8,
        protocol: packet[9],
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    })
}

pub fn ipv4_header_checksum_ok(packet: &[u8]) -> bool {
    let Some(header) = read_ipv4(packet) else {
        return false;
    };
    let mut sum = Checksum::new();
    sum.add(&packet[..header.header_len]);
    sum.finish() == 0
}

pub struct Ipv4Fields {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub total_len: u16,
    pub ident: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// In bytes; a multiple of 8.
    pub fragment_offset: u16,
    pub ttl: u8,
}

/// Writes a 20-byte IPv4 header, checksum included, at the start of `buf`.
pub fn write_ipv4(buf: &mut [u8], f: &Ipv4Fields) {
    let h = &mut buf[..IPV4_HEADER_LEN];
    h[0] = 0x45;
    h[1] = 0;
    h[2..4].copy_from_slice(&f.total_len.to_be_bytes());
    h[4..6].copy_from_slice(&f.ident.to_be_bytes());
    let mut flags_offset = f.fragment_offset / 8;
    if f.dont_fragment {
        flags_offset |= 0x4000;
    }
    if f.more_fragments {
        flags_offset |= 0x2000;
    }
    h[6..8].copy_from_slice(&flags_offset.to_be_bytes());
    h[8] = f.ttl;
    h[9] = f.protocol;
    h[10..12].copy_from_slice(&[0, 0]);
    h[12..16].copy_from_slice(&f.src.octets());
    h[16..20].copy_from_slice(&f.dst.octets());
    let mut sum = Checksum::new();
    sum.add(h);
    let value = sum.finish();
    h[10..12].copy_from_slice(&value.to_be_bytes());
}

pub struct Ipv6Header {
    pub payload_len: usize,
    pub next_header: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

pub fn read_ipv6(packet: &[u8]) -> Option<Ipv6Header> {
    if packet.len() < IPV6_HEADER_LEN || packet[0] >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(be16(packet, 4));
    if IPV6_HEADER_LEN + payload_len > packet.len() {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    dst.copy_from_slice(&packet[24..40]);
    Some(Ipv6Header {
        payload_len,
        next_header: packet[6],
        src: Ipv6Addr::from(src),
        dst: Ipv6Addr::from(dst),
    })
}

/// Writes a 40-byte IPv6 header at the start of `buf`.
pub fn write_ipv6(
    buf: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next: u8,
    payload_len: u16,
    hop_limit: u8,
) {
    let h = &mut buf[..IPV6_HEADER_LEN];
    h[0..4].copy_from_slice(&[0x60, 0, 0, 0]);
    h[4..6].copy_from_slice(&payload_len.to_be_bytes());
    h[6] = next;
    h[7] = hop_limit;
    h[8..24].copy_from_slice(&src.octets());
    h[24..40].copy_from_slice(&dst.octets());
}

// ---- TCP ---------------------------------------------------------------

pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub header_len: usize,
    pub window: u16,
}

/// Reads a TCP segment's header; the options are `segment[20..header_len]`
/// and the payload `segment[header_len..]`.
pub fn read_tcp(segment: &[u8]) -> Option<TcpHeader> {
    if segment.len() < TCP_HEADER_LEN {
        return None;
    }
    let header_len = usize::from(segment[12] >> 4) * 4;
    if header_len < TCP_HEADER_LEN || header_len > segment.len() {
        return None;
    }
    Some(TcpHeader {
        src_port: be16(segment, 0),
        dst_port: be16(segment, 2),
        seq: be32(segment, 4),
        ack: be32(segment, 8),
        header_len,
        window: be16(segment, 14),
    })
}

// ---- UDP ---------------------------------------------------------------

pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub len: usize,
    pub checksum: u16,
}

pub fn read_udp(segment: &[u8]) -> Option<UdpHeader> {
    if segment.len() < UDP_HEADER_LEN {
        return None;
    }
    let len = usize::from(be16(segment, 4));
    if len < UDP_HEADER_LEN || len > segment.len() {
        return None;
    }
    Some(UdpHeader {
        src_port: be16(segment, 0),
        dst_port: be16(segment, 2),
        len,
        checksum: be16(segment, 6),
    })
}

/// Writes the UDP header at the start of `segment`, which already holds
/// the payload after it and is exactly the datagram's length.
pub fn write_udp(segment: &mut [u8], src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16) {
    let len = segment.len() as u16;
    segment[0..2].copy_from_slice(&src_port.to_be_bytes());
    segment[2..4].copy_from_slice(&dst_port.to_be_bytes());
    segment[4..6].copy_from_slice(&len.to_be_bytes());
    fill_transport_checksum(src, dst, PROTO_UDP, segment, 6);
}

#[cfg(test)]
mod tests {
    //! Known answers computed outside this code.

    use super::*;

    #[test]
    fn ipv4_header_checksum_matches_the_textbook_example() {
        // The worked example on Wikipedia's "IPv4 header checksum" page.
        let mut header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let mut sum = Checksum::new();
        sum.add(&header);
        assert_eq!(sum.finish(), 0xb861);
        header[10..12].copy_from_slice(&0xb861u16.to_be_bytes());
        let mut packet = header.to_vec();
        packet.resize(0x73, 0);
        assert!(ipv4_header_checksum_ok(&packet));
    }

    #[test]
    fn udp6_checksum_of_an_odd_length_datagram() {
        let src: IpAddr = "fd00::2".parse().unwrap();
        let dst: IpAddr = "2001:db8::1".parse().unwrap();
        let mut segment = vec![0u8; UDP_HEADER_LEN + 5];
        segment[UDP_HEADER_LEN..].copy_from_slice(b"hello");
        write_udp(&mut segment, src, dst, 5353, 53);
        assert_eq!(u16::from_be_bytes([segment[6], segment[7]]), 0x7c27);
        assert!(transport_checksum_ok(src, dst, PROTO_UDP, &segment));
    }

    #[test]
    fn a_checksum_fed_in_odd_pieces_equals_one_fed_whole() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1001).collect();
        let mut whole = Checksum::new();
        whole.add(&data);
        let mut pieces = Checksum::new();
        for chunk in data.chunks(7) {
            pieces.add(chunk);
        }
        assert_eq!(whole.finish(), pieces.finish());
    }
}
