//! A segment as the queues hold it: sequence space, header flags, payload,
//! and the pbuf chain lwIP would keep it in — the send queue is limited in
//! pbufs, so how many a segment takes is part of its behaviour.

use super::config::OVERSIZE;
use super::seq::SeqNum;

/// The TCP header's control bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpFlags(u8);

impl TcpFlags {
    pub const FIN: TcpFlags = TcpFlags(0x01);
    pub const SYN: TcpFlags = TcpFlags(0x02);
    pub const RST: TcpFlags = TcpFlags(0x04);
    pub const PSH: TcpFlags = TcpFlags(0x08);
    pub const ACK: TcpFlags = TcpFlags(0x10);
    pub const NONE: TcpFlags = TcpFlags(0);

    /// The six control bits of a header byte.
    pub fn from_header(byte: u8) -> TcpFlags {
        TcpFlags(byte & 0x3f)
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn has(self, flag: TcpFlags) -> bool {
        self.0 & flag.0 != 0
    }

    pub fn has_any(self, flags: TcpFlags) -> bool {
        self.0 & flags.0 != 0
    }

    pub fn insert(&mut self, flag: TcpFlags) {
        self.0 |= flag.0;
    }

    pub fn remove(&mut self, flag: TcpFlags) {
        self.0 &= !flag.0;
    }
}

impl std::ops::BitOr for TcpFlags {
    type Output = TcpFlags;

    fn bitor(self, rhs: TcpFlags) -> TcpFlags {
        TcpFlags(self.0 | rhs.0)
    }
}

/// The pbuf chain behind a segment: the payload bytes each pbuf holds.
/// One pbuf needs no allocation.
#[derive(Clone, Debug)]
pub enum Pbufs {
    One(u16),
    /// Two or more.
    Chain(Vec<u16>),
}

impl Pbufs {
    pub fn single(len: u16) -> Pbufs {
        Pbufs::One(len)
    }

    fn sizes(&self) -> &[u16] {
        match self {
            Pbufs::One(len) => std::slice::from_ref(len),
            Pbufs::Chain(sizes) => sizes,
        }
    }

    pub fn count(&self) -> u16 {
        self.sizes().len() as u16
    }

    pub fn push(&mut self, len: u16) {
        match self {
            Pbufs::One(first) => *self = Pbufs::Chain(vec![*first, len]),
            Pbufs::Chain(sizes) => sizes.push(len),
        }
    }

    /// The last pbuf takes `len` more bytes into its spare room.
    pub fn grow_last(&mut self, len: u16) {
        let last = match self {
            Pbufs::One(only) => Some(only),
            Pbufs::Chain(sizes) => sizes.last_mut(),
        };
        if let Some(last) = last {
            *last += len;
        }
    }

    /// The chain after cutting the payload to `len` bytes: the pbuf where
    /// the cut falls is the last one kept.
    fn truncate(&mut self, len: u16) {
        match self {
            Pbufs::One(only) => *only = (*only).min(len),
            Pbufs::Chain(sizes) => {
                let mut remaining = len;
                let mut kept = sizes.len();
                for (i, size) in sizes.iter_mut().enumerate() {
                    if remaining > *size {
                        remaining -= *size;
                    } else {
                        *size = remaining;
                        kept = i + 1;
                        break;
                    }
                }
                sizes.truncate(kept);
                if let [only] = sizes[..] {
                    *self = Pbufs::One(only);
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Segment {
    pub seq: SeqNum,
    pub flags: TcpFlags,
    /// Carries the MSS option (a SYN).
    pub mss_option: bool,
    pub data: Vec<u8>,
    pub pbufs: Pbufs,
}

impl Segment {
    /// A segment of just control bits, in one empty pbuf.
    pub fn control(seq: SeqNum, flags: TcpFlags) -> Segment {
        Segment {
            seq,
            flags,
            mss_option: flags.has(TcpFlags::SYN),
            data: Vec::new(),
            pbufs: Pbufs::single(0),
        }
    }

    /// A segment of data in one pbuf.
    pub fn data(seq: SeqNum, data: Vec<u8>) -> Segment {
        let len = data.len() as u16;
        Segment {
            seq,
            flags: TcpFlags::NONE,
            mss_option: false,
            data,
            pbufs: Pbufs::single(len),
        }
    }

    pub fn len(&self) -> u16 {
        self.data.len() as u16
    }

    /// Sequence space taken: payload, plus one for a SYN or FIN.
    pub fn seq_len(&self) -> u32 {
        u32::from(self.len()) + u32::from(self.flags.has_any(TcpFlags::SYN | TcpFlags::FIN))
    }

    /// One past the last payload byte.
    pub fn data_end(&self) -> SeqNum {
        self.seq + u32::from(self.len())
    }

    /// One past the last sequence number taken, SYN or FIN included.
    pub fn end(&self) -> SeqNum {
        self.seq + self.seq_len()
    }

    pub fn options_len(&self) -> u16 {
        if self.mss_option {
            4
        } else {
            0
        }
    }

    /// Cuts the payload to `len` bytes, dropping the pbufs no longer
    /// needed.
    pub fn truncate(&mut self, len: u16) {
        self.pbufs.truncate(len);
        self.data.truncate(usize::from(len));
    }
}

/// The spare room of a pbuf allocated for `length` payload bytes, when more
/// writes may come to fill it.
pub fn oversize_for(length: u16, max_length: u16) -> u16 {
    let align = super::config::MEM_ALIGNMENT;
    let padded = length.wrapping_add(OVERSIZE).wrapping_add(align - 1) & !(align - 1);
    max_length.min(padded).wrapping_sub(length)
}
