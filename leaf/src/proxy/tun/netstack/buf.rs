//! Byte queues that grow by doubling, as `VecDeque` does, but never past the
//! most they can ever hold — a 46 KiB window must not cost 64 KiB — and that
//! give their memory back once empty.

use std::collections::VecDeque;

/// Appends `data`, growing `buf` geometrically up to `limit` bytes of
/// capacity (beyond it only as far as needed, when `data` itself is larger).
pub fn extend_bounded(buf: &mut VecDeque<u8>, data: &[u8], limit: usize) {
    let needed = buf.len() + data.len();
    if needed > buf.capacity() {
        let target = (buf.capacity() * 2).max(needed).min(limit.max(needed));
        buf.reserve_exact(target - buf.len());
    }
    buf.extend(data);
}

/// Shrinks a map-like collection whose length has fallen far below its
/// capacity, so a burst of connections does not keep its memory for good.
pub fn should_shrink(len: usize, capacity: usize) -> bool {
    capacity > 64 && len * 4 < capacity
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_stops_at_the_limit() {
        let mut buf = VecDeque::new();
        for _ in 0..32 {
            extend_bounded(&mut buf, &[0u8; 1460], 46_720);
        }
        assert_eq!(buf.len(), 46_720);
        assert!(
            buf.capacity() < 46_720 + 1460,
            "capacity {}",
            buf.capacity()
        );
    }
}
