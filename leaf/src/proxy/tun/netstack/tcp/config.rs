//! The configuration this TCP runs with: lwIP's options as set for a TUN
//! stack, the lwIP defaults left in place, and the per-connection settings
//! applied on accept.

pub const MSS: u16 = 1460;
/// The receive window, which is also the most a connection buffers unread.
pub const WINDOW: u16 = 32 * MSS;
/// Bytes the application may have queued unacknowledged.
pub const SEND_BUFFER: u16 = 16 * MSS;
/// Pbufs the send queue may hold: four per maximum segment of the buffer.
pub const SEND_QUEUE_PBUFS: u16 = (4 * SEND_BUFFER as u32).div_ceil(MSS as u32) as u16;
const SEND_QUEUE_OVERFLOW: u16 = 0xffff - 3;
/// The limit a write's pbufs are checked against.
pub const SEND_QUEUE_LIMIT: u16 = if SEND_QUEUE_PBUFS < SEND_QUEUE_OVERFLOW {
    SEND_QUEUE_PBUFS
} else {
    SEND_QUEUE_OVERFLOW
};
/// How far reading must reopen the window before it is announced at once.
pub const WINDOW_UPDATE_THRESHOLD: u32 = {
    let quarter = WINDOW as u32 / 4;
    let four_mss = MSS as u32 * 4;
    if quarter < four_mss {
        quarter
    } else {
        four_mss
    }
};
pub const OUT_OF_ORDER_MAX_BYTES: u32 = WINDOW as u32;
pub const OUT_OF_ORDER_MAX_SEGMENTS: u16 = 64;
/// Extra room a send pbuf is given when more writes may fill it.
pub const OVERSIZE: u16 = MSS;
pub const MEM_ALIGNMENT: u16 = 8;
pub const TTL: u8 = 64;
pub const MAX_RETRANSMITS: u8 = 12;
pub const INITIAL_MSS: u16 = 536;
/// Pushed segments are acknowledged at once, not on the next fast-timer
/// tick, which a Nagle-using peer would otherwise wait out on every write.
pub const ACK_PUSHED_AT_ONCE: bool = true;

/// The TCP timer runs this often; every other run is a slow tick.
pub const TIMER_INTERVAL_MS: u32 = 250;
pub const SLOW_TICK_MS: u32 = 2 * TIMER_INTERVAL_MS;
pub const FIN_WAIT_2_TIMEOUT_TICKS: u32 = 20_000 / SLOW_TICK_MS;
pub const SYN_RECEIVED_TIMEOUT_TICKS: u32 = 20_000 / SLOW_TICK_MS;
/// Twice the maximum segment lifetime: how long TIME-WAIT and LAST-ACK last.
pub const TWO_MSL_TICKS: u32 = 2 * 60_000 / SLOW_TICK_MS;
/// Out-of-order data is dropped after this many RTOs without a segment.
pub const OUT_OF_ORDER_TIMEOUT_RTOS: u32 = 6;
pub const INITIAL_RTO_TICKS: i16 = (3000 / SLOW_TICK_MS) as i16;
/// RTO multipliers by retransmission count (as shifts).
pub const RTO_BACKOFF: [u8; 13] = [1, 2, 3, 4, 5, 6, 7, 7, 7, 7, 7, 7, 7];
/// Slow ticks between window probes, by persist round.
pub const PERSIST_BACKOFF: [u8; 7] = [3, 6, 12, 24, 48, 96, 120];

/// Keep-alive as configured on accept.
pub const KEEPALIVE_INTERVAL_MS: u32 = 10_000;
pub const KEEPALIVE_PROBES: u32 = 6;

/// Connections the stack holds at once (lwIP's PCB pool).
pub const CONNECTION_POOL: usize = if cfg!(target_os = "ios") { 256 } else { 1024 };
/// Pbufs packets from the TUN device are read into.
pub const PBUF_POOL_SIZE: usize = if cfg!(target_os = "ios") { 128 } else { 256 };
/// Bytes per pool pbuf: MSS plus IPv6, TCP and link headers, aligned.
pub const PBUF_POOL_BUFSIZE: usize = 1536;
