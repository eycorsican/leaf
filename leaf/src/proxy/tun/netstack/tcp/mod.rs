//! A TCP in Rust, following the logic of lwIP 2.2.1's TCP with a few fixes
//! to it (noted where they apply).
//!
//! Where it is lwIP's implementation rather than its behaviour that is
//! left out:
//! - lwIP's heap (`MEM_SIZE`) and segment pool (`MEMP_NUM_TCP_SEG`) are not
//!   reproduced; queueing fails only past `Limits::memory_budget`, where
//!   lwIP would fail at its fixed heap size instead. The connection pool
//!   (`MEMP_NUM_TCP_PCB`), the pbuf pool packets are read into
//!   (`PBUF_POOL_SIZE`), and what lwIP frees when either runs out are.
//! - The IPv4 identification field counts per engine from 0, where lwIP's
//!   counter is per process.
//! - lwIP's other timers (ND6's, every second) are not run: they never act
//!   on TCP, so only when the engine asks to be polled differs.
//! - Received IPv6 extension headers are walked as the shared IP layer
//!   walks them.

mod app;
mod config;
mod conn;
mod input;
mod lifecycle;
mod receive;
mod retransmit;
mod segment;
mod send;
mod seq;
mod stack;
mod timer;

use std::io;
use std::time::Duration;

use stack::Stack;

use crate::proxy::tun::netstack::engine::{Accepted, ConnId, EngineStats, Instant, Limits};
use crate::proxy::tun::netstack::isn::IsnGenerator;

/// The TCP engine, sans-IO: it is handed whole IP packets carrying TCP and
/// the time, and drained of the packets it wants sent. It only ever accepts
/// connections — it terminates the TCP that applications behind the TUN
/// device open, whatever their destination.
///
/// The `io::Result`s follow the socket conventions so the driver can hand
/// them straight to the application: `WouldBlock` for "not now", `Ok(0)` from
/// [`TcpEngine::recv`] for end of stream, `ConnectionReset` once the peer has
/// reset, `BrokenPipe` for a write after shutdown, `NotConnected` for an id
/// the engine no longer knows.
pub struct TcpEngine {
    stack: Stack,
}

impl TcpEngine {
    pub fn new(limits: Limits) -> Self {
        let isn = IsnGenerator::new();
        let mtu = u16::try_from(limits.mtu).unwrap_or(1500);
        let keepalive_idle_ms = limits.keepalive.map_or(0, |d| {
            u32::try_from(d.as_millis()).unwrap_or(u32::MAX).max(1)
        });
        TcpEngine {
            stack: Stack::new(
                isn,
                mtu,
                keepalive_idle_ms,
                limits.max_connections,
                limits.memory_budget,
            ),
        }
    }

    fn open_conn(&mut self, id: ConnId) -> io::Result<&mut app::AppConn> {
        match self.stack.env.apps.conns.get_mut(&id) {
            Some(conn) if conn.open => Ok(conn),
            _ => Err(io::ErrorKind::NotConnected.into()),
        }
    }

    /// One whole IP packet (v4 or v6) carrying TCP, from the TUN device.
    pub fn input(&mut self, now: Instant, packet: &[u8]) {
        self.stack.set_now(now);
        self.stack.receive_packet(packet);
        self.stack.shrink();
    }

    /// Runs whatever timers have come due.
    pub fn poll(&mut self, now: Instant) {
        self.stack.set_now(now);
        self.stack.poll();
        self.stack.shrink();
    }

    /// When [`TcpEngine::poll`] next has something to do; `None` when no
    /// timer is armed.
    pub fn poll_at(&mut self, now: Instant) -> Option<Instant> {
        self.stack.set_now(now);
        let due = self.stack.timer_due()?;
        let ms = due.until(self.stack.now_ms());
        Some(now + Duration::from_millis(u64::from(ms)))
    }

    /// Moves the IP packets the engine wants sent into `out`.
    pub fn drain_output(&mut self, out: &mut Vec<Vec<u8>>) {
        out.append(&mut self.stack.env.net.packets);
    }

    /// Next connection with a completed handshake.
    pub fn accept(&mut self) -> Option<Accepted> {
        let apps = &mut self.stack.env.apps;
        let conn = apps.accepted.pop_front()?;
        if let Some(c) = apps.conns.get_mut(&conn.id) {
            c.open = true;
        }
        Some(conn)
    }

    pub fn recv(&mut self, now: Instant, id: ConnId, buf: &mut [u8]) -> io::Result<usize> {
        self.stack.set_now(now);
        let conn = self.open_conn(id)?;
        if !conn.rx.is_empty() {
            let n = buf.len().min(conn.rx.len());
            for (dst, src) in buf.iter_mut().zip(conn.rx.drain(..n)) {
                *dst = src;
            }
            let key = conn.conn;
            self.stack.env.apps.rx_bytes -= n;
            if let Some(key) = key {
                self.stack.with_conn(key, |c, env| {
                    let mut left = n;
                    while left > 0 {
                        let chunk = left.min(0xffff);
                        c.app_read(chunk as u16, env);
                        left -= chunk;
                    }
                });
            }
            return Ok(n);
        }
        if conn.reset {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        if conn.fin || conn.conn.is_none() {
            return Ok(0);
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    pub fn send(&mut self, now: Instant, id: ConnId, data: &[u8]) -> io::Result<usize> {
        self.stack.set_now(now);
        let conn = self.open_conn(id)?;
        if conn.reset {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        if conn.write_shut {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let Some(key) = conn.conn else {
            return Err(io::ErrorKind::NotConnected.into());
        };
        if data.is_empty() {
            return Ok(0);
        }
        let n = self
            .stack
            .with_conn(key, |c, env| c.write(data, env))
            .unwrap_or(0);
        if n == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(n)
    }

    /// No more data from the application: FIN once what is queued is sent.
    pub fn shutdown_write(&mut self, now: Instant, id: ConnId) {
        self.stack.set_now(now);
        let Ok(conn) = self.open_conn(id) else {
            return;
        };
        if conn.write_shut || conn.reset {
            return;
        }
        conn.write_shut = true;
        if let Some(key) = conn.conn {
            self.stack.with_conn(key, |c, env| c.shutdown_write(env));
        }
    }

    /// The application let go of the connection. The engine finishes the
    /// close on its own and frees it; as on a kernel socket, data that was
    /// never read, or that arrives afterwards, resets the connection.
    pub fn close(&mut self, now: Instant, id: ConnId) {
        self.stack.set_now(now);
        if self.open_conn(id).is_err() {
            return;
        }
        let Some(conn) = self.stack.env.apps.remove(id) else {
            return;
        };
        if let Some(key) = conn.conn {
            self.stack.with_conn(key, |c, env| c.release(env));
        }
    }

    /// Reset the connection now.
    pub fn abort(&mut self, now: Instant, id: ConnId) {
        self.stack.set_now(now);
        let apps = &mut self.stack.env.apps;
        let Some(conn) = apps.conns.get_mut(&id) else {
            return;
        };
        conn.reset = true;
        apps.rx_bytes -= conn.rx.len();
        conn.rx = std::collections::VecDeque::new();
        let forget = !conn.open;
        let key = apps.detach(id);
        apps.ready.push(id);
        if let Some(key) = key {
            self.stack.with_conn(key, |c, env| c.abort_by_app(env));
        }
        if forget {
            let apps = &mut self.stack.env.apps;
            apps.remove(id);
            apps.accepted.retain(|a| a.id != id);
        }
    }

    /// Moves into `out` the connections whose readiness may have changed
    /// since the last call — data or a FIN arrived, buffer space was freed,
    /// the connection reset. Spurious entries are allowed; missing ones are
    /// bugs.
    pub fn drain_ready(&mut self, out: &mut Vec<ConnId>) {
        out.append(&mut self.stack.env.apps.ready);
        self.stack.shrink();
    }

    pub fn stats(&self) -> EngineStats {
        let apps = &self.stack.env.apps;
        EngineStats {
            connections: self.stack.connections() + apps.orphans(),
            open_handles: apps.conns.values().filter(|c| c.open).count(),
            buffered_bytes: apps.rx_bytes + self.stack.buffered(),
        }
    }
}
