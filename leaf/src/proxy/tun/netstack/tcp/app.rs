//! The application's side of each connection: what it has been told, what
//! it may still read, and the readiness it is woken for.
//!
//! Received data is copied out of the connection as it arrives; the window
//! reopens only as the application reads it, so the window still measures
//! what the application has consumed.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use super::config::WINDOW;
use super::conn::Handler;
use super::stack::ConnKey;
use crate::proxy::tun::netstack::engine::{Accepted, ConnId};

pub struct AppConn {
    /// The connection while the stack still holds one for it.
    pub conn: Option<ConnKey>,
    /// Both FINs are out and the stack finishes the connection alone,
    /// counted among its connections rather than here.
    pub handed_over: bool,
    pub rx: VecDeque<u8>,
    pub fin: bool,
    pub reset: bool,
    pub write_shut: bool,
    /// Taken by `accept`.
    pub open: bool,
}

/// How a connection ended under the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// Both FINs exchanged and acknowledged.
    Closed,
    /// Reset by the peer, or aborted for a timeout.
    Reset,
}

pub struct Apps {
    pub conns: HashMap<ConnId, AppConn>,
    pub accepted: VecDeque<Accepted>,
    pub ready: Vec<ConnId>,
    next_id: ConnId,
    max_connections: usize,
    pub rx_bytes: usize,
    /// Entries of `conns` that still have a connection.
    attached: usize,
    /// Entries of `conns` whose connection was handed over.
    handed_over: usize,
}

impl Apps {
    pub fn new(max_connections: usize) -> Apps {
        Apps {
            conns: HashMap::new(),
            accepted: VecDeque::new(),
            ready: Vec::new(),
            next_id: 1,
            max_connections,
            rx_bytes: 0,
            attached: 0,
            handed_over: 0,
        }
    }

    /// Takes on a connection whose handshake completed; `None` when the
    /// application already holds as many as it may.
    pub fn accept(
        &mut self,
        key: ConnKey,
        client: SocketAddr,
        target: SocketAddr,
    ) -> Option<ConnId> {
        if self.attached >= self.max_connections {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.conns.insert(
            id,
            AppConn {
                conn: Some(key),
                handed_over: false,
                rx: VecDeque::new(),
                fin: false,
                reset: false,
                write_shut: false,
                open: false,
            },
        );
        self.attached += 1;
        self.accepted.push_back(Accepted { id, client, target });
        Some(id)
    }

    /// Something may have changed for the application holding `handler`:
    /// space to write, or just the periodic nudge.
    pub fn wake(&mut self, handler: Handler) {
        if let Some(id) = handler.app() {
            self.ready.push(id);
        }
    }

    pub fn data(&mut self, id: ConnId, chunk: &[u8]) {
        if let Some(conn) = self.conns.get_mut(&id) {
            self.rx_bytes += chunk.len();
            // No more than the window is ever outstanding.
            crate::proxy::tun::netstack::buf::extend_bounded(
                &mut conn.rx,
                chunk,
                usize::from(WINDOW),
            );
            self.ready.push(id);
        }
    }

    pub fn fin(&mut self, id: ConnId) {
        if let Some(conn) = self.conns.get_mut(&id) {
            conn.fin = true;
            self.ready.push(id);
        }
    }

    pub fn ended(&mut self, handler: Handler, how: Ending) {
        let Some(id) = handler.app() else {
            return;
        };
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        if conn.conn.take().is_some() {
            self.attached -= 1;
        }
        match how {
            Ending::Closed => conn.fin = true,
            Ending::Reset => {
                // As on a kernel socket, a reset discards what was not read:
                // the next read reports the reset.
                conn.reset = true;
                self.rx_bytes -= conn.rx.len();
                conn.rx = VecDeque::new();
            }
        }
        self.ready.push(id);
    }

    /// The connection behind `id`, no longer the application's to use.
    pub fn detach(&mut self, id: ConnId) -> Option<ConnKey> {
        let key = self.conns.get_mut(&id)?.conn.take()?;
        self.attached -= 1;
        Some(key)
    }

    /// The application lets go of a connection whose FINs are both out;
    /// reading what is left no longer reopens the window.
    pub fn hand_over(&mut self, id: ConnId) {
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        if conn.conn.take().is_some() {
            self.attached -= 1;
            conn.handed_over = true;
            self.handed_over += 1;
        }
    }

    pub fn remove(&mut self, id: ConnId) -> Option<AppConn> {
        let conn = self.conns.remove(&id)?;
        self.rx_bytes -= conn.rx.len();
        if conn.conn.is_some() {
            self.attached -= 1;
        }
        if conn.handed_over {
            self.handed_over -= 1;
        }
        Some(conn)
    }

    /// Entries the application holds with no connection behind them.
    pub fn orphans(&self) -> usize {
        self.conns.len() - self.attached - self.handed_over
    }

    pub fn shrink(&mut self) {
        let shrink = crate::proxy::tun::netstack::buf::should_shrink;
        if shrink(self.conns.len(), self.conns.capacity()) {
            self.conns.shrink_to(self.conns.len() * 2);
        }
        if shrink(self.ready.len(), self.ready.capacity()) {
            self.ready.shrink_to(self.ready.len() * 2);
        }
        if shrink(self.accepted.len(), self.accepted.capacity()) {
            self.accepted.shrink_to(self.accepted.len() * 2);
        }
    }
}
