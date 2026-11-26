//! How a connection ends: closed by the application or by the peer,
//! aborted, or given up on.

use super::app::Ending;
use super::config::WINDOW;
use super::conn::{Connection, Handler, State};
use super::stack::Env;

impl Connection {
    /// Leaves the connection for good: queues dropped, an owed delayed ACK
    /// sent first, then the stack forgets it.
    pub fn retire(&mut self, env: &mut Env) {
        self.purge();
        if !matches!(self.state, State::TimeWait) && self.ack.delayed {
            self.ack.now = true;
            self.output(env);
        }
        self.state = State::Closed;
        self.forget = true;
    }

    /// Drops the connection, resetting it if `reset` and it was still
    /// synchronised; the application hears it as a reset.
    pub fn abandon(&mut self, reset: bool, env: &mut Env) {
        if self.state == State::TimeWait {
            self.state = State::Closed;
            self.forget = true;
            return;
        }
        let (seq, ack, handler) = (self.snd.next, self.rcv.next, self.handler);
        let was_open = self.state != State::Closed;
        if was_open {
            self.retire(env);
        }
        self.snd.unacked.clear();
        self.snd.unsent.clear();
        self.rcv.out_of_order.clear();
        if reset && was_open {
            env.net.send_reset(self.local, self.remote, seq, ack);
        }
        self.forget = true;
        env.apps.ended(handler, Ending::Reset);
    }

    pub fn abort(&mut self, env: &mut Env) {
        self.abandon(true, env);
    }

    /// The application will neither read nor write any more.
    pub fn close(&mut self, env: &mut Env) {
        self.rx_closed = true;
        self.shut_down(true, env);
    }

    /// The application will write no more: a FIN once what is queued is
    /// out.
    pub fn shutdown_write(&mut self, env: &mut Env) {
        if matches!(
            self.state,
            State::SynReceived | State::Established | State::CloseWait
        ) {
            self.shut_down(false, env);
        }
    }

    /// The application let go of the connection: it closes on its own,
    /// and nothing more is reported.
    pub fn release(&mut self, env: &mut Env) {
        self.handler = Handler::Released;
        self.close(env);
    }

    /// The application reset the connection.
    pub fn abort_by_app(&mut self, env: &mut Env) {
        self.handler = Handler::Released;
        self.abort(env);
    }

    /// Closes the sending side; with `reset_unread`, data the application
    /// never read resets the connection instead, as on a kernel socket.
    fn shut_down(&mut self, reset_unread: bool, env: &mut Env) {
        let unread = self.rcv.window != WINDOW;
        if reset_unread && matches!(self.state, State::Established | State::CloseWait) && unread {
            env.net
                .send_reset(self.local, self.remote, self.snd.next, self.rcv.next);
            self.purge();
            if env.holds_output(self.key) {
                env.closed_during_input = true;
            } else {
                self.forget = true;
            }
            return;
        }
        if self.state == State::Closed {
            self.forget = true;
            return;
        }
        self.close_with_fin(env);
    }

    /// Queues the FIN and moves on to FIN-WAIT-1 or LAST-ACK; without the
    /// memory for it, the close waits for the fast timer.
    pub fn close_with_fin(&mut self, env: &mut Env) {
        let next = match self.state {
            State::SynReceived | State::Established => State::FinWait1,
            State::CloseWait => State::LastAck,
            _ => return,
        };
        match self.queue_fin(env) {
            Ok(()) => {
                self.state = next;
                self.output(env);
            }
            Err(super::send::NoMemory) => self.close_pending = true,
        }
    }
}
