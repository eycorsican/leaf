//! One client connection through the group: a set of *legs* (attempts on
//! actors) until one answers, then that leg alone.
//!
//! Before the first response byte the client's writes are buffered as the
//! *first flight* (up to [`MAX_FLIGHT`]). A flight that starts with a TLS
//! ClientHello record goes to every connected leg (replay is harmless: a
//! server that never answered has nothing to duplicate); any other flight
//! goes to one leg only (the first connected; the others are dropped) and
//! is never replayed. The first leg to return bytes wins; the others are
//! dropped without a verdict.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;
use tracing::debug;

use super::{Group, MAX_FLIGHT};
use crate::{app::SyncDnsClient, proxy::*, session::Session};

pub(super) struct Ctx {
    pub actors: Vec<AnyOutboundHandler>,
    pub group: Arc<Group>,
    pub dns_client: SyncDnsClient,
}

pub struct Handler {
    ctx: Arc<Ctx>,
}

impl Handler {
    pub fn new(
        actors: Vec<AnyOutboundHandler>,
        group: Arc<Group>,
        dns_client: SyncDnsClient,
    ) -> Self {
        Self {
            ctx: Arc::new(Ctx {
                actors,
                group,
                dns_client,
            }),
        }
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let group = &self.ctx.group;
        let plan = group.plan(Instant::now());
        tracing::trace!("standby [{}]: {:?}", group.tag(), plan);
        if let Some(i) = plan.prewarm {
            if let Ok(h) = self.ctx.actors[i].stream() {
                h.prewarm();
            }
        }
        let mut conn = Conn::new(self.ctx.clone(), sess.clone(), plan);
        // Until a leg connects (or none can): connect errors are errors.
        futures::future::poll_fn(|cx| conn.poll_connected(cx)).await?;
        Ok(Box::new(conn))
    }
}

/// True for a TLS handshake record carrying a ClientHello.
pub(super) fn is_client_hello(b: &[u8]) -> bool {
    b.len() >= 6 && b[0] == 0x16 && b[1] == 0x03 && (1..=4).contains(&b[2]) && b[5] == 0x01
}

/// An error's kind only: reasons reach the info log, addresses must not.
fn reason(prefix: &str, e: &io::Error) -> String {
    format!("{prefix}: {:?}", e.kind())
}

type Connecting = Pin<Box<dyn Future<Output = io::Result<AnyStream>> + Send>>;

struct Leg {
    idx: usize,
    /// Tried after every known actor failed (discovery).
    explore: bool,
    connecting: Option<Mutex<Connecting>>,
    stream: Option<AnyStream>,
    /// When it connected.
    since: Option<Instant>,
    /// Flight bytes written to it.
    sent: usize,
    /// Running from its first flight byte to its first response byte.
    timer: Option<Mutex<Pin<Box<Sleep>>>>,
    shut: bool,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Flight {
    Empty,
    /// Starts with a ClientHello: replayable.
    Hello,
    /// Anything else, or a ClientHello flight past [`MAX_FLIGHT`]: one leg.
    Single,
}

pub(super) struct Conn {
    ctx: Arc<Ctx>,
    /// The retry raced on this connection.
    retry: Option<usize>,
    /// Running from the start while the retry may still win.
    grace: Option<Mutex<Pin<Box<Sleep>>>>,
    /// The network epoch it started on: after a switch it reports nothing.
    epoch: u64,
    sess: Session,
    legs: Vec<Leg>,
    known: VecDeque<usize>,
    explore: VecDeque<usize>,
    /// Discovery pace (`discover-stagger`, more legs per connection) once
    /// every known actor failed or there was none.
    discovering: bool,
    next_start: Mutex<Pin<Box<Sleep>>>,
    flight: Vec<u8>,
    kind: Flight,
    /// Some flight byte went to some leg.
    sent_any: bool,
    /// A leg failed since the last step: the next one may start at once.
    just_failed: bool,
    /// New legs that may still receive a replayed flight.
    hops: usize,
    /// The leg that answered (then the only one).
    won: bool,
    settled: bool,
    want_shutdown: bool,
    dead: Option<io::ErrorKind>,
    write_waker: Option<Waker>,
    /// The flight outgrew [`MAX_FLIGHT`] and was dropped: it cannot go
    /// to another leg any more.
    truncated: bool,
}

impl Conn {
    fn new(ctx: Arc<Ctx>, sess: Session, plan: super::Plan) -> Self {
        let p = ctx.group.params().clone();
        let discovering = plan.known.is_empty();
        let hops = if discovering { plan.explore.len() } else { 1 };
        let epoch = ctx.group.epoch();
        let mut c = Self {
            retry: plan.retry,
            grace: plan
                .retry
                .map(|_| Mutex::new(Box::pin(tokio::time::sleep(p.retry_grace)))),
            epoch,
            ctx,
            sess,
            legs: vec![],
            known: plan.known.into(),
            explore: plan.explore.into(),
            discovering,
            next_start: Mutex::new(Box::pin(tokio::time::sleep(if discovering {
                p.discover_stagger
            } else {
                p.stagger
            }))),
            flight: vec![],
            kind: Flight::Empty,
            sent_any: false,
            just_failed: false,
            hops,
            won: false,
            settled: false,
            want_shutdown: false,
            dead: None,
            write_waker: None,
            truncated: false,
        };
        if let Some(r) = plan.retry {
            c.start(r, false);
        }
        c.start_next();
        c
    }

    fn group(&self) -> &Group {
        &self.ctx.group
    }

    /// The group, to report to, unless the network changed since the start.
    fn report(&self) -> Option<&Group> {
        (self.ctx.group.epoch() == self.epoch).then_some(&*self.ctx.group)
    }

    fn start(&mut self, idx: usize, explore: bool) {
        let now = Instant::now();
        if explore {
            if let Some(g) = self.report() {
                g.claim(idx, now);
            }
        }
        let ctx = self.ctx.clone();
        let sess = self.sess.clone();
        let budget = self.group().params().timeout;
        let fut: Connecting = Box::pin(async move {
            let a = &ctx.actors[idx];
            let attempt = async {
                let stream = connect_stream_outbound(&sess, ctx.dns_client.clone(), a).await?;
                a.stream()?.handle(&sess, None, stream).await
            };
            match tokio::time::timeout(budget, attempt).await {
                Ok(r) => r,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout")),
            }
        });
        self.legs.push(Leg {
            idx,
            explore,
            connecting: Some(Mutex::new(fut)),
            stream: None,
            since: None,
            sent: 0,
            timer: None,
            shut: false,
        });
        let p = self.group().params();
        let pace = if self.discovering {
            p.discover_stagger
        } else {
            p.stagger
        };
        let mut t = self.next_start.lock().unwrap();
        t.as_mut().reset(tokio::time::Instant::now() + pace);
    }

    /// A leg failed with `e` (and was dropped). An outbound that says none
    /// of the flight left it ([`FlightNotSent`], e.g. kiri's egress could
    /// not reach the destination) leaves the flight unsent, plaintext too:
    /// the next leg gets it, as if that leg had failed to connect. The
    /// failure still counts against the actor.
    fn unbind(&mut self, e: &io::Error) {
        if self.kind == Flight::Single && !self.won && !self.truncated && FlightNotSent::is(e) {
            self.sent_any = self.legs.iter().any(|l| l.sent > 0);
            debug!("standby [{}]: the flight was not sent, it may go to the next actor", self.group().tag());
        }
    }

    /// The flight went to some leg and cannot be replayed.
    fn flight_bound(&self) -> bool {
        self.kind == Flight::Single && self.sent_any
    }

    /// Starts the next leg if the rules allow; true if one started.
    fn start_next(&mut self) -> bool {
        if self.won || self.dead.is_some() || self.flight_bound() {
            return false;
        }
        if self.legs.len() >= self.group().params().max_parallel.max(1) {
            return false;
        }
        let replay = self.kind == Flight::Hello && self.sent_any;
        if replay && self.hops == 0 {
            return false;
        }
        if let Some(i) = self.known.pop_front() {
            if replay {
                self.hops -= 1;
            }
            self.start(i, false);
            return true;
        }
        // Discovery: only once no known leg is left.
        if self.legs.iter().any(|l| !l.explore) {
            return false;
        }
        if !self.discovering {
            self.discovering = true;
            if replay {
                self.hops = self.explore.len();
            }
        }
        let Some(&i) = self.explore.front() else {
            return false;
        };
        // The last actor only while no other leg is connected and waiting
        // for an answer (a hung connect does not hold it back).
        if i == self.group().last() && self.legs.iter().any(|l| l.stream.is_some()) {
            return false;
        }
        self.explore.pop_front();
        if replay {
            self.hops = self.hops.saturating_sub(1);
        }
        self.start(i, true);
        true
    }

    /// A stagger tick may start a leg: in discovery while nothing answered;
    /// in steady state only while no leg has connected.
    fn tick_allows(&self) -> bool {
        if self.discovering {
            true
        } else {
            self.legs.iter().all(|l| l.stream.is_none())
        }
    }

    fn drop_leg(&mut self, k: usize, verdict: Option<(&str, bool)>) {
        let leg = self.legs.remove(k);
        let now = Instant::now();
        match verdict {
            Some((r, connect)) => {
                self.just_failed = true;
                if let Some(g) = self.report() {
                    g.failure(leg.idx, now, connect, r)
                }
            }
            None => {
                if let Some(g) = self.report() {
                    g.lost(leg.idx, now)
                }
            }
        }
    }

    /// Keeps leg `keep` only. `requeue`: the others lost a connect race
    /// (no flight sent), so they go back in line for a rescue.
    fn drop_others(&mut self, keep: usize, requeue: bool) {
        let now = Instant::now();
        let fresh = self.ctx.group.epoch() == self.epoch;
        let legs: Vec<Leg> = self.legs.drain(..).collect();
        for (k, l) in legs.into_iter().enumerate().rev() {
            if k == keep {
                self.legs.push(l);
            } else if requeue && !self.ctx.group.is_down(l.idx) && !l.explore {
                self.known.push_front(l.idx);
            } else if requeue && l.explore {
                self.explore.push_front(l.idx);
            } else if fresh {
                self.ctx.group.lost(l.idx, now);
            }
        }
    }

    /// Progress without reading: connects, flight writes, timers, new legs.
    fn step(&mut self, cx: &mut Context<'_>) -> bool {
        let mut changed = false;
        let p = self.group().params().clone();
        let mut k = 0;
        while k < self.legs.len() {
            // Connecting.
            let polled = self.legs[k]
                .connecting
                .as_ref()
                .map(|c| c.lock().unwrap().as_mut().poll(cx));
            if let Some(r) = polled {
                match r {
                    Poll::Pending => {}
                    Poll::Ready(Ok(s)) => {
                        let leg = &mut self.legs[k];
                        leg.connecting = None;
                        leg.stream = Some(s);
                        leg.since = Some(Instant::now());
                        let idx = leg.idx;
                        if let Some(g) = self.report() {
                            g.established(idx, Instant::now());
                        }
                        changed = true;
                        if !self.discovering || self.kind == Flight::Single {
                            // First connected carries (steady state, or a
                            // flight that goes to one leg only); in a retry
                            // race the retry may still win within the grace.
                            let connected = self.legs.iter().filter(|l| l.stream.is_some()).count();
                            let is_retry = Some(idx) == self.retry;
                            if (connected == 1 && !self.holding())
                                || (is_retry && self.grace.is_some())
                            {
                                let requeue = self.kind == Flight::Empty;
                                self.grace = None;
                                self.drop_others(k, requeue);
                                k = 0;
                                continue;
                            }
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        self.drop_leg(k, Some((&reason("connect", &e), true)));
                        changed = true;
                        continue;
                    }
                }
            }
            let carry = self.kind != Flight::Single || self.legs.len() == 1;
            let flight_len = self.flight.len();
            let leg = &mut self.legs[k];
            if let (Some(s), true) = (leg.stream.as_mut(), carry) {
                // The flight.
                let mut err = None;
                while leg.sent < flight_len {
                    match Pin::new(&mut *s).poll_write(cx, &self.flight[leg.sent..]) {
                        Poll::Ready(Ok(0)) => {
                            err = Some(io::Error::from(io::ErrorKind::WriteZero));
                            break;
                        }
                        Poll::Ready(Ok(n)) => {
                            if leg.timer.is_none() && !self.won {
                                leg.timer = Some(Mutex::new(Box::pin(tokio::time::sleep(
                                    p.response_timeout,
                                ))));
                            }
                            leg.sent += n;
                            self.sent_any = true;
                            changed = true;
                        }
                        Poll::Ready(Err(e)) => {
                            err = Some(e);
                            break;
                        }
                        Poll::Pending => break,
                    }
                }
                if err.is_none()
                    && self.want_shutdown
                    && !leg.shut
                    && leg.sent == flight_len
                    && Pin::new(&mut *s).poll_shutdown(cx).is_ready()
                {
                    leg.shut = true;
                }
                if let Some(e) = err {
                    let r = reason("write", &e);
                    let connect = leg.sent == 0;
                    self.drop_leg(k, Some((&r, connect)));
                    self.unbind(&e);
                    changed = true;
                    continue;
                }
            }
            // The response timer.
            let leg = &mut self.legs[k];
            let fired = leg
                .timer
                .as_ref()
                .is_some_and(|t| t.lock().unwrap().as_mut().poll(cx).is_ready());
            if fired {
                self.drop_leg(k, Some(("no response", false)));
                changed = true;
                continue;
            }
            k += 1;
        }
        // The retry race's grace ran out: the connected leg carries.
        let grace_over = self
            .grace
            .as_ref()
            .is_some_and(|t| t.lock().unwrap().as_mut().poll(cx).is_ready());
        if grace_over || (self.grace.is_some() && !self.retry_pending()) {
            self.grace = None;
            if let Some(k) = self.legs.iter().position(|l| l.stream.is_some()) {
                if self.legs.iter().filter(|l| l.stream.is_some()).count() == 1 && !self.discovering
                {
                    let requeue = self.kind == Flight::Empty;
                    self.drop_others(k, requeue);
                }
            }
            changed = true;
        }
        // New legs: at once after a failure left room, or on the stagger.
        loop {
            let tick = self.next_start.lock().unwrap().as_mut().poll(cx).is_ready();
            if tick && self.tick_allows() && self.start_next() {
                changed = true;
                continue;
            }
            // One failure buys one immediate start.
            if (self.legs.is_empty() || self.just_failed) && self.start_next() {
                self.just_failed = false;
                changed = true;
                continue;
            }
            break;
        }
        self.just_failed = false;
        if self.legs.is_empty() && self.dead.is_none() {
            self.dead = Some(io::ErrorKind::ConnectionRefused);
            // A reader polling must see it now, not at the next timer.
            changed = true;
        }
        if changed {
            if let Some(w) = self.write_waker.take() {
                w.wake();
            }
        }
        changed
    }

    /// The retry leg is still connecting.
    fn retry_pending(&self) -> bool {
        self.retry.is_some_and(|r| {
            self.legs
                .iter()
                .any(|l| l.idx == r && l.connecting.is_some())
        })
    }

    /// In a retry race the current actor connected first and the retry has
    /// `retry-grace` ([`super::Params::retry_grace`]) left to connect (and win).
    fn holding(&self) -> bool {
        self.grace.is_some() && self.retry_pending()
    }

    fn poll_connected(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let changed = self.step(cx);
            if self.legs.iter().any(|l| l.stream.is_some()) && !self.holding() {
                return Poll::Ready(Ok(()));
            }
            if self.dead.is_some() {
                return Poll::Ready(Err(io::Error::other(format!(
                    "standby [{}]: every actor failed",
                    self.group().tag()
                ))));
            }
            if !changed {
                return Poll::Pending;
            }
        }
    }

    /// The winner's connection is young enough that dying counts.
    fn young(&self) -> bool {
        self.legs
            .first()
            .and_then(|l| l.since)
            .is_some_and(|t| t.elapsed() < self.group().params().early_death)
    }

    fn settle(&mut self, failed: Option<&str>) {
        if self.settled || !self.won {
            return;
        }
        self.settled = true;
        let idx = self.legs[0].idx;
        let now = Instant::now();
        let Some(g) = self.report() else { return };
        match failed {
            Some(r) => g.failure(idx, now, false, r),
            None => g.success(idx, now),
        }
    }

    fn check_age(&mut self) {
        if self.won && !self.settled && !self.young() {
            self.settle(None);
        }
    }

    /// A write, flush or shutdown error on the one leg left: scored like a
    /// read error (before an answer a failure if bytes went out; after one,
    /// by `early-death`), and the connection is over.
    fn io_error(&mut self, e: &io::Error) {
        if self.won {
            if self.young() {
                self.settle(Some("died after answering"));
            } else {
                self.settle(None);
            }
            return;
        }
        if self.legs.is_empty() {
            return;
        }
        let verdict = reason("reset without a response", e);
        if self.sent_any {
            self.drop_leg(0, Some((&verdict, false)));
        } else {
            self.drop_leg(0, None);
        }
        self.legs.clear();
        self.dead = Some(e.kind());
    }

    fn dead_err(&self) -> io::Error {
        io::Error::new(
            self.dead.unwrap_or(io::ErrorKind::Other),
            format!("standby [{}]: no actor answered", self.group().tag()),
        )
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.won {
                // Finish the flight first (a server that spoke first).
                me.step(cx);
                let Some(s) = me.legs.first_mut().and_then(|l| l.stream.as_mut()) else {
                    return Poll::Ready(Err(me.dead_err()));
                };
                let before = buf.filled().len();
                let r = Pin::new(s).poll_read(cx, buf);
                match &r {
                    Poll::Ready(Ok(())) if buf.filled().len() > before => me.check_age(),
                    Poll::Ready(Ok(())) => me.settle(None),
                    Poll::Ready(Err(_)) => {
                        if me.young() {
                            me.settle(Some("died after answering"));
                        } else {
                            me.settle(None);
                        }
                    }
                    Poll::Pending => {}
                }
                return r;
            }
            if me.dead.is_some() {
                return Poll::Ready(Err(me.dead_err()));
            }
            let mut changed = me.step(cx);
            let mut k = 0;
            while k < me.legs.len() {
                let Some(s) = me.legs[k].stream.as_mut() else {
                    k += 1;
                    continue;
                };
                let before = buf.filled().len();
                match Pin::new(s).poll_read(cx, buf) {
                    Poll::Ready(Ok(())) if buf.filled().len() > before => {
                        // The winner.
                        me.drop_others(k, false);
                        me.won = true;
                        let leg = &mut me.legs[0];
                        leg.timer = None;
                        let idx = leg.idx;
                        if let Some(g) = me.report() {
                            g.responded(idx, Instant::now());
                        }
                        debug!(
                            "standby [{}] handles [{}:{}] to [{}]",
                            me.group().tag(),
                            me.sess.network,
                            me.sess.destination,
                            me.ctx.actors[idx].tag()
                        );
                        if let Some(w) = me.write_waker.take() {
                            w.wake();
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(())) => {
                        if me.legs[k].sent > 0 {
                            me.drop_leg(k, Some(("closed without a response", false)));
                        } else {
                            me.drop_leg(k, None);
                        }
                        changed = true;
                    }
                    Poll::Ready(Err(e)) => {
                        let r = reason("reset without a response", &e);
                        if me.legs[k].sent > 0 {
                            me.drop_leg(k, Some((&r, false)));
                        } else {
                            me.drop_leg(k, None);
                        }
                        me.unbind(&e);
                        changed = true;
                    }
                    Poll::Pending => k += 1,
                }
            }
            if !changed {
                return Poll::Pending;
            }
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.dead.is_some() {
            return Poll::Ready(Err(me.dead_err()));
        }
        if me.kind == Flight::Empty && !buf.is_empty() && !me.won {
            me.kind = if is_client_hello(buf) {
                Flight::Hello
            } else {
                Flight::Single
            };
            if me.kind == Flight::Single {
                // One leg only: the first connected one, if any.
                if let Some(k) = me.legs.iter().position(|l| l.stream.is_some()) {
                    me.drop_others(k, false);
                }
            }
        }
        // Buffered while the flight may still be (re)sent.
        let flushed =
            me.legs.len() == 1 && me.legs[0].stream.is_some() && me.legs[0].sent == me.flight.len();
        let direct = (me.won || me.kind == Flight::Single) && flushed;
        if !direct {
            if me.flight.len() + buf.len() <= MAX_FLIGHT {
                me.flight.extend_from_slice(buf);
                me.step(cx);
                return Poll::Ready(Ok(buf.len()));
            }
            if me.kind == Flight::Hello {
                // Too long to replay: one leg from here on.
                me.kind = Flight::Single;
                if let Some(k) = me
                    .legs
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| l.stream.is_some())
                    .max_by_key(|(_, l)| l.sent)
                    .map(|(k, _)| k)
                {
                    me.drop_others(k, false);
                }
            }
            me.step(cx);
            me.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let rt = me.group().params().response_timeout;
        let leg = &mut me.legs[0];
        let r = Pin::new(leg.stream.as_mut().unwrap()).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            if !me.won && n > 0 {
                // Still unanswered: keep the flight count in step.
                me.flight.extend_from_slice(&buf[..n]);
                leg.sent += n;
                me.sent_any = true;
                if leg.timer.is_none() {
                    leg.timer = Some(Mutex::new(Box::pin(tokio::time::sleep(rt))));
                }
                if me.flight.len() > MAX_FLIGHT {
                    me.flight.clear();
                    leg.sent = 0;
                    me.truncated = true;
                }
            }
        }
        if let Poll::Ready(Err(e)) = &r {
            // Not sent (see `unbind`): the flight, with these bytes, goes
            // to the next leg instead of ending the connection.
            if me.kind == Flight::Single
                && !me.won
                && !me.truncated
                && FlightNotSent::is(e)
                && me.flight.len() + buf.len() <= MAX_FLIGHT
            {
                let v = reason("reset without a response", e);
                me.drop_leg(0, Some((&v, false)));
                me.unbind(e);
                me.flight.extend_from_slice(buf);
                me.step(cx);
                if me.dead.is_some() {
                    return Poll::Ready(Err(me.dead_err()));
                }
                return Poll::Ready(Ok(buf.len()));
            }
            me.io_error(e);
        }
        me.check_age();
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.dead.is_some() {
            return Poll::Ready(Err(me.dead_err()));
        }
        let single = me.won || me.legs.len() == 1;
        let r = match me.legs.first_mut().and_then(|l| l.stream.as_mut()) {
            Some(s) if single => Pin::new(s).poll_flush(cx),
            _ => Poll::Ready(Ok(())),
        };
        if let Poll::Ready(Err(e)) = &r {
            me.io_error(e);
        }
        r
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        me.want_shutdown = true;
        if me.won {
            if let Some(l) = me.legs.first_mut() {
                if l.sent == me.flight.len() || me.flight.is_empty() {
                    if let Some(s) = l.stream.as_mut() {
                        return Pin::new(s).poll_shutdown(cx);
                    }
                }
            }
        }
        me.step(cx);
        Poll::Ready(Ok(()))
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if self.won {
            // Closed by the client after an answer: served.
            self.settle(None);
            return;
        }
        let now = Instant::now();
        let fresh = self.ctx.group.epoch() == self.epoch;
        for l in self.legs.drain(..) {
            if fresh {
                self.ctx.group.lost(l.idx, now);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_is_recognised() {
        assert!(is_client_hello(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00]));
        assert!(is_client_hello(&[0x16, 0x03, 0x03, 0x00, 0x10, 0x01]));
        assert!(!is_client_hello(b"GET / HTTP/1.1\r\n"));
        assert!(!is_client_hello(&[0x16, 0x03, 0x05, 0x00, 0x10, 0x01]));
        assert!(
            !is_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x10, 0x02]),
            "not a ClientHello"
        );
        assert!(!is_client_hello(&[0x16, 0x03]));
    }
}
