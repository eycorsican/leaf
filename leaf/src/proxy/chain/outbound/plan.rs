//! What each actor in a chain is asked to do, worked out before anything is
//! dialled.
//!
//! A chain has to answer three questions about every actor: which of its two
//! handlers runs, what address it is told to reach, and which one of them the
//! caller should dial before any of it starts. The answers depend on each
//! other -- whether a stream becomes a datagram at actor `i` depends on what
//! every actor after it can carry, and what actor `i` is told to reach depends
//! on which actor after it names an endpoint -- so they are worked out here,
//! in one pass, and the handlers are left doing nothing but I/O.
//!
//! Nothing here touches the network, which is the point: the rules a chain
//! follows are a function of its actors and can be tested as one.

use std::convert::TryFrom;
use std::io;

use crate::proxy::*;
use crate::session::{Session, SocksAddr};

/// Which of an actor's two handlers a stage runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Stream,
    Datagram,
}

/// What the chain was handed to start from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Input {
    Nothing,
    Stream,
    Datagram,
}

/// One actor's part in the chain.
pub(super) struct Stage {
    pub index: usize,
    pub tag: String,
    pub kind: Kind,
    /// The address to put in this actor's session: the endpoint of the next
    /// actor that names one.
    ///
    /// `None` leaves the session's own destination in place, which is what the
    /// last actor needs -- it is the one talking to where the client wanted to
    /// go. This is how a chain relays: every actor but the last is told to
    /// reach the next hop, and says so in its own protocol.
    pub next_hop: Option<SocksAddr>,
}

impl Stage {
    /// The session this actor sees.
    pub fn session(&self, sess: &Session) -> Session {
        let mut sess = sess.clone();
        if let Some(next_hop) = self.next_hop.as_ref() {
            sess.destination = next_hop.clone();
            // The sniffed domains describe the destination that has just been
            // replaced, so they no longer describe anything.
            sess.dns_sniffed_domain = None;
            sess.http_sniffed_domain = None;
            sess.tls_sniffed_domain = None;
        }
        sess
    }

    /// Names the stage in an error, so a failure says which actor produced it
    /// rather than only which chain contained it.
    pub fn error(&self, err: io::Error) -> io::Error {
        io::Error::new(
            err.kind(),
            format!("chain actor {} [{}]: {}", self.index, self.tag, err),
        )
    }

    pub fn failed(&self, what: &str) -> io::Error {
        io::Error::other(format!(
            "chain actor {} [{}]: {}",
            self.index, self.tag, what
        ))
    }
}

pub(super) struct Plan {
    pub stages: Vec<Stage>,
    /// What the caller should dial before the first stage runs.
    pub dial: OutboundConnect,
}

impl Plan {
    /// A chain carrying a stream: every actor wraps the one before it.
    pub fn for_stream(actors: &[AnyOutboundHandler]) -> Plan {
        Plan::build(actors, vec![Kind::Stream; actors.len()])
    }

    /// A chain carrying datagrams, which may still run some of its actors as
    /// streams: a datagram tunnelled over a reliable transport is a stream
    /// until the actor that tunnels it.
    pub fn for_datagram(actors: &[AnyOutboundHandler], input: Input) -> Plan {
        Plan::build(actors, datagram_kinds(actors, input))
    }

    fn build(actors: &[AnyOutboundHandler], kinds: Vec<Kind>) -> Plan {
        let resolved = resolve(actors, &kinds);
        let stages = actors
            .iter()
            .enumerate()
            .map(|(index, actor)| Stage {
                index,
                tag: actor.tag().to_string(),
                kind: kinds[index],
                next_hop: proxy_address(&resolved[index + 1]),
            })
            .collect();
        Plan {
            stages,
            dial: resolved[0].clone(),
        }
    }

    pub fn last(&self) -> usize {
        self.stages.len().saturating_sub(1)
    }
}

/// Which handler each actor runs when the chain is carrying datagrams.
///
/// Folded forwards, because it depends on what the actor before produced: an
/// actor holding a datagram keeps it, and an actor holding a stream converts
/// only where everything after it can carry an unreliable datagram. Converting
/// too early would strand the actors that need a stream, and there is no way
/// back.
fn datagram_kinds(actors: &[AnyOutboundHandler], input: Input) -> Vec<Kind> {
    let unreliable = unreliable_from(actors);
    let mut held = match input {
        Input::Nothing => None,
        Input::Stream => Some(Kind::Stream),
        Input::Datagram => Some(Kind::Datagram),
    };
    let mut kinds = Vec::with_capacity(actors.len());
    for (index, actor) in actors.iter().enumerate() {
        let kind = if actor.datagram().is_err() {
            // Nothing to run a datagram with. If one is being held this chain
            // cannot carry it, which the executor reports against this actor.
            Kind::Stream
        } else if held == Some(Kind::Datagram) || unreliable[index + 1] {
            Kind::Datagram
        } else {
            Kind::Stream
        };
        held = Some(kind);
        kinds.push(kind);
    }
    kinds
}

/// Whether every actor from `i` onwards can carry an unreliable datagram.
///
/// Vacuously true past the end, which is what lets the last actor be the one
/// that turns a stream into a datagram.
fn unreliable_from(actors: &[AnyOutboundHandler]) -> Vec<bool> {
    let mut unreliable = vec![true; actors.len() + 1];
    for index in (0..actors.len()).rev() {
        let carries = actors[index]
            .datagram()
            .map(|handler| handler.transport_type() == DatagramTransportType::Unreliable)
            .unwrap_or(false);
        unreliable[index] = carries && unreliable[index + 1];
    }
    unreliable
}

/// The endpoint each suffix of the chain names, resolved from the back.
///
/// `resolved[i]` is what the actors from `i` onwards want dialled: the first
/// one of them that names something. `Next` is an actor saying "whatever the
/// one after me says", which is how a transport that wraps rather than dials
/// -- tls, ws -- leaves the address to the protocol inside it.
fn resolve(actors: &[AnyOutboundHandler], kinds: &[Kind]) -> Vec<OutboundConnect> {
    let mut resolved = vec![OutboundConnect::Unknown; actors.len() + 1];
    for index in (0..actors.len()).rev() {
        resolved[index] = match connect_addr(&actors[index], kinds[index]) {
            OutboundConnect::Next => resolved[index + 1].clone(),
            named => named,
        };
    }
    resolved
}

/// What one actor names, asked of the handler its stage runs and falling back
/// to the other one: an actor may name its endpoint on only one of its sides.
fn connect_addr(actor: &AnyOutboundHandler, kind: Kind) -> OutboundConnect {
    let (mine, other) = match kind {
        Kind::Stream => (
            actor.stream().ok().map(|h| h.connect_addr()),
            actor.datagram().ok().map(|h| h.connect_addr()),
        ),
        Kind::Datagram => (
            actor.datagram().ok().map(|h| h.connect_addr()),
            actor.stream().ok().map(|h| h.connect_addr()),
        ),
    };
    mine.or(other).unwrap_or(OutboundConnect::Unknown)
}

/// Only a proxy endpoint replaces an actor's destination. `Direct` means the
/// actor goes to the session's own destination, which is already there.
fn proxy_address(connect: &OutboundConnect) -> Option<SocksAddr> {
    match connect {
        OutboundConnect::Proxy(_, address, port) => {
            SocksAddr::try_from((address.clone(), *port)).ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;

    use crate::proxy::outbound::HandlerBuilder;

    use super::*;

    /// An actor that names an endpoint, or does not, and carries streams,
    /// datagrams or both. Enough to ask a plan every question it answers.
    struct Stream(OutboundConnect);

    #[async_trait]
    impl OutboundStreamHandler for Stream {
        fn connect_addr(&self) -> OutboundConnect {
            self.0.clone()
        }

        async fn handle<'a>(
            &'a self,
            _sess: &'a Session,
            _lhs: Option<&mut AnyStream>,
            _stream: Option<AnyStream>,
        ) -> io::Result<AnyStream> {
            unreachable!("a plan runs no I/O")
        }
    }

    struct Datagram(OutboundConnect, DatagramTransportType);

    #[async_trait]
    impl OutboundDatagramHandler for Datagram {
        fn connect_addr(&self) -> OutboundConnect {
            self.0.clone()
        }

        fn transport_type(&self) -> DatagramTransportType {
            self.1
        }

        async fn handle<'a>(
            &'a self,
            _sess: &'a Session,
            _transport: Option<AnyOutboundTransport>,
        ) -> io::Result<AnyOutboundDatagram> {
            unreachable!("a plan runs no I/O")
        }
    }

    fn proxy(port: u16) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, "127.0.0.1".to_string(), port)
    }

    /// A transport: wraps whatever is inside it and names no endpoint of its
    /// own, like tls or ws.
    fn wrapper(tag: &str) -> AnyOutboundHandler {
        HandlerBuilder::default()
            .tag(tag.to_string())
            .stream_handler(Arc::new(Stream(OutboundConnect::Next)))
            .build()
    }

    /// A protocol that dials, and tunnels datagrams over the stream it has,
    /// like trojan.
    fn protocol(tag: &str, port: u16) -> AnyOutboundHandler {
        HandlerBuilder::default()
            .tag(tag.to_string())
            .stream_handler(Arc::new(Stream(proxy(port))))
            .datagram_handler(Arc::new(Datagram(
                proxy(port),
                DatagramTransportType::Reliable,
            )))
            .build()
    }

    /// A protocol whose datagrams are datagrams, like shadowsocks over UDP.
    fn unreliable(tag: &str, port: u16) -> AnyOutboundHandler {
        HandlerBuilder::default()
            .tag(tag.to_string())
            .stream_handler(Arc::new(Stream(proxy(port))))
            .datagram_handler(Arc::new(Datagram(
                proxy(port),
                DatagramTransportType::Unreliable,
            )))
            .build()
    }

    fn hops(plan: &Plan) -> Vec<Option<String>> {
        plan.stages
            .iter()
            .map(|stage| stage.next_hop.as_ref().map(|hop| hop.to_string()))
            .collect()
    }

    #[test]
    fn the_endpoint_dialled_is_the_first_one_named() {
        let actors = vec![wrapper("tls"), wrapper("ws"), protocol("trojan", 3001)];
        let plan = Plan::for_stream(&actors);
        assert!(
            matches!(plan.dial, OutboundConnect::Proxy(_, _, 3001)),
            "the transports name nothing, so the protocol inside them decides"
        );
    }

    /// Every actor but the last is told to reach the next hop; the last is
    /// left with the session's own destination. This is the whole of relaying.
    #[test]
    fn each_actor_is_told_to_reach_the_next_one_that_names_an_endpoint() {
        let actors = vec![
            protocol("hop1", 3001),
            protocol("hop2", 3002),
            protocol("hop3", 3003),
        ];
        let plan = Plan::for_stream(&actors);
        assert_eq!(
            hops(&plan),
            vec![
                Some("127.0.0.1:3002".to_string()),
                Some("127.0.0.1:3003".to_string()),
                None,
            ]
        );
    }

    #[test]
    fn a_transport_leaves_the_destination_to_what_is_inside_it() {
        let actors = vec![
            wrapper("ws"),
            protocol("trojan", 3001),
            protocol("ss", 3002),
        ];
        let plan = Plan::for_stream(&actors);
        assert_eq!(
            hops(&plan),
            vec![
                // ws is followed by trojan, which names 3001... but the chain
                // is dialled at 3001 already, so what ws is told is where the
                // *next* actor goes: trojan's own endpoint.
                Some("127.0.0.1:3001".to_string()),
                Some("127.0.0.1:3002".to_string()),
                None,
            ]
        );
    }

    /// A datagram tunnelled over a reliable protocol stays a stream until the
    /// actor that tunnels it.
    #[test]
    fn a_reliable_protocol_carries_datagrams_over_its_stream() {
        let actors = vec![wrapper("ws"), protocol("trojan", 3001)];
        let plan = Plan::for_datagram(&actors, Input::Nothing);
        let kinds: Vec<Kind> = plan.stages.iter().map(|stage| stage.kind).collect();
        assert_eq!(kinds, vec![Kind::Stream, Kind::Datagram]);
    }

    /// And an unreliable one takes the datagram as it is, from the first actor
    /// that can.
    #[test]
    fn an_unreliable_chain_stays_a_datagram_throughout() {
        let actors = vec![unreliable("ss1", 3001), unreliable("ss2", 3002)];
        let plan = Plan::for_datagram(&actors, Input::Nothing);
        let kinds: Vec<Kind> = plan.stages.iter().map(|stage| stage.kind).collect();
        assert_eq!(kinds, vec![Kind::Datagram, Kind::Datagram]);
    }

    /// A transport that speaks only streams in front of a datagram protocol:
    /// the plan runs it as a stream, and nothing after it can turn that back
    /// into what shadowsocks needs. The executor is what reports it, but the
    /// shape is decided here.
    #[test]
    fn a_stream_only_transport_cannot_lead_to_an_unreliable_protocol() {
        let actors = vec![wrapper("ws"), unreliable("ss", 3001)];
        let plan = Plan::for_datagram(&actors, Input::Nothing);
        let kinds: Vec<Kind> = plan.stages.iter().map(|stage| stage.kind).collect();
        assert_eq!(
            kinds,
            vec![Kind::Stream, Kind::Datagram],
            "ss converts the stream it is given, which is not a UDP association"
        );
    }

    #[test]
    fn an_empty_chain_names_nothing() {
        let plan = Plan::for_stream(&[]);
        assert!(matches!(plan.dial, OutboundConnect::Unknown));
        assert!(plan.stages.is_empty());
    }
}
