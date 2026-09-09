use std::io;

use async_trait::async_trait;
use tracing::Instrument;

use crate::{proxy::*, session::Session};

use super::plan::{Input, Kind, Plan};

pub struct Handler {
    pub actors: Vec<AnyOutboundHandler>,
}

/// What the chain is carrying between two actors.
///
/// A chain that ends in datagrams may still start as a stream: a datagram
/// tunnelled over a reliable protocol is a stream until the actor that
/// tunnels it, and there is no way back.
enum Carried {
    Nothing,
    Stream(AnyStream),
    Datagram(AnyOutboundDatagram),
}

impl Carried {
    fn from(transport: Option<AnyOutboundTransport>) -> Self {
        match transport {
            Some(OutboundTransport::Stream(stream)) => Carried::Stream(stream),
            Some(OutboundTransport::Datagram(datagram)) => Carried::Datagram(datagram),
            None => Carried::Nothing,
        }
    }

    fn input(&self) -> Input {
        match self {
            Carried::Nothing => Input::Nothing,
            Carried::Stream(_) => Input::Stream,
            Carried::Datagram(_) => Input::Datagram,
        }
    }
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        // What is dialled does not depend on what the chain is handed: the
        // first actor that names an endpoint names it either way.
        Plan::for_datagram(&self.actors, Input::Nothing).dial
    }

    /// What the *first* actor accepts, which is what an enclosing chain is
    /// asking about when it decides whether it may convert a stream into a
    /// datagram before reaching this one. Not what this chain produces.
    fn transport_type(&self) -> DatagramTransportType {
        self.actors
            .first()
            .and_then(|actor| {
                actor
                    .datagram()
                    .ok()
                    .map(|handler| handler.transport_type())
            })
            .unwrap_or(DatagramTransportType::Unknown)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        let mut carried = Carried::from(transport);
        let plan = Plan::for_datagram(&self.actors, carried.input());

        for stage in &plan.stages {
            let actor = &self.actors[stage.index];
            let sess = stage.session(sess);
            carried = match stage.kind {
                Kind::Datagram => {
                    let transport = match carried {
                        Carried::Nothing => None,
                        Carried::Stream(stream) => Some(OutboundTransport::Stream(stream)),
                        Carried::Datagram(datagram) => Some(OutboundTransport::Datagram(datagram)),
                    };
                    Carried::Datagram(
                        actor
                            .datagram()
                            .map_err(|err| stage.error(err))?
                            .handle(&sess, transport)
                            .instrument(tracing::Span::current())
                            .await
                            .map_err(|err| stage.error(err))?,
                    )
                }
                Kind::Stream => {
                    let stream = match carried {
                        Carried::Nothing => None,
                        Carried::Stream(stream) => Some(stream),
                        // The actor before produced a datagram and this one
                        // speaks only streams. Nothing can be done with it,
                        // and silently dropping it is how this used to end as
                        // "invalid input" from an actor that was handed
                        // nothing.
                        Carried::Datagram(_) => {
                            return Err(stage
                                .failed("cannot carry the datagram the actor before it produced"))
                        }
                    };
                    Carried::Stream(
                        actor
                            .stream()
                            .map_err(|err| stage.error(err))?
                            .handle(&sess, None, stream)
                            .instrument(tracing::Span::current())
                            .await
                            .map_err(|err| stage.error(err))?,
                    )
                }
            };
        }

        match carried {
            Carried::Datagram(datagram) => Ok(datagram),
            _ => Err(io::Error::other(format!(
                "chain [{}] carries no datagrams: no actor in it turns a stream into one",
                plan.stages
                    .iter()
                    .map(|stage| stage.tag.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }
}
