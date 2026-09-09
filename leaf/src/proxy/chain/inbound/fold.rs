//! Running a chain's actors over an inbound transport.
//!
//! Four places used to do this: the stream handler, the datagram handler, and
//! one function per shape for the actors that run behind a multiplexed
//! transport. They agreed on the interesting parts and differed in the rest --
//! one panicked where another returned, one timed out each actor and the
//! others did not, and each had its own way of saying "invalid transport"
//! without saying which actor produced it.
//!
//! This is that fold, once. What a chain does is unwrap: each actor takes what
//! the one before it produced and hands back something more specific, until
//! either the actors run out or one of them produces a transport that carries
//! others -- amux, quic -- in which case the actors that have not run belong
//! to each of *those*, not to the thing yielding them.

use std::io;
use std::time::Duration;

use tokio::time::timeout;
use tracing::warn;

use crate::proxy::*;

/// Where a fold stopped.
pub(super) enum Folded {
    /// Every actor ran.
    Done(AnyBaseInboundTransport),
    /// An actor produced a multiplexed transport. The actors from `next`
    /// onwards have not run: they belong to what it yields.
    Incoming(AnyIncomingTransport, usize),
}

/// Runs `actors` over `transport`, in order.
///
/// `handshake_timeout` bounds each actor when there is one to bound: the
/// actors running behind a multiplexed transport are handshaking with a peer
/// that may never finish, while the ones on the accept path are already bound
/// by the listener.
pub(super) async fn fold(
    transport: AnyBaseInboundTransport,
    actors: &[AnyInboundHandler],
    handshake_timeout: Option<Duration>,
) -> io::Result<Folded> {
    let mut carried = transport;

    for (index, actor) in actors.iter().enumerate() {
        let named = |what: String| -> io::Error {
            io::Error::other(format!("chain actor {} [{}]: {}", index, actor.tag(), what))
        };
        let attributed = |err: io::Error| -> io::Error {
            io::Error::new(
                err.kind(),
                format!("chain actor {} [{}]: {}", index, actor.tag(), err),
            )
        };

        let (was_stream, produced) = match carried {
            AnyBaseInboundTransport::Stream(stream, sess) => {
                let handler = actor.stream().map_err(attributed)?;
                let handled = handler.handle(sess, stream);
                (
                    true,
                    run(handled, handshake_timeout).await.map_err(attributed)?,
                )
            }
            AnyBaseInboundTransport::Datagram(socket, _) => {
                let handler = actor.datagram().map_err(attributed)?;
                let handled = handler.handle(socket);
                (
                    false,
                    run(handled, handshake_timeout).await.map_err(attributed)?,
                )
            }
            AnyBaseInboundTransport::Empty => {
                return Err(named("nothing was handed to it".to_string()))
            }
        };

        carried = match produced {
            InboundTransport::Stream(stream, sess) => AnyBaseInboundTransport::Stream(stream, sess),
            InboundTransport::Datagram(socket, sess) => {
                if was_stream {
                    // A stream that has become a datagram is the end of the
                    // chain: there is no way back to a stream, and a
                    // stream-initiated datagram cannot be handed to another
                    // datagram actor on this node.
                    let remaining = &actors[index + 1..];
                    if !remaining.is_empty() {
                        warn!(
                            "chain actor {} [{}] produced a datagram, so [{}] will not run",
                            index,
                            actor.tag(),
                            remaining
                                .iter()
                                .map(|actor| actor.tag().as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    }
                    return Ok(Folded::Done(AnyBaseInboundTransport::Datagram(
                        socket, sess,
                    )));
                }
                AnyBaseInboundTransport::Datagram(socket, sess)
            }
            InboundTransport::Incoming(incoming) => {
                return Ok(Folded::Incoming(incoming, index + 1))
            }
            InboundTransport::Empty => return Err(named("produced nothing".to_string())),
        };
    }

    Ok(Folded::Done(carried))
}

/// Runs one actor, under a deadline when there is one.
async fn run<F>(handling: F, handshake_timeout: Option<Duration>) -> io::Result<AnyInboundTransport>
where
    F: std::future::Future<Output = io::Result<AnyInboundTransport>>,
{
    match handshake_timeout {
        Some(within) => timeout(within, handling)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?,
        None => handling.await,
    }
}
