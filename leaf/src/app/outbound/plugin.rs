//! The host side of the C ABI plugin system: it loads plugin libraries and
//! turns the engines they export into ordinary leaf outbound handlers.
//!
//! A plugin is a shared library exporting `leaf_plugin_get_descriptor`, which
//! hands back a stream vtable, a datagram vtable, or both. [`ExternalHandlers`]
//! loads one per configured `plugin` outbound -- caching by path, so one
//! library shared by several outbounds is opened once -- validates the
//! descriptor, and registers a handler under the outbound's tag.
//!
//! A plugin engine is a codec, not a transport. The host keeps the socket and
//! all the I/O; the engine only turns bytes into other bytes:
//!
//! * [`EngineStream`] wraps a stream instance as an [`AsyncRead`] +
//!   [`AsyncWrite`]. Each poll reads `poll_state`, feeds the engine what it
//!   asked for, drains what it produced, and moves the result to or from the
//!   socket. The two directions run independently: a congested socket parks the
//!   write side without stopping the read side, which is what keeps a saturated
//!   upload from deadlocking against a peer waiting on decoded bytes.
//! * [`EngineDatagram`] wraps an unreliable datagram instance, one whole frame
//!   per packet, over the UDP transport the host opened.
//! * [`EngineReliableDatagram`] wraps a reliable one, running the engine's
//!   framing over the stream transport the chain already established, so a
//!   single read may hold a partial frame or several.
//!
//! An engine that cannot make progress from anything the host can hand it
//! reports [`STREAM_ENGINE_STATE_BLOCKED`] and later calls the `wake` callback,
//! which wakes the wakers in [`PluginInstanceContext`]. Everything else is
//! backpressure and resolves itself on the next poll.
//!
//! A plugin runs in the host process with the host's privileges, so loading one
//! is as consequential as running a binary: nothing here contains a plugin that
//! is actually hostile. What the host does defend against is a plugin that is
//! merely wrong. The descriptor is checked for the ABI major version and for
//! every entry the host will call, sizes and lengths an engine reports are
//! rejected when they exceed the buffers they describe, size hints are clamped,
//! the buffers here have caps -- an engine that neither consumes nor produces
//! anything fails its connection instead of growing them without bound -- no
//! string an engine passes over is scanned further than the host's own cap,
//! every callback runs behind a panic barrier so that a mistake costs a log
//! line rather than the process, and `host_ctx` is an opaque id rather than a
//! pointer, so an engine that calls back after it was destroyed loses the call
//! instead of corrupting the host.
//!
//! Those caps are also what bounds the memory a plugin outbound can hold: a
//! stream keeps at most `MAX_BUFFERED_NET_INPUT` of undecoded input,
//! `MAX_BUFFERED_APP_OUTPUT` of decoded output and `MAX_NET_FLUSH_PER_POLL` on
//! its way to the socket, per connection.
//!
//! Before any of that, the file itself has to be one the operator can vouch
//! for: the path is resolved rather than searched for, a library anyone on the
//! host can rewrite is refused, and an outbound may pin the digest it expects,
//! which is the only check here that still holds against someone who can write
//! the file.
//!
//! [`inspect_plugin`] runs exactly those checks, in the same order, without a
//! config file and without starting a proxy, and reports what the plugin
//! declares -- which is how an operator finds out whether a build will load,
//! what its outbound will have to give it, and what to pin it to, before it is
//! in the path of any traffic. `leaf --verify-plugin` is that function.
//!
//! What is still taken on trust, because nothing on this side can check it: the
//! truthfulness of each struct's `size` field, that the structs are suitably
//! aligned, that the vtable entries are real functions, and that the plugin
//! writes no more than the `produced` and `consumed` it goes on to report.
//!
//! The ABI itself, and the contract both sides have to keep, is documented in
//! the `leaf_plugin_abi` crate.

use std::collections::{BTreeSet, HashMap};
use std::ffi::{c_char, c_void, CStr, OsStr};
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::task::{Context, Poll};

use async_ffi::BorrowingFfiFuture;
use async_trait::async_trait;
use bytes::BytesMut;
use libloading::Library;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, info, warn};

use crate::{
    proxy::*,
    session::{Network, Session},
};

// The ABI itself lives in the dependency-free `leaf-plugin-abi` crate so that
// out-of-tree plugins can depend on it without linking a second copy of the
// proxy engine. Re-exported here to keep `leaf::app::outbound::plugin::*` the
// single import path for in-tree code.
pub use leaf_plugin_abi::*;

/// The host state an engine instance reaches through `host_ctx`.
///
/// The engine never holds this directly. It holds the id of a
/// [`PluginInstanceHandle`], which the callbacks resolve through
/// [`PLUGIN_INSTANCES`]; see there for why.
struct PluginInstanceContext {
    span: tracing::Span,
    plugin: String,
    /// Woken by an engine that reported `STREAM_ENGINE_STATE_BLOCKED`.
    ///
    /// Two of them because a stream can be split, leaving the read and write
    /// halves polled by different tasks; one waker would lose whichever
    /// registered first.
    read_waker: futures::task::AtomicWaker,
    write_waker: futures::task::AtomicWaker,
}

/// Every live instance context, keyed by the id its engine was given.
///
/// The ABI says `host_ctx` stops being valid once `destroy_instance` returns.
/// Handing the engine a pointer would turn a plugin that calls `wake` late --
/// out of contract, but an easy mistake for a plugin with threads of its own --
/// into a use-after-free inside the host. An id costs a lookup and turns the
/// same mistake into a dropped call.
/// Sharded, because every `log` call an engine makes takes a read lock here
/// and every instance that goes away takes a write lock. One lock would put
/// all of a busy proxy's plugin logging, and all of its connection teardown,
/// through the same place.
static PLUGIN_INSTANCES: LazyLock<[RwLock<PluginInstanceMap>; PLUGIN_INSTANCE_SHARDS]> =
    LazyLock::new(|| std::array::from_fn(|_| RwLock::new(HashMap::new())));

type PluginInstanceMap = HashMap<usize, Arc<PluginInstanceContext>>;

const PLUGIN_INSTANCE_SHARDS: usize = 16;

/// Every library mapped in this process that declared
/// [`PLUGIN_FLAG_EMBEDS_RUNTIME`].
///
/// Process-wide rather than per-[`ExternalHandlers`], because that is the scope
/// the question has: two nodes in one process, each with one such plugin, are
/// two runtimes just as surely as one node with two. It only ever grows, which
/// is correct -- these libraries are never unmapped.
static RUNTIME_LIBRARIES: LazyLock<Mutex<BTreeSet<PathBuf>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));

/// Records a runtime-embedding library and says whether this process now holds
/// more than one.
///
/// More than one is not refused. It is, for the runtimes we ship a plugin for,
/// a configuration their own projects decline to *guarantee* rather than one
/// known to break -- Go's, for instance, arbitrates faults between runtimes by
/// which module the faulting instruction is in, and holds up under the suite's
/// `hostile/go/a-fault-with-another-runtime-live`. Refusing it would break
/// chains that work today. But it is worth a line in the log, because it is
/// the first thing to look at when such a process misbehaves in a way nothing
/// else explains, and it is not otherwise visible anywhere.
fn note_runtime_library(path: &Path) -> Option<Vec<String>> {
    let mut libraries = RUNTIME_LIBRARIES.lock().unwrap();
    if !libraries.insert(path.to_path_buf()) || libraries.len() < 2 {
        return None;
    }
    Some(
        libraries
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
    )
}

/// The shard an id lives in. Ids are handed out consecutively, so the low bits
/// spread them evenly.
fn plugin_instance_shard(id: usize) -> &'static RwLock<PluginInstanceMap> {
    &PLUGIN_INSTANCES[id % PLUGIN_INSTANCE_SHARDS]
}

/// Source of instance ids. Starts at 1 so that a null `host_ctx` is never a
/// valid id, and never reuses a value, so a late call cannot land on the
/// instance that took its place.
static NEXT_PLUGIN_INSTANCE_ID: AtomicUsize = AtomicUsize::new(1);

/// A context registered in [`PLUGIN_INSTANCES`], deregistered when dropped.
///
/// Held by whichever wrapper owns the engine instance, and dropped after
/// `destroy_instance` has returned -- the point at which the ABI says the
/// callbacks stop being valid.
struct PluginInstanceHandle {
    id: usize,
    ctx: Arc<PluginInstanceContext>,
}

impl PluginInstanceHandle {
    fn register(ctx: PluginInstanceContext) -> Self {
        let ctx = Arc::new(ctx);
        // Relaxed is all this needs: the only requirement on the counter is
        // that no two registrations come away with the same value.
        let id = NEXT_PLUGIN_INSTANCE_ID.fetch_add(1, Ordering::Relaxed);
        plugin_instance_shard(id)
            .write()
            .unwrap_or_else(|err| err.into_inner())
            .insert(id, Arc::clone(&ctx));
        Self { id, ctx }
    }

    /// What goes into [`HostCallbacks::host_ctx`].
    fn host_ctx(&self) -> *mut c_void {
        self.id as *mut c_void
    }

    fn context(&self) -> &Arc<PluginInstanceContext> {
        &self.ctx
    }
}

impl Drop for PluginInstanceHandle {
    fn drop(&mut self) {
        plugin_instance_shard(self.id)
            .write()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&self.id);
    }
}

/// Resolves the `host_ctx` a callback was handed, or `None` when the instance
/// it names has already been destroyed.
fn plugin_instance_context(host_ctx: *mut c_void) -> Option<Arc<PluginInstanceContext>> {
    let id = host_ctx as usize;
    if id == 0 {
        return None;
    }
    plugin_instance_shard(id)
        .read()
        .unwrap_or_else(|err| err.into_inner())
        .get(&id)
        .cloned()
}

#[derive(Clone, Debug)]
struct LoadedPluginMetadata {
    abi_major: u32,
    abi_minor: u32,
    name: String,
    version: String,
    /// The plugin carries a language runtime, so its library must stay mapped
    /// for the life of the process. See [`PLUGIN_FLAG_EMBEDS_RUNTIME`].
    embeds_runtime: bool,
}

#[derive(Clone)]
struct LoadedPlugin {
    lib: Arc<Library>,
    metadata: Arc<LoadedPluginMetadata>,
    stream_engine: Option<Arc<StreamEnginePlugin>>,
    datagram_engine: Option<Arc<DatagramEnginePlugin>>,
}

pub trait ExternalOutboundStreamHandler: Send + Sync + Unpin {
    fn connect_addr(&self) -> Option<OutboundConnect>;

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyStream>>;
}
pub type AnyExternalOutboundStreamHandler = Arc<dyn ExternalOutboundStreamHandler>;

pub trait ExternalOutboundDatagramHandler: Send + Sync + Unpin {
    fn connect_addr(&self) -> Option<OutboundConnect>;

    fn transport_type(&self) -> DatagramTransportType;

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyOutboundDatagram>>;
}

#[derive(Clone, Debug, Default)]
pub struct PluginOutboundConfig {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub args: String,
    /// The digest the operator pinned this library to, as lowercase hex. The
    /// plugin is loaded only if the file on disk matches.
    pub sha256: Option<String>,
}

struct EngineOutboundStreamHandler {
    plugin: LoadedPlugin,
    engine: Arc<StreamEnginePlugin>,
    connect_addr: OutboundConnect,
    engine_args: String,
}

struct EngineOutboundDatagramHandler {
    plugin: LoadedPlugin,
    engine: Arc<DatagramEnginePlugin>,
    connect_addr: OutboundConnect,
    server_addr: crate::session::SocksAddr,
    engine_args: String,
}

struct EngineStream {
    stream: AnyStream,
    engine: Arc<StreamEnginePlugin>,
    instance: *mut std::ffi::c_void,
    host_ctx: Arc<PluginInstanceContext>,
    /// Deregisters this instance once the engine can no longer call back.
    _instance: PluginInstanceHandle,
    /// Keeps the library mapped for as long as this stream can call into it.
    ///
    /// `engine` is a copy of the vtable, so it holds function pointers into the
    /// library without holding the library itself. A connection outlives the
    /// handler that created it -- the UDP path and `dispatch_stream_outbound`
    /// both hand the wrapper back and drop the handler -- so a reload that
    /// drops the last handler would otherwise unload the library underneath a
    /// live stream. `None` only in tests, whose engines have no library.
    _lib: Option<Arc<Library>>,
    /// Bytes read from the socket that the engine has not consumed yet.
    read_encoded: BytesMut,
    /// Decoded bytes waiting to be handed to the application.
    read_decoded: BytesMut,
    /// Encoded bytes waiting to be written to the socket.
    write_pending: BytesMut,
    /// Reused so that reading from the socket does not allocate per poll.
    net_scratch: Vec<u8>,
    app_close_sent: bool,
    net_close_sent: bool,
}

struct EngineDatagram {
    socket: AnyOutboundDatagram,
    instance: Arc<Mutex<EngineDatagramInstance>>,
    destination_override: Option<crate::session::SocksAddr>,
    server_addr: crate::session::SocksAddr,
}

struct EngineDatagramInstance {
    engine: Arc<DatagramEnginePlugin>,
    instance: *mut std::ffi::c_void,
    _log_context: PluginInstanceHandle,
    /// See [`EngineStream::_lib`]. A datagram session outlives its handler by
    /// more than a stream does: `dispatch_datagram` returns the wrapper and the
    /// NAT session holds it from a task of its own.
    _lib: Option<Arc<Library>>,
}

struct EngineDatagramRecvHalf {
    instance: Arc<Mutex<EngineDatagramInstance>>,
    recv_half: Box<dyn OutboundDatagramRecvHalf>,
    destination_override: Option<crate::session::SocksAddr>,
}

struct EngineDatagramSendHalf {
    instance: Arc<Mutex<EngineDatagramInstance>>,
    send_half: Box<dyn OutboundDatagramSendHalf>,
    server_addr: crate::session::SocksAddr,
}

struct EngineReliableDatagram {
    stream: AnyStream,
    instance: Arc<Mutex<EngineDatagramInstance>>,
    destination_override: Option<crate::session::SocksAddr>,
}

struct EngineReliableDatagramRecvHalf {
    instance: Arc<Mutex<EngineDatagramInstance>>,
    read_half: tokio::io::ReadHalf<AnyStream>,
    destination_override: Option<crate::session::SocksAddr>,
    /// Bytes read from the stream that do not yet form a whole frame. A
    /// reliable transport has no message boundaries, so a read can stop in the
    /// middle of a frame or span several of them.
    pending: BytesMut,
}

struct EngineReliableDatagramSendHalf {
    instance: Arc<Mutex<EngineDatagramInstance>>,
    send_half: tokio::io::WriteHalf<AnyStream>,
}

/// How much to read from the socket in one go for a stream engine.
const NET_READ_CHUNK: usize = 16 * 1024;

/// How much decoded output to hold for a reader that is not keeping up before
/// declaring the engine stalled. Only reached by an engine that refuses
/// application input until its own output is drained.
const MAX_BUFFERED_APP_OUTPUT: usize = 256 * 1024;

/// How much unconsumed network input to hold before declaring the engine
/// stalled. An engine may legitimately need a whole frame before it consumes
/// anything, so this has to clear the largest frame worth waiting for.
const MAX_BUFFERED_NET_INPUT: usize = 256 * 1024;

const RELIABLE_DATAGRAM_READ_CHUNK: usize = 16 * 1024;

/// How much undecodable input to hold before giving up on a peer. A frame that
/// never completes would otherwise grow the buffer without bound.
const RELIABLE_DATAGRAM_MAX_PENDING: usize = 256 * 1024;

/// Ceiling for growing an output buffer after the engine reports
/// [`ENGINE_STATUS_BUFFER_TOO_SMALL`].
const DATAGRAM_MAX_OUTPUT_SIZE: usize = 1024 * 1024;

/// Ceiling for the address buffer handed to `decode_packet`. A `SocksAddr` is
/// an IPv6 address or a domain name, and a domain name is at most 255 bytes, so
/// nothing an engine can legitimately fill in comes close.
const MAX_PLUGIN_ADDRESS_SIZE: usize = 256;

/// Ceiling for the message `get_last_error` says it needs. Every other size an
/// engine reports is clamped; this one used to be believed, which let a wrong
/// length turn into an allocation the process could not satisfy.
const MAX_PLUGIN_ERROR_LEN: usize = 64 * 1024;

/// Ceiling for one message from the `log` callback, for the same reason.
const MAX_PLUGIN_LOG_LEN: usize = 64 * 1024;

/// Ceiling for the target a `log` call files its message under. A target names
/// a module; nothing legitimate is anywhere near this long.
const MAX_PLUGIN_LOG_TARGET_LEN: usize = 128;

/// Ceiling for the descriptor's `name` and `version`. They are read once, at
/// load, and are meant for a log line.
const MAX_PLUGIN_METADATA_LEN: usize = 256;

/// How many times to grow the output buffer before treating the engine's size
/// hints as broken.
const DATAGRAM_OUTPUT_GROWTH_ATTEMPTS: usize = 4;

/// How many bytes one poll moves from the engine to the socket before yielding.
///
/// An engine that always has more output, against a peer that keeps reading,
/// would otherwise keep an executor thread inside a single poll indefinitely.
/// Nothing is lost by stopping: the task wakes itself and picks up where it
/// left off.
const MAX_NET_FLUSH_PER_POLL: usize = 1024 * 1024;

/// What one `decode_packet` call produced.
enum DecodedDatagram {
    /// The input holds an incomplete frame; the host must read more bytes.
    NeedMoreInput,
    /// A frame carrying no datagram was consumed, such as a keepalive.
    Skipped { consumed: usize },
    /// One datagram was decoded.
    Packet {
        consumed: usize,
        payload: BytesMut,
        source: crate::session::SocksAddr,
    },
}

fn engine_datagram_transport_type(engine: &DatagramEnginePlugin) -> DatagramTransportType {
    match engine.transport_type {
        DATAGRAM_TRANSPORT_TYPE_RELIABLE => DatagramTransportType::Reliable,
        DATAGRAM_TRANSPORT_TYPE_UNRELIABLE => DatagramTransportType::Unreliable,
        _ => DatagramTransportType::Unknown,
    }
}

fn engine_stream_connect_type(engine: &StreamEnginePlugin) -> Option<OutboundConnect> {
    match engine.connect_type {
        STREAM_CONNECT_TYPE_PROXY_TCP => None,
        STREAM_CONNECT_TYPE_DIRECT => Some(OutboundConnect::Direct),
        STREAM_CONNECT_TYPE_NEXT => Some(OutboundConnect::Next),
        _ => Some(OutboundConnect::Unknown),
    }
}

fn require_connect_endpoint(
    settings: &PluginOutboundConfig,
    plugin_name: &str,
    reason: &str,
) -> io::Result<(String, u16, String)> {
    match (&settings.host, settings.port) {
        (Some(host), Some(port)) => Ok((host.clone(), port, settings.args.clone())),
        (None, None) => Err(io::Error::other(format!(
            "plugin [{}] requires explicit host and port for {}",
            plugin_name, reason
        ))),
        _ => Err(io::Error::other(format!(
            "plugin [{}] requires both host and port for {}",
            plugin_name, reason
        ))),
    }
}

fn ensure_no_explicit_connect_endpoint(
    settings: &PluginOutboundConfig,
    plugin_name: &str,
    reason: &str,
) -> io::Result<String> {
    match (&settings.host, settings.port) {
        (None, None) => Ok(settings.args.clone()),
        _ => Err(io::Error::other(format!(
            "plugin [{}] must not set host/port for {}",
            plugin_name, reason
        ))),
    }
}

impl ExternalOutboundStreamHandler for EngineOutboundStreamHandler {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        Some(self.connect_addr.clone())
    }

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyStream>> {
        BorrowingFfiFuture::new(async move {
            let stream = stream.ok_or_else(|| io::Error::other("invalid input"))?;
            let (
                engine_args,
                destination_data,
                destination,
                log_context,
                host_callbacks,
                create_args,
            ) = build_engine_create_args(sess, &self.engine_args, self.plugin.metadata.as_ref())?;
            let instance = unsafe {
                (self
                    .engine
                    .create_instance
                    .expect("validated stream engine create_instance"))(&create_args)
            };
            drop(host_callbacks);
            drop(destination);
            drop(destination_data);
            drop(engine_args);
            if instance.is_null() {
                let detail = unsafe {
                    read_plugin_error(
                        self.engine
                            .get_last_error
                            .expect("validated stream engine get_last_error"),
                        std::ptr::null_mut(),
                        ENGINE_STATUS_PLUGIN_FAILURE,
                    )
                };
                return Err(io::Error::other(format!(
                    "plugin [{}] failed to create stream engine instance{}",
                    self.plugin.metadata.name,
                    format_plugin_error_suffix(detail)
                )));
            }
            Ok(Box::new(EngineStream::new(
                stream,
                Arc::clone(&self.engine),
                instance,
                log_context,
                Some(Arc::clone(&self.plugin.lib)),
            )) as AnyStream)
        })
    }
}

impl ExternalOutboundDatagramHandler for EngineOutboundDatagramHandler {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        Some(self.connect_addr.clone())
    }

    fn transport_type(&self) -> DatagramTransportType {
        engine_datagram_transport_type(self.engine.as_ref())
    }

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyOutboundDatagram>> {
        BorrowingFfiFuture::new(async move {
            let (
                engine_args,
                destination_data,
                destination,
                log_context,
                host_callbacks,
                create_args,
            ) = build_engine_create_args(sess, &self.engine_args, self.plugin.metadata.as_ref())?;
            let instance = unsafe {
                (self
                    .engine
                    .create_instance
                    .expect("validated datagram engine create_instance"))(
                    &create_args
                )
            };
            drop(host_callbacks);
            drop(destination);
            drop(destination_data);
            drop(engine_args);
            if instance.is_null() {
                let detail = unsafe {
                    read_plugin_error(
                        self.engine
                            .get_last_error
                            .expect("validated datagram engine get_last_error"),
                        std::ptr::null_mut(),
                        ENGINE_STATUS_PLUGIN_FAILURE,
                    )
                };
                return Err(io::Error::other(format!(
                    "plugin [{}] failed to create datagram engine instance{}",
                    self.plugin.metadata.name,
                    format_plugin_error_suffix(detail)
                )));
            }
            let destination_override = match &sess.destination {
                crate::session::SocksAddr::Domain(domain, port) => {
                    Some(crate::session::SocksAddr::Domain(domain.clone(), *port))
                }
                _ => None,
            };
            let instance = Arc::new(Mutex::new(EngineDatagramInstance {
                engine: Arc::clone(&self.engine),
                instance,
                _log_context: log_context,
                _lib: Some(Arc::clone(&self.plugin.lib)),
            }));
            match engine_datagram_transport_type(self.engine.as_ref()) {
                DatagramTransportType::Reliable => {
                    let stream = if let Some(OutboundTransport::Stream(stream)) = transport {
                        stream
                    } else {
                        return Err(io::Error::other(
                            "invalid reliable datagram input: expected stream transport",
                        ));
                    };
                    Ok(Box::new(EngineReliableDatagram {
                        stream,
                        instance,
                        destination_override,
                    }) as AnyOutboundDatagram)
                }
                DatagramTransportType::Unreliable => {
                    let socket = if let Some(OutboundTransport::Datagram(socket)) = transport {
                        socket
                    } else {
                        return Err(io::Error::other(
                            "invalid unreliable datagram input: expected datagram transport",
                        ));
                    };
                    Ok(Box::new(EngineDatagram {
                        socket,
                        instance,
                        destination_override,
                        server_addr: self.server_addr.clone(),
                    }) as AnyOutboundDatagram)
                }
                DatagramTransportType::Unknown => Err(io::Error::other(
                    "invalid datagram engine transport type for plugin",
                )),
            }
        })
    }
}

pub struct OutboundStreamHandlerProxy {
    handler: AnyExternalOutboundStreamHandler,
    _lib: Arc<Library>,
}

impl OutboundStreamHandlerProxy {
    fn get_handler(&self) -> AnyExternalOutboundStreamHandler {
        self.handler.clone()
    }
}

impl EngineStream {
    fn new(
        stream: AnyStream,
        engine: Arc<StreamEnginePlugin>,
        instance: *mut std::ffi::c_void,
        log_context: PluginInstanceHandle,
        lib: Option<Arc<Library>>,
    ) -> Self {
        Self {
            stream,
            engine,
            instance,
            host_ctx: Arc::clone(log_context.context()),
            _instance: log_context,
            _lib: lib,
            read_encoded: BytesMut::new(),
            read_decoded: BytesMut::new(),
            write_pending: BytesMut::new(),
            net_scratch: vec![0u8; NET_READ_CHUNK],
            app_close_sent: false,
            net_close_sent: false,
        }
    }

    fn call_poll_state(&mut self) -> io::Result<u32> {
        let mut flags = 0u32;
        let rc = unsafe {
            (self
                .engine
                .poll_state
                .expect("validated stream engine poll_state"))(self.instance, &mut flags)
        };
        if rc != 0 {
            return Err(self.stream_error("poll_state", rc));
        }
        if (flags & STREAM_ENGINE_STATE_FATAL) != 0 {
            return Err(io::Error::other("stream engine entered fatal state"));
        }
        Ok(flags)
    }

    fn push_input(&mut self, side: u32, label: &str, input: &[u8]) -> io::Result<usize> {
        let mut consumed = 0usize;
        let rc = unsafe {
            (self.engine.push.expect("validated stream engine push"))(
                self.instance,
                side,
                input.as_ptr(),
                input.len(),
                &mut consumed,
            )
        };
        if rc != 0 {
            return Err(self.stream_error(label, rc));
        }
        if consumed > input.len() {
            // Believing this would either panic on the buffer split or report
            // more bytes written than the caller ever handed over.
            return Err(io::Error::other(format!(
                "stream engine {} consumed {} bytes of a {} byte input",
                label,
                consumed,
                input.len()
            )));
        }
        Ok(consumed)
    }

    fn push_app_input(&mut self, input: &[u8]) -> io::Result<usize> {
        self.push_input(STREAM_SIDE_APP, "push(app)", input)
    }

    fn push_net_input(&mut self, input: &[u8]) -> io::Result<usize> {
        self.push_input(STREAM_SIDE_NET, "push(net)", input)
    }

    fn stream_error(&mut self, label: &str, status_code: i32) -> io::Error {
        io::Error::other(format_plugin_error(
            "stream engine",
            label,
            status_code,
            unsafe {
                read_plugin_error(
                    self.engine
                        .get_last_error
                        .expect("validated stream engine get_last_error"),
                    self.instance,
                    status_code,
                )
            },
        ))
    }

    fn stream_output_hints(&mut self, side: u32) -> (usize, usize) {
        let size = unsafe {
            (self
                .engine
                .suggest_output_size
                .expect("validated stream engine suggest_output_size"))(
                self.instance, side
            )
        }
        .clamp(256, 64 * 1024);
        let batch = unsafe {
            (self
                .engine
                .suggest_output_batch
                .expect("validated stream engine suggest_output_batch"))(
                self.instance, side
            )
        }
        .clamp(1, 32);
        (size, batch)
    }

    fn drain_output(&mut self, side: u32, label: &str) -> io::Result<BytesMut> {
        let (chunk_size, batch_size) = self.stream_output_hints(side);
        let mut output = BytesMut::with_capacity(chunk_size.saturating_mul(batch_size));
        for _ in 0..batch_size {
            let mut chunk = vec![0u8; chunk_size];
            let mut produced = 0usize;
            let rc = unsafe {
                (self.engine.pull.expect("validated stream engine pull"))(
                    self.instance,
                    side,
                    chunk.as_mut_ptr(),
                    chunk.len(),
                    &mut produced,
                )
            };
            if rc != 0 {
                return Err(self.stream_error(label, rc));
            }
            if produced > chunk.len() {
                return Err(io::Error::other(format!(
                    "stream engine {} produced {} bytes into a {} byte buffer",
                    label,
                    produced,
                    chunk.len()
                )));
            }
            if produced == 0 {
                break;
            }
            output.extend_from_slice(&chunk[..produced]);
            if produced < chunk.len() {
                break;
            }
        }
        Ok(output)
    }

    fn pull_app_output(&mut self) -> io::Result<BytesMut> {
        self.drain_output(STREAM_SIDE_APP, "pull(app)")
    }

    fn pull_net_output(&mut self) -> io::Result<BytesMut> {
        self.drain_output(STREAM_SIDE_NET, "pull(net)")
    }

    fn close_engine(&mut self, flags: u32) -> io::Result<()> {
        let rc = unsafe {
            (self.engine.close.expect("validated stream engine close"))(self.instance, flags)
        };
        if rc != 0 {
            return Err(self.stream_error("close", rc));
        }
        Ok(())
    }

    /// Writes whatever is already queued for the socket, without asking the
    /// engine for more. Returns whether any bytes actually moved.
    fn poll_write_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut moved = false;
        while !self.write_pending.is_empty() {
            // Move the buffer out rather than copying it: `poll_write` needs a
            // shared borrow of the bytes while `self.stream` is borrowed
            // mutably, and this runs on every write.
            let pending = std::mem::take(&mut self.write_pending);
            let result = Pin::new(&mut self.stream).poll_write(cx, &pending);
            self.write_pending = pending;
            match result {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write stream engine net output",
                    )))
                }
                Poll::Ready(Ok(written)) => {
                    let _ = self.write_pending.split_to(written);
                    moved = true;
                }
            }
        }
        Poll::Ready(Ok(moved))
    }

    /// Drains the engine's network output all the way to the socket. Returns
    /// whether anything moved, which tells the caller whether looping again
    /// could help.
    fn poll_flush_net(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut moved = false;
        let mut budget = MAX_NET_FLUSH_PER_POLL;
        loop {
            moved |= std::task::ready!(self.poll_write_pending(cx))?;

            let flags = self.call_poll_state()?;
            if (flags & STREAM_ENGINE_STATE_HAS_NET_OUTPUT) == 0 {
                return Poll::Ready(Ok(moved));
            }
            if budget == 0 {
                // The engine still has output and the socket is still taking
                // it. Yield rather than stay here: this is the one loop in the
                // wrapper an engine can keep running for as long as the peer
                // keeps reading. Waking first is what makes it a yield rather
                // than a stall -- and `poll_read`, which treats a pending send
                // side as advisory, has its own bounded work to finish before
                // it returns.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let produced = self.pull_net_output()?;
            if produced.is_empty() {
                // The engine advertised output it did not deliver. Believe the
                // bytes, not the flag, or this would spin.
                return Poll::Ready(Ok(moved));
            }
            budget = budget.saturating_sub(produced.len());
            self.write_pending.extend_from_slice(&produced);
            moved = true;
        }
    }

    /// Moves decoded bytes out of the engine into `read_decoded`, returning how
    /// many were moved.
    fn drain_app_output(&mut self) -> io::Result<usize> {
        let produced = self.pull_app_output()?;
        self.read_decoded.extend_from_slice(&produced);
        Ok(produced.len())
    }

    /// Hands the engine whatever encoded bytes are already buffered, returning
    /// how many it took.
    fn feed_engine_from_read_buffer(&mut self) -> io::Result<usize> {
        if self.read_encoded.is_empty() {
            return Ok(0);
        }
        // Taken out and put back so the engine sees a shared borrow of the
        // bytes while `self` is borrowed mutably, rather than a copy per poll.
        let encoded = std::mem::take(&mut self.read_encoded);
        let consumed = self.push_net_input(&encoded);
        self.read_encoded = encoded;
        let consumed = consumed?;
        let _ = self.read_encoded.split_to(consumed);
        Ok(consumed)
    }

    /// Reads from the socket into `read_encoded`. `Ok(0)` means the peer closed.
    fn poll_read_net(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let filled = {
            let Self {
                stream,
                net_scratch,
                ..
            } = self;
            let mut scratch = ReadBuf::new(net_scratch.as_mut_slice());
            std::task::ready!(Pin::new(stream).poll_read(cx, &mut scratch))?;
            scratch.filled().len()
        };
        if filled > 0 {
            let scratch = std::mem::take(&mut self.net_scratch);
            self.read_encoded.extend_from_slice(&scratch[..filled]);
            self.net_scratch = scratch;
        }
        Poll::Ready(Ok(filled))
    }

    /// Reports the engine as deadlocked: it took no input, produced no output
    /// and is not waiting on anything the host can supply.
    fn stalled_engine_error(&self, flags: u32) -> io::Error {
        io::Error::other(format!(
            "stream engine made no progress and is not waiting for input (state flags {:#06x})",
            flags
        ))
    }
}

impl Drop for EngineStream {
    fn drop(&mut self) {
        let mut flags = 0u32;
        if !self.app_close_sent {
            flags |= STREAM_ENGINE_CLOSE_APP;
        }
        if !self.net_close_sent {
            flags |= STREAM_ENGINE_CLOSE_NET;
        }
        if flags != 0 {
            let _ = self.close_engine(flags);
        }
        unsafe {
            (self
                .engine
                .destroy_instance
                .expect("validated stream engine destroy_instance"))(self.instance)
        }
    }
}

// SAFETY: The instance pointer belongs to the plugin and is only accessed through
// &mut self while the stream wrapper is polled. The loaded library is held by Arc.
unsafe impl Send for EngineStream {}
unsafe impl Sync for EngineStream {}

impl Drop for EngineDatagramInstance {
    fn drop(&mut self) {
        unsafe {
            (self
                .engine
                .destroy_instance
                .expect("validated datagram engine destroy_instance"))(self.instance)
        }
    }
}

// SAFETY: Datagram engine instances are only accessed behind a mutex and the
// loaded library is held by Arc for the lifetime of the instance.
unsafe impl Send for EngineDatagramInstance {}

impl AsyncRead for EngineStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Registered before any state is read: an engine that unblocks partway
        // through this poll then wakes a waker that is already in place,
        // whether this poll ends up parked on the engine or on the socket.
        self.host_ctx.read_waker.register(cx.waker());
        loop {
            // Anything the engine wants on the wire has to keep moving even
            // while the caller is only reading: a handshake is a conversation.
            //
            // A full socket must not stop this poll here, though. The two
            // directions of a stream make progress independently, and a peer
            // that is slow to accept what the engine is sending is a normal
            // condition -- one that a saturated upload produces routinely. If
            // a congested socket parked the read side, bytes the engine has
            // already decoded would sit undelivered until the upload drained,
            // and the upload cannot drain while the peer is waiting for those
            // bytes. So a congested send side only leaves its waker registered
            // here; this poll goes on to deliver, decode and read as usual.
            match self.poll_flush_net(cx) {
                Poll::Ready(Ok(_)) | Poll::Pending => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }

            if !self.read_decoded.is_empty() {
                let to_copy = self.read_decoded.len().min(buf.remaining());
                buf.put_slice(&self.read_decoded.split_to(to_copy));
                return Poll::Ready(Ok(()));
            }

            if self.drain_app_output()? > 0 {
                continue;
            }

            if self.feed_engine_from_read_buffer()? > 0 {
                continue;
            }

            let flags = self.call_poll_state()?;
            if (flags & STREAM_ENGINE_STATE_BLOCKED) != 0 {
                return Poll::Pending;
            }

            if self.read_encoded.len() >= MAX_BUFFERED_NET_INPUT {
                return Poll::Ready(Err(io::Error::other(format!(
                    "stream engine has not consumed {} buffered bytes of network input \
                     (state flags {:#06x})",
                    self.read_encoded.len(),
                    flags
                ))));
            }

            if self.net_close_sent {
                // The peer is gone and the engine has nothing left to decode,
                // so this is a clean end of stream.
                return Poll::Ready(Ok(()));
            }

            // Nothing decoded and nothing left to decode, so read from the
            // peer -- even while the engine's own output is stuck behind a full
            // socket. Reading is what produces the bytes the caller is waiting
            // for, and it is independent of whether the send side can drain.
            // `poll_read_net` parks on the socket when there is nothing there,
            // and `poll_flush_net` has already registered for the send side, so
            // either becoming ready gets this polled again.
            if std::task::ready!(self.poll_read_net(cx))? == 0 {
                self.close_engine(STREAM_ENGINE_CLOSE_NET)?;
                self.net_close_sent = true;
            }
        }
    }
}

impl AsyncWrite for EngineStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // See the note in `poll_read`: registered before any state is read.
        self.host_ctx.write_waker.register(cx.waker());
        loop {
            // Draining first is what usually frees room inside the engine.
            let flushed = std::task::ready!(self.poll_flush_net(cx))?;

            let consumed = self.push_app_input(buf)?;
            if consumed > 0 {
                // Get the freshly encoded bytes moving, but do not make the
                // caller wait on the socket for them: that is what flush is
                // for.
                if let Poll::Ready(Err(err)) = self.poll_flush_net(cx) {
                    return Poll::Ready(Err(err));
                }
                return Poll::Ready(Ok(consumed));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if flushed {
                // Something moved, so the engine may have room now.
                continue;
            }

            // The engine refused the write. That is backpressure, not a
            // failure, so work out what it is waiting for and supply it.
            let flags = self.call_poll_state()?;

            // Waiting on work of its own: more input would not help, and the
            // waker registered on entry is what gets this polled again.
            if (flags & STREAM_ENGINE_STATE_BLOCKED) != 0 {
                return Poll::Pending;
            }

            if (flags & STREAM_ENGINE_STATE_HAS_APP_OUTPUT) != 0
                && self.read_decoded.len() < MAX_BUFFERED_APP_OUTPUT
                && self.drain_app_output()? > 0
            {
                continue;
            }

            // Past the cap, feeding the engine more of the peer's bytes only
            // moves the backlog somewhere the host cannot see or bound: the
            // engine's own decoded-output buffer. The ABI has no way to say
            // "stop decoding", so the connection fails here instead, the same
            // way it does for network input the engine will not consume.
            if self.read_decoded.len() >= MAX_BUFFERED_APP_OUTPUT {
                return Poll::Ready(Err(io::Error::other(format!(
                    "stream engine has {} bytes of decoded output the reader has not taken \
                     (state flags {:#06x})",
                    self.read_decoded.len(),
                    flags
                ))));
            }

            if !self.net_close_sent {
                if self.feed_engine_from_read_buffer()? > 0 {
                    continue;
                }
                if (flags & STREAM_ENGINE_STATE_WANT_NET_INPUT) != 0 {
                    if std::task::ready!(self.poll_read_net(cx))? == 0 {
                        self.close_engine(STREAM_ENGINE_CLOSE_NET)?;
                        self.net_close_sent = true;
                    }
                    continue;
                }
            }

            return Poll::Ready(Err(self.stalled_engine_error(flags)));
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.host_ctx.write_waker.register(cx.waker());
        std::task::ready!(self.poll_flush_net(cx))?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.host_ctx.write_waker.register(cx.waker());
        if !self.app_close_sent {
            self.close_engine(STREAM_ENGINE_CLOSE_APP)?;
            self.app_close_sent = true;
        }
        std::task::ready!(self.poll_flush_net(cx))?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl EngineDatagramInstance {
    fn datagram_error(&mut self, label: &str, status_code: i32) -> io::Error {
        io::Error::other(format_plugin_error(
            "datagram engine",
            label,
            status_code,
            unsafe {
                read_plugin_error(
                    self.engine
                        .get_last_error
                        .expect("validated datagram engine get_last_error"),
                    self.instance,
                    status_code,
                )
            },
        ))
    }

    /// Asks the engine how big an output buffer to hand it, clamped so that a
    /// wild hint cannot make the host allocate without bound.
    fn suggested_output_size(&mut self, input_len: usize, direction: u32) -> usize {
        let hint = unsafe {
            (self
                .engine
                .max_output_size
                .expect("validated datagram engine max_output_size"))(
                self.instance,
                input_len,
                direction,
            )
        };
        hint.clamp(1, DATAGRAM_MAX_OUTPUT_SIZE)
    }

    fn encode_packet(&mut self, payload: &[u8], target: &[u8]) -> io::Result<BytesMut> {
        let target = crate::session::SocksAddr::try_from((
            target,
            crate::session::SocksAddrWireType::PortLast,
        ))?;
        let (target_storage, target_address) = socks_addr_to_plugin_address(&target);
        let mut capacity = self.suggested_output_size(
            datagram_encode_input_hint_len(payload.len(), &target),
            DATAGRAM_DIRECTION_ENCODE,
        );

        // The size hint is advisory. When the engine says the buffer is too
        // small, grow it and retry rather than failing the datagram.
        for attempt in 0..=DATAGRAM_OUTPUT_GROWTH_ATTEMPTS {
            let mut output = vec![0u8; capacity];
            let mut produced = 0usize;
            let rc = unsafe {
                (self
                    .engine
                    .encode_packet
                    .expect("validated datagram engine encode_packet"))(
                    self.instance,
                    payload.as_ptr(),
                    payload.len(),
                    &target_address,
                    output.as_mut_ptr(),
                    output.len(),
                    &mut produced,
                )
            };
            if rc == ENGINE_STATUS_BUFFER_TOO_SMALL && attempt < DATAGRAM_OUTPUT_GROWTH_ATTEMPTS {
                match grown_output_capacity(capacity) {
                    Some(grown) => {
                        capacity = grown;
                        continue;
                    }
                    None => break,
                }
            }
            drop(target_storage);
            if rc != ENGINE_STATUS_OK {
                return Err(self.datagram_error("encode_packet", rc));
            }
            if produced > output.len() {
                return Err(io::Error::other(format!(
                    "datagram engine encode_packet produced {} bytes into a {} byte buffer",
                    produced,
                    output.len()
                )));
            }
            output.truncate(produced);
            return Ok(BytesMut::from(output.as_slice()));
        }
        drop(target_storage);
        Err(io::Error::other(format!(
            "datagram engine encode_packet still reports a buffer of {} bytes as too small",
            capacity
        )))
    }

    /// Decodes at most one datagram out of `input`, leaving any bytes it did
    /// not consume for the caller to re-present with more data appended.
    fn decode_packet(&mut self, input: &[u8]) -> io::Result<DecodedDatagram> {
        let mut capacity = self.suggested_output_size(input.len(), DATAGRAM_DIRECTION_DECODE);
        let addr_cap = unsafe {
            (self
                .engine
                .max_address_size
                .expect("validated datagram engine max_address_size"))(
                self.instance,
                DATAGRAM_DIRECTION_DECODE,
            )
        }
        .clamp(1, MAX_PLUGIN_ADDRESS_SIZE);

        for attempt in 0..=DATAGRAM_OUTPUT_GROWTH_ATTEMPTS {
            let mut output = vec![0u8; capacity];
            let mut addr = vec![0u8; addr_cap];
            let addr_ptr = addr.as_mut_ptr();
            let mut address = PluginAddress {
                kind: 0,
                port: 0,
                data: addr_ptr,
                data_len: addr.len(),
            };
            let mut consumed = 0usize;
            let mut produced = 0usize;
            let rc = unsafe {
                (self
                    .engine
                    .decode_packet
                    .expect("validated datagram engine decode_packet"))(
                    self.instance,
                    input.as_ptr(),
                    input.len(),
                    &mut consumed,
                    output.as_mut_ptr(),
                    output.len(),
                    &mut produced,
                    &mut address,
                )
            };
            if rc == ENGINE_STATUS_BUFFER_TOO_SMALL && attempt < DATAGRAM_OUTPUT_GROWTH_ATTEMPTS {
                // The engine is required to consume nothing in this case, so
                // the same input can simply be presented again.
                match grown_output_capacity(capacity) {
                    Some(grown) => {
                        capacity = grown;
                        continue;
                    }
                    None => break,
                }
            }
            if rc != ENGINE_STATUS_OK {
                return Err(self.datagram_error("decode_packet", rc));
            }
            if consumed > input.len() {
                return Err(io::Error::other(format!(
                    "datagram engine decode_packet consumed {} bytes of a {} byte input",
                    consumed,
                    input.len()
                )));
            }
            if produced > output.len() {
                return Err(io::Error::other(format!(
                    "datagram engine decode_packet produced {} bytes into a {} byte buffer",
                    produced,
                    output.len()
                )));
            }
            if produced == 0 {
                return Ok(if consumed == 0 {
                    DecodedDatagram::NeedMoreInput
                } else {
                    DecodedDatagram::Skipped { consumed }
                });
            }
            if consumed == 0 {
                return Err(io::Error::other(
                    "datagram engine decode_packet produced a datagram without consuming input",
                ));
            }
            // The address buffer belongs to the host: the engine fills it in
            // and reports a length, it does not get to hand back a pointer of
            // its own.
            if address.data != addr_ptr {
                return Err(io::Error::other(
                    "datagram engine decode_packet replaced the host address buffer pointer",
                ));
            }
            if address.data_len > addr.len() {
                return Err(io::Error::other(format!(
                    "datagram engine decode_packet reported a {} byte address in a {} byte buffer",
                    address.data_len,
                    addr.len()
                )));
            }
            output.truncate(produced);
            addr.truncate(address.data_len);
            let decoded_address = PluginAddress {
                data: addr.as_ptr(),
                ..address
            };
            let source = plugin_address_to_socks_addr(&decoded_address)?;
            return Ok(DecodedDatagram::Packet {
                consumed,
                payload: BytesMut::from(output.as_slice()),
                source,
            });
        }
        Err(io::Error::other(format!(
            "datagram engine decode_packet still reports a buffer of {} bytes as too small",
            capacity
        )))
    }
}

/// Doubles an output buffer, up to [`DATAGRAM_MAX_OUTPUT_SIZE`].
fn grown_output_capacity(capacity: usize) -> Option<usize> {
    if capacity >= DATAGRAM_MAX_OUTPUT_SIZE {
        return None;
    }
    Some(capacity.saturating_mul(2).min(DATAGRAM_MAX_OUTPUT_SIZE))
}

impl OutboundDatagram for EngineDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (recv_half, send_half) = self.socket.split();
        (
            Box::new(EngineDatagramRecvHalf {
                instance: Arc::clone(&self.instance),
                recv_half,
                destination_override: self.destination_override.clone(),
            }),
            Box::new(EngineDatagramSendHalf {
                instance: self.instance,
                send_half,
                server_addr: self.server_addr,
            }),
        )
    }
}

impl OutboundDatagram for EngineReliableDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (recv_half, send_half) = tokio::io::split(self.stream);
        (
            Box::new(EngineReliableDatagramRecvHalf {
                instance: Arc::clone(&self.instance),
                read_half: recv_half,
                destination_override: self.destination_override.clone(),
                pending: BytesMut::new(),
            }),
            Box::new(EngineReliableDatagramSendHalf {
                instance: self.instance,
                send_half,
            }),
        )
    }
}

#[async_trait]
impl OutboundDatagramRecvHalf for EngineDatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<(usize, crate::session::SocksAddr)> {
        let mut recv_buf = vec![0u8; buf.len().saturating_mul(2).max(2048)];
        loop {
            let (n, _) = self.recv_half.recv_from(&mut recv_buf).await?;
            let decoded = self
                .instance
                .lock()
                .map_err(|_| io::Error::other("datagram engine instance poisoned"))?
                .decode_packet(&recv_buf[..n])?;
            // An unreliable transport delivers whole frames, so anything that
            // does not decode into a datagram is a damaged packet. Dropping it
            // and waiting for the next one is what a UDP peer would do anyway.
            let (payload, source) = match decoded {
                DecodedDatagram::Packet {
                    payload, source, ..
                } => (payload, source),
                DecodedDatagram::NeedMoreInput | DecodedDatagram::Skipped { .. } => continue,
            };
            if payload.len() > buf.len() {
                // A datagram too big for the caller's buffer is a damaged
                // packet, the same as one that failed to decode, and the loop
                // above already drops those. Failing here instead would let
                // one oversized packet from the server end the whole session.
                debug!(
                    payload = payload.len(),
                    capacity = buf.len(),
                    "dropping a decoded datagram larger than the receive buffer"
                );
                continue;
            }
            buf[..payload.len()].copy_from_slice(&payload);
            return Ok((
                payload.len(),
                self.destination_override.clone().unwrap_or(source),
            ));
        }
    }
}

#[async_trait]
impl OutboundDatagramSendHalf for EngineDatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        dst_addr: &crate::session::SocksAddr,
    ) -> io::Result<usize> {
        let mut target = BytesMut::new();
        dst_addr.write_buf(&mut target, crate::session::SocksAddrWireType::PortLast);
        let encoded = self
            .instance
            .lock()
            .map_err(|_| io::Error::other("datagram engine instance poisoned"))?
            .encode_packet(buf, &target)?;
        self.send_half.send_to(&encoded, &self.server_addr).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.send_half.close().await
    }
}

#[async_trait]
impl OutboundDatagramRecvHalf for EngineReliableDatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<(usize, crate::session::SocksAddr)> {
        loop {
            // Drain whatever whole frames the buffer already holds before
            // going back to the stream: one read can carry several of them.
            while !self.pending.is_empty() {
                let decoded = self
                    .instance
                    .lock()
                    .map_err(|_| io::Error::other("datagram engine instance poisoned"))?
                    .decode_packet(&self.pending)?;
                match decoded {
                    DecodedDatagram::NeedMoreInput => break,
                    DecodedDatagram::Skipped { consumed } => {
                        let _ = self.pending.split_to(consumed);
                    }
                    DecodedDatagram::Packet {
                        consumed,
                        payload,
                        source,
                    } => {
                        // Consumed before anything else can go wrong: the
                        // frame is whole and its bytes must leave the buffer
                        // either way, or the stream desynchronises.
                        let _ = self.pending.split_to(consumed);
                        if payload.len() > buf.len() {
                            // Dropped rather than fatal, as on the unreliable
                            // path: the carrier is a stream, but what rides it
                            // is still datagrams, and losing one is within
                            // what the caller already handles.
                            debug!(
                                payload = payload.len(),
                                capacity = buf.len(),
                                "dropping a decoded datagram larger than the receive buffer"
                            );
                            continue;
                        }
                        buf[..payload.len()].copy_from_slice(&payload);
                        return Ok((
                            payload.len(),
                            self.destination_override.clone().unwrap_or(source),
                        ));
                    }
                }
            }

            if self.pending.len() >= RELIABLE_DATAGRAM_MAX_PENDING {
                return Err(io::Error::other(format!(
                    "reliable datagram frame exceeds {} bytes without completing",
                    RELIABLE_DATAGRAM_MAX_PENDING
                )));
            }
            self.pending.reserve(RELIABLE_DATAGRAM_READ_CHUNK);
            let n = self.read_half.read_buf(&mut self.pending).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "reliable datagram transport eof",
                ));
            }
        }
    }
}

#[async_trait]
impl OutboundDatagramSendHalf for EngineReliableDatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        dst_addr: &crate::session::SocksAddr,
    ) -> io::Result<usize> {
        let mut target = BytesMut::new();
        dst_addr.write_buf(&mut target, crate::session::SocksAddrWireType::PortLast);
        let encoded = self
            .instance
            .lock()
            .map_err(|_| io::Error::other("datagram engine instance poisoned"))?
            .encode_packet(buf, &target)?;
        self.send_half.write_all(&encoded).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.send_half.shutdown().await
    }
}

impl ExternalOutboundStreamHandler for OutboundStreamHandlerProxy {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        self.handler.connect_addr()
    }

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyStream>> {
        self.handler.handle(sess, stream)
    }
}

pub struct OutboundDatagramHandlerProxy {
    handler: AnyExternalOutboundDatagramHandler,
    _lib: Arc<Library>,
}

impl OutboundDatagramHandlerProxy {
    fn get_handler(&self) -> AnyExternalOutboundDatagramHandler {
        self.handler.clone()
    }
}

impl ExternalOutboundDatagramHandler for OutboundDatagramHandlerProxy {
    fn connect_addr(&self) -> Option<OutboundConnect> {
        self.handler.connect_addr()
    }

    fn transport_type(&self) -> DatagramTransportType {
        self.handler.transport_type()
    }

    fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> BorrowingFfiFuture<'a, io::Result<AnyOutboundDatagram>> {
        self.handler.handle(sess, transport)
    }
}

pub type AnyExternalOutboundDatagramHandler = Arc<dyn ExternalOutboundDatagramHandler>;

#[derive(Default)]
pub struct ExternalHandlers {
    stream_handlers: HashMap<String, OutboundStreamHandlerProxy>,
    datagram_handlers: HashMap<String, OutboundDatagramHandlerProxy>,
    /// Keyed by the resolved path rather than by its lossy string form, under
    /// which two different files whose names are not valid UTF-8 could collapse
    /// onto the same entry and silently share one library.
    libraries: HashMap<PathBuf, LoadedPlugin>,
}

impl ExternalHandlers {
    pub fn new() -> Self {
        Self::default()
    }

    pub unsafe fn new_handler<P>(
        &mut self,
        path: P,
        tag: &str,
        settings: PluginOutboundConfig,
    ) -> io::Result<()>
    where
        P: AsRef<OsStr> + Clone,
    {
        let resolved = resolve_plugin_path(path.as_ref())?;
        let plugin_path = resolved.display().to_string();
        for warning in check_plugin_file_permissions(&resolved)? {
            warn!(plugin_path = %plugin_path, "{}", warning);
        }
        if let Some(expected) = settings.sha256.as_deref() {
            verify_plugin_digest(&resolved, expected)?;
        }
        let plugin = if let Some(plugin) = self.libraries.get(&resolved) {
            debug!(
                plugin_path = %plugin_path,
                plugin = %plugin.metadata.name,
                tag = %tag,
                "reusing cached plugin library"
            );
            plugin.clone()
        } else {
            info!(
                plugin_path = %plugin_path,
                tag = %tag,
                pinned = settings.sha256.is_some(),
                "loading plugin library"
            );
            let lib = Arc::new(open_plugin_library(&resolved, &plugin_path)?);
            let (metadata, stream_engine, datagram_engine) =
                read_plugin_descriptor(lib.as_ref(), &plugin_path)?;
            info!(
                plugin_path = %plugin_path,
                plugin = %metadata.name,
                plugin_version = %metadata.version,
                abi_major = metadata.abi_major,
                abi_minor = metadata.abi_minor,
                has_stream = stream_engine.is_some(),
                has_datagram = datagram_engine.is_some(),
                embeds_runtime = metadata.embeds_runtime,
                "loaded plugin descriptor"
            );
            if metadata.embeds_runtime {
                // Deliberately leaked, so the count can never reach zero and
                // the library is never unmapped. Everything else the host
                // holds a library for it can also let go of; the threads this
                // plugin's runtime started are outside that accounting
                // entirely and go on running code in the library after the
                // last handler, stream and session are gone. Unmapping then
                // pulls the code out from under them -- immediately fatal
                // where the loader really unmaps, which is Windows, and
                // merely latent where it declines to.
                //
                // The cost is one library's worth of address space for the
                // life of the process, which is what a plugin still in use
                // costs anyway, and losing the release of that space on a
                // reload that drops the plugin. That is the trade the flag
                // exists to make.
                info!(
                    plugin_path = %plugin_path,
                    plugin = %metadata.name,
                    "plugin embeds a runtime; keeping its library mapped for the life of the process"
                );
                core::mem::forget(Arc::clone(&lib));
                if let Some(libraries) = note_runtime_library(&resolved) {
                    warn!(
                        count = libraries.len(),
                        libraries = %libraries.join(", "),
                        "more than one plugin in this process embeds a language runtime; \
                         each runs its own threads and handles its own faults, which the \
                         runtimes involved generally arbitrate but do not all promise to"
                    );
                }
            }
            let plugin = LoadedPlugin {
                lib: lib.clone(),
                metadata: Arc::new(metadata),
                stream_engine,
                datagram_engine,
            };
            self.libraries.insert(resolved.clone(), plugin.clone());
            plugin
        };

        let mut registered = false;
        if let Some(engine) = plugin.stream_engine.as_ref() {
            let (connect_addr, engine_args) = match engine_stream_connect_type(engine.as_ref()) {
                None => {
                    let (connect_host, connect_port, engine_args) = require_connect_endpoint(
                        &settings,
                        &plugin.metadata.name,
                        "stream connect_type=ProxyTcp",
                    )?;
                    (
                        OutboundConnect::Proxy(Network::Tcp, connect_host, connect_port),
                        engine_args,
                    )
                }
                Some(OutboundConnect::Direct) => (
                    OutboundConnect::Direct,
                    ensure_no_explicit_connect_endpoint(
                        &settings,
                        &plugin.metadata.name,
                        "stream connect_type=Direct",
                    )?,
                ),
                Some(OutboundConnect::Next) => (
                    OutboundConnect::Next,
                    ensure_no_explicit_connect_endpoint(
                        &settings,
                        &plugin.metadata.name,
                        "stream connect_type=Next",
                    )?,
                ),
                Some(OutboundConnect::Unknown) => {
                    return Err(io::Error::other(format!(
                        "plugin [{}] exports stream engine with invalid connect_type={}",
                        plugin.metadata.name, engine.connect_type
                    )));
                }
                Some(OutboundConnect::Proxy(_, _, _)) => unreachable!(),
            };
            self.stream_handlers.insert(
                tag.to_string(),
                OutboundStreamHandlerProxy {
                    handler: Arc::new(EngineOutboundStreamHandler {
                        plugin: plugin.clone(),
                        engine: Arc::clone(engine),
                        connect_addr,
                        engine_args: engine_args.clone(),
                    }),
                    _lib: Arc::clone(&plugin.lib),
                },
            );
            info!(
                plugin_path = %plugin_path,
                plugin = %plugin.metadata.name,
                tag = %tag,
                "stream engine plugin handler registered"
            );
            registered = true;
        }
        if let Some(engine) = plugin.datagram_engine.as_ref() {
            let transport_type = engine_datagram_transport_type(engine.as_ref());
            if transport_type == DatagramTransportType::Unknown {
                return Err(io::Error::other(format!(
                    "plugin [{}] exports datagram engine with invalid transport_type={}",
                    plugin.metadata.name, engine.transport_type
                )));
            }
            let (connect_host, connect_port, engine_args) =
                require_connect_endpoint(&settings, &plugin.metadata.name, "datagram engine")?;
            let connect_addr = OutboundConnect::Proxy(
                match transport_type {
                    DatagramTransportType::Reliable => Network::Tcp,
                    DatagramTransportType::Unreliable => Network::Udp,
                    DatagramTransportType::Unknown => unreachable!(),
                },
                connect_host.clone(),
                connect_port,
            );
            let server_addr =
                crate::session::SocksAddr::try_from((connect_host.as_str(), connect_port))
                    .map_err(|err| {
                        io::Error::other(format!("invalid plugin remote address: {}", err))
                    })?;
            self.datagram_handlers.insert(
                tag.to_string(),
                OutboundDatagramHandlerProxy {
                    handler: Arc::new(EngineOutboundDatagramHandler {
                        plugin: plugin.clone(),
                        engine: Arc::clone(engine),
                        connect_addr,
                        server_addr,
                        engine_args: engine_args.clone(),
                    }),
                    _lib: Arc::clone(&plugin.lib),
                },
            );
            info!(
                plugin_path = %plugin_path,
                plugin = %plugin.metadata.name,
                tag = %tag,
                transport_type = ?transport_type,
                "datagram engine plugin handler registered"
            );
            registered = true;
        }
        if !registered {
            return Err(io::Error::other(format!(
                "plugin [{}] descriptor exports neither stream nor datagram engine",
                plugin_path
            )));
        }
        Ok(())
    }

    pub fn get_stream_handler(&self, name: &str) -> Option<AnyExternalOutboundStreamHandler> {
        self.stream_handlers.get(name).map(|h| h.get_handler())
    }

    pub fn get_datagram_handler(&self, name: &str) -> Option<AnyExternalOutboundDatagramHandler> {
        self.datagram_handlers.get(name).map(|h| h.get_handler())
    }
}

pub struct ExternalOutboundStreamHandlerProxy(pub AnyExternalOutboundStreamHandler);

#[async_trait]
impl OutboundStreamHandler for ExternalOutboundStreamHandlerProxy {
    fn connect_addr(&self) -> OutboundConnect {
        self.0.connect_addr().unwrap_or(OutboundConnect::Unknown)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let payload = peek_tcp_one_off(lhs).await;
        let mut stream = self.0.handle(sess, stream).await?;
        if !payload.is_empty() {
            stream.write_all(&payload).await?;
        }
        Ok(stream)
    }
}

pub struct ExternalOutboundDatagramHandlerProxy(pub AnyExternalOutboundDatagramHandler);

#[async_trait]
impl OutboundDatagramHandler for ExternalOutboundDatagramHandlerProxy {
    fn connect_addr(&self) -> OutboundConnect {
        self.0.connect_addr().unwrap_or(OutboundConnect::Unknown)
    }

    fn transport_type(&self) -> DatagramTransportType {
        self.0.transport_type()
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        self.0.handle(sess, transport).await
    }
}

/// Resolves a configured plugin path into one the dynamic loader cannot
/// reinterpret.
///
/// A bare name -- one with no directory part -- is not a path as far as
/// `dlopen` and `LoadLibraryW` are concerned. Both go looking for it along a
/// search order the process does not fully control: `LD_LIBRARY_PATH` and the
/// ldconfig cache on Unix, the DLL search order on Windows. Loading whatever
/// that turns up, into a proxy, with the proxy's privileges, is not a decision
/// a config file should be able to delegate to the environment, so a bare name
/// is refused outright. Everything else is made absolute, which leaves the
/// loader nothing to search for.
fn resolve_plugin_path(path: &OsStr) -> io::Result<PathBuf> {
    let path = Path::new(path);
    if path.as_os_str().is_empty() {
        return Err(io::Error::other("plugin path is empty"));
    }
    let has_directory_part = path
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty());
    if !has_directory_part {
        return Err(io::Error::other(format!(
            "plugin path [{}] is a bare library name, which the dynamic loader would look up \
             along the system library search path; give it a directory, such as [./{}]",
            path.display(),
            path.display()
        )));
    }
    path.canonicalize().map_err(|err| {
        io::Error::other(format!(
            "failed to resolve plugin path [{}]: {}",
            path.display(),
            err
        ))
    })
}

/// Refuses a plugin anyone on the host can rewrite, and notes one a group can.
///
/// Loading a shared library runs whatever its last writer put there, with the
/// proxy's privileges. If the file is world-writable, or sits in a directory
/// where anyone can unlink it and put their own file in its place, then that
/// writer is anybody at all -- which is not something a config file gets to
/// delegate, whatever it says the path is. A world-writable directory carrying
/// the sticky bit, as `/tmp` does, is only a warning: that bit is exactly what
/// stops one user from unlinking another's file. Group-writable is a warning
/// too, because sharing a build directory with a group is a deliberate
/// arrangement and the group is a named set of people.
///
/// The warnings are returned rather than logged, so that the loader can put
/// them in the log and [`inspect_plugin`] can put the same ones in its report.
#[cfg(unix)]
fn check_plugin_file_permissions(path: &Path) -> io::Result<Vec<String>> {
    use std::os::unix::fs::MetadataExt;
    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(Vec::new());
    };
    let mut warnings = Vec::new();
    let mode = metadata.mode() & 0o7777;
    if mode & 0o002 != 0 {
        return Err(io::Error::other(format!(
            "plugin library [{}] is world-writable (mode {:o}); anyone on this host could \
             replace the code leaf runs, so it will not be loaded",
            path.display(),
            mode
        )));
    }
    if mode & 0o020 != 0 {
        warnings.push(format!(
            "plugin library [{}] is group-writable (mode {:o}); anyone in that group can \
             replace the code it runs",
            path.display(),
            mode
        ));
    }
    let Some(parent) = path.parent() else {
        return Ok(warnings);
    };
    let Ok(parent_metadata) = std::fs::metadata(parent) else {
        return Ok(warnings);
    };
    let parent_mode = parent_metadata.mode() & 0o7777;
    if parent_mode & 0o002 == 0 {
        return Ok(warnings);
    }
    if parent_mode & 0o1000 == 0 {
        return Err(io::Error::other(format!(
            "plugin library [{}] sits in world-writable directory [{}] (mode {:o}) with no \
             sticky bit; anyone on this host could replace it, so it will not be loaded",
            path.display(),
            parent.display(),
            parent_mode
        )));
    }
    warnings.push(format!(
        "plugin library [{}] sits in world-writable directory [{}] (mode {:o}); only the sticky \
         bit keeps another user from replacing it",
        path.display(),
        parent.display(),
        parent_mode
    ));
    Ok(warnings)
}

#[cfg(not(unix))]
fn check_plugin_file_permissions(_path: &Path) -> io::Result<Vec<String>> {
    Ok(Vec::new())
}

/// Checks a plugin file against the digest the config pinned it to.
///
/// Resolving the path says which file, and the permission checks say who may
/// write it; neither says anything about what is in it. A digest does, and it
/// is the only control here that still holds against someone who can write the
/// file -- including through the window between the path being resolved and
/// the loader opening it. An operator who knows which build they meant to run
/// can say so, and a plugin that has since been swapped fails to load instead
/// of running.
fn verify_plugin_digest(path: &Path, expected: &str) -> io::Result<()> {
    let expected = expected.trim();
    let expected_bytes = hex::decode(expected).map_err(|err| {
        io::Error::other(format!(
            "plugin [{}] has an unreadable sha256 pin [{}]: {}",
            path.display(),
            expected,
            err
        ))
    })?;
    if expected_bytes.len() != 32 {
        return Err(io::Error::other(format!(
            "plugin [{}] sha256 pin is {} bytes, not the 32 a sha256 digest has",
            path.display(),
            expected_bytes.len()
        )));
    }
    let actual = plugin_file_digest(path)?;
    if actual != hex::encode(&expected_bytes) {
        return Err(io::Error::other(format!(
            "plugin [{}] does not match its sha256 pin: expected {}, found {}",
            path.display(),
            hex::encode(&expected_bytes),
            actual
        )));
    }
    debug!(
        plugin_path = %path.display(),
        sha256 = %expected,
        "plugin library matches its pinned digest"
    );
    Ok(())
}

/// The sha256 of a plugin file, as lowercase hex.
///
/// This is the value an operator puts in `sha256`, which is why
/// [`inspect_plugin`] prints it whether or not one was pinned: the digest of a
/// build you have in front of you is exactly what you need to pin it to.
fn plugin_file_digest(path: &Path) -> io::Result<String> {
    let mut file = std::fs::File::open(path).map_err(|err| {
        io::Error::other(format!(
            "failed to open plugin [{}] to digest it: {}",
            path.display(),
            err
        ))
    })?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).map_err(|err| {
        io::Error::other(format!(
            "failed to read plugin [{}] to digest it: {}",
            path.display(),
            err
        ))
    })?;
    Ok(hex::encode(hasher.finalize()))
}

/// Opens a plugin library, saying as much as the platform will about a failure.
///
/// A plugin that does not open is nearly always a deployment problem rather
/// than a code one -- the wrong architecture, a dependency that is not beside
/// it or on `PATH` -- and the loader error alone rarely says which. Everything
/// cheap that narrows it down goes in the message, because the operator
/// reading it may not be able to reproduce the failure anywhere else.
///
/// # Safety
///
/// Opening a library runs its initialisers in this process.
unsafe fn open_plugin_library(resolved: &Path, plugin_path: &str) -> io::Result<Library> {
    Library::new(resolved).map_err(|err| {
        let current_dir = std::env::current_dir()
            .map(|dir| dir.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        #[allow(unused_mut)]
        let mut details = vec![
            format!("failed to open plugin library [{}]: {}", plugin_path, err),
            format!("current_dir={}", current_dir),
            format!("resolved_path={}", resolved.display()),
        ];
        #[cfg(windows)]
        {
            let os_error = io::Error::last_os_error();
            details.push(format!("windows_os_error={}", os_error));
            if let Some(code) = os_error.raw_os_error() {
                details.push(format!("windows_os_error_code={}", code));
            }
            details.push(
                "hint=the plugin dll may depend on extra MinGW or C runtime DLLs that are not in PATH or beside the plugin"
                    .to_string(),
            );
        }
        io::Error::new(io::ErrorKind::Other, details.join("; "))
    })
}

unsafe fn read_plugin_descriptor(
    lib: &Library,
    plugin_path: &str,
) -> io::Result<(
    LoadedPluginMetadata,
    Option<Arc<StreamEnginePlugin>>,
    Option<Arc<DatagramEnginePlugin>>,
)> {
    let descriptor_fn = lib
        .get::<PluginDescriptorFn>(PLUGIN_DESCRIPTOR_SYMBOL)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "plugin [{}] is missing required symbol [leaf_plugin_get_descriptor]: {}",
                    plugin_path, err
                ),
            )
        })?;

    let descriptor = descriptor_fn();
    let descriptor = read_abi_struct(descriptor, plugin_path)?;
    let metadata = validate_plugin_descriptor(&descriptor, plugin_path)?;
    let stream_engine = if descriptor.stream.is_null() {
        None
    } else {
        let stream_engine = read_abi_struct(descriptor.stream, plugin_path)?;
        validate_stream_engine(&stream_engine, plugin_path)?;
        Some(Arc::new(stream_engine))
    };
    let datagram_engine = if descriptor.datagram.is_null() {
        None
    } else {
        let datagram_engine = read_abi_struct(descriptor.datagram, plugin_path)?;
        validate_datagram_engine(&datagram_engine, plugin_path)?;
        Some(Arc::new(datagram_engine))
    };
    if stream_engine.is_none() && datagram_engine.is_none() {
        return Err(io::Error::other(format!(
            "plugin [{}] descriptor exports neither stream nor datagram engine",
            plugin_path
        )));
    }

    Ok((metadata, stream_engine, datagram_engine))
}

fn validate_plugin_descriptor(
    descriptor: &PluginDescriptor,
    plugin_path: &str,
) -> io::Result<LoadedPluginMetadata> {
    ensure_required_struct_size::<PluginDescriptor>(descriptor.size, plugin_path)?;
    if descriptor.abi_major != PLUGIN_ABI_MAJOR {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "plugin [{}] ABI major version {} is incompatible with host ABI major version {}",
                plugin_path, descriptor.abi_major, PLUGIN_ABI_MAJOR
            ),
        ));
    }
    let name = cstr_to_string(descriptor.name, "name", plugin_path)?;
    let version = cstr_to_string(descriptor.version, "version", plugin_path)?;

    Ok(LoadedPluginMetadata {
        abi_major: descriptor.abi_major,
        abi_minor: descriptor.abi_minor,
        name,
        version,
        // Unknown bits are ignored rather than refused: a flag may only ever
        // ask for treatment that is safe to omit, so a plugin built against a
        // later minor still loads here and simply does not get what this host
        // does not know how to give.
        embeds_runtime: descriptor.flags & PLUGIN_FLAG_EMBEDS_RUNTIME != 0,
    })
}

fn validate_stream_engine(engine: &StreamEnginePlugin, plugin_path: &str) -> io::Result<()> {
    ensure_required_struct_size::<StreamEnginePlugin>(engine.size, plugin_path)?;
    validate_required_fn(
        engine.create_instance,
        "stream.create_instance",
        plugin_path,
    )?;
    validate_required_fn(
        engine.destroy_instance,
        "stream.destroy_instance",
        plugin_path,
    )?;
    validate_required_fn(engine.poll_state, "stream.poll_state", plugin_path)?;
    validate_required_fn(engine.push, "stream.push", plugin_path)?;
    validate_required_fn(engine.pull, "stream.pull", plugin_path)?;
    validate_required_fn(engine.close, "stream.close", plugin_path)?;
    validate_required_fn(engine.get_last_error, "stream.get_last_error", plugin_path)?;
    validate_required_fn(
        engine.suggest_output_size,
        "stream.suggest_output_size",
        plugin_path,
    )?;
    validate_required_fn(
        engine.suggest_output_batch,
        "stream.suggest_output_batch",
        plugin_path,
    )?;
    Ok(())
}

fn validate_datagram_engine(engine: &DatagramEnginePlugin, plugin_path: &str) -> io::Result<()> {
    ensure_required_struct_size::<DatagramEnginePlugin>(engine.size, plugin_path)?;
    validate_required_fn(
        engine.create_instance,
        "datagram.create_instance",
        plugin_path,
    )?;
    validate_required_fn(
        engine.destroy_instance,
        "datagram.destroy_instance",
        plugin_path,
    )?;
    validate_required_fn(engine.encode_packet, "datagram.encode_packet", plugin_path)?;
    validate_required_fn(engine.decode_packet, "datagram.decode_packet", plugin_path)?;
    validate_required_fn(
        engine.max_output_size,
        "datagram.max_output_size",
        plugin_path,
    )?;
    validate_required_fn(
        engine.max_address_size,
        "datagram.max_address_size",
        plugin_path,
    )?;
    validate_required_fn(
        engine.get_last_error,
        "datagram.get_last_error",
        plugin_path,
    )?;
    Ok(())
}

fn validate_required_fn<T>(fp: Option<T>, field_name: &str, plugin_path: &str) -> io::Result<()> {
    if fp.is_none() {
        return Err(io::Error::other(format!(
            "plugin [{}] has null required field [{}]",
            plugin_path, field_name
        )));
    }
    Ok(())
}

/// What a plugin library declares about itself, as the loader reads it.
///
/// Produced by [`inspect_plugin`]. Every field here is something the loader
/// would have established anyway on its way to registering an outbound, which
/// is what makes the report worth having: it is the loader's own answer, not a
/// second opinion arrived at some other way.
#[derive(Debug, Clone)]
pub struct PluginReport {
    /// The file the loader would open, after resolution.
    pub path: PathBuf,
    /// Its sha256, lowercase hex -- the value to pin `sha256` to.
    pub sha256: String,
    /// The name the plugin gives itself. Diagnostic only; nothing keys on it.
    pub name: String,
    /// The version the plugin gives itself, likewise.
    pub version: String,
    /// The ABI the plugin was built against. The major must equal the host's.
    pub abi_major: u32,
    pub abi_minor: u32,
    /// The plugin carries a language runtime, so once loaded its library stays
    /// mapped for the life of the process.
    pub embeds_runtime: bool,
    /// What loading would have logged and gone ahead anyway.
    pub warnings: Vec<String>,
    pub stream: Option<StreamEngineReport>,
    pub datagram: Option<DatagramEngineReport>,
}

/// The stream engine half of a [`PluginReport`].
#[derive(Debug, Clone)]
pub struct StreamEngineReport {
    /// `proxy-tcp`, `direct`, or `next`.
    pub connect_type: &'static str,
    /// Whether the outbound must carry `host` and `port`. A transport plugin
    /// that layers on whatever precedes it in a chain must not.
    pub needs_endpoint: bool,
}

/// The datagram engine half of a [`PluginReport`].
#[derive(Debug, Clone)]
pub struct DatagramEngineReport {
    /// `reliable` if the engine frames over the chain's stream transport,
    /// `unreliable` if it wants one whole frame per UDP packet.
    pub transport_type: &'static str,
}

/// Checks a plugin library the way loading an outbound would, and says what it
/// found.
///
/// The point is that it needs no config file and starts no proxy: an operator
/// can find out whether a build will load, what the outbound will have to give
/// it, and what to pin it to, before it is anywhere near live traffic. The
/// path resolution, the permission checks, the digest and the descriptor
/// validation are the same code the loader runs, in the same order, so a
/// plugin that reports here is one that loads, and the error from a plugin
/// that does not is the error the proxy would have failed to start with.
///
/// `sha256` is the pin an outbound would have carried, checked here exactly as
/// it would be there. The report gives the digest whether or not one was
/// passed, because the first inspection of a new build is how an operator
/// finds the value to pin it to.
///
/// What this does not do is drive the engine: no instance is created and no
/// bytes go through it. A descriptor can be perfectly well formed and the
/// engine behind it still wrong.
///
/// # Safety
///
/// Reading the descriptor means opening the library, which runs whatever its
/// initialisers do in this process, with these privileges. That is the same
/// trust decision as loading it for real -- so this is a check to run on a
/// build you were going to deploy, not a way to triage one you suspect.
pub unsafe fn inspect_plugin(path: &OsStr, sha256: Option<&str>) -> io::Result<PluginReport> {
    let resolved = resolve_plugin_path(path)?;
    let warnings = check_plugin_file_permissions(&resolved)?;
    if let Some(expected) = sha256 {
        verify_plugin_digest(&resolved, expected)?;
    }
    let sha256 = plugin_file_digest(&resolved)?;
    let plugin_path = resolved.display().to_string();

    let lib = open_plugin_library(&resolved, &plugin_path)?;
    let read = read_plugin_descriptor(&lib, &plugin_path);
    // The same rule the loader keeps, for the same reason: a library carrying
    // a language runtime is never unmapped, because that runtime's threads are
    // not something any reference here can account for. Reading a descriptor
    // is enough to start one.
    if read
        .as_ref()
        .is_ok_and(|(metadata, _, _)| metadata.embeds_runtime)
    {
        core::mem::forget(lib);
    }
    let (metadata, stream_engine, datagram_engine) = read?;

    let stream = match stream_engine.as_deref() {
        None => None,
        Some(engine) => Some(match engine_stream_connect_type(engine) {
            None => StreamEngineReport {
                connect_type: "proxy-tcp",
                needs_endpoint: true,
            },
            Some(OutboundConnect::Direct) => StreamEngineReport {
                connect_type: "direct",
                needs_endpoint: false,
            },
            Some(OutboundConnect::Next) => StreamEngineReport {
                connect_type: "next",
                needs_endpoint: false,
            },
            // Reported rather than merely refused: an operator holding a
            // plugin the host will not load wants the number that says why.
            Some(OutboundConnect::Unknown) => {
                return Err(io::Error::other(format!(
                    "plugin [{}] exports stream engine with invalid connect_type={}",
                    metadata.name, engine.connect_type
                )));
            }
            Some(OutboundConnect::Proxy(_, _, _)) => unreachable!(),
        }),
    };
    let datagram = match datagram_engine.as_deref() {
        None => None,
        Some(engine) => Some(DatagramEngineReport {
            transport_type: match engine_datagram_transport_type(engine) {
                DatagramTransportType::Reliable => "reliable",
                DatagramTransportType::Unreliable => "unreliable",
                DatagramTransportType::Unknown => {
                    return Err(io::Error::other(format!(
                        "plugin [{}] exports datagram engine with invalid transport_type={}",
                        metadata.name, engine.transport_type
                    )));
                }
            },
        }),
    };

    Ok(PluginReport {
        path: resolved,
        sha256,
        name: metadata.name,
        version: metadata.version,
        abi_major: metadata.abi_major,
        abi_minor: metadata.abi_minor,
        embeds_runtime: metadata.embeds_runtime,
        warnings,
        stream,
        datagram,
    })
}

impl fmt::Display for PluginReport {
    /// Renders the report for an operator, not for a parser.
    ///
    /// The order is what someone checking a deployment asks in: which file,
    /// what is in it, what it is, and then what its config has to say.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "path:      {}", self.path.display())?;
        writeln!(f, "sha256:    {}", self.sha256)?;
        writeln!(f, "name:      {}", self.name)?;
        writeln!(f, "version:   {}", self.version)?;
        writeln!(
            f,
            "abi:       {}.{} (host {}.{})",
            self.abi_major, self.abi_minor, PLUGIN_ABI_MAJOR, PLUGIN_ABI_MINOR
        )?;
        if self.embeds_runtime {
            writeln!(
                f,
                "runtime:   embedded; the library stays mapped for the life of the process"
            )?;
        }
        match &self.stream {
            None => writeln!(f, "stream:    none")?,
            Some(stream) => {
                writeln!(f, "stream:    connect_type={}", stream.connect_type)?;
                writeln!(
                    f,
                    "           the outbound {} set host and port",
                    if stream.needs_endpoint {
                        "must"
                    } else {
                        "must not"
                    }
                )?;
            }
        }
        match &self.datagram {
            None => writeln!(f, "datagram:  none")?,
            Some(datagram) => {
                writeln!(f, "datagram:  transport_type={}", datagram.transport_type)?;
                writeln!(f, "           the outbound must set host and port")?;
            }
        }
        for warning in &self.warnings {
            writeln!(f, "warning:   {}", warning)?;
        }
        Ok(())
    }
}

/// Reads a `size`-prefixed struct the plugin exported.
///
/// The plugin only has to provide the prefix frozen for this ABI major version,
/// not whatever this build happens to have grown to, so a plugin built against
/// an older minor version still loads. Any tail this build does not know about
/// is ignored, and any field this build knows about but the plugin did not
/// provide reads back as null/`None`/zero.
///
/// # Safety
///
/// `ptr` must either be null or point to a struct whose leading `size` field
/// truthfully describes how many bytes are readable.
unsafe fn read_abi_struct<T: AbiStruct>(ptr: *const T, plugin_path: &str) -> io::Result<T> {
    if ptr.is_null() {
        return Err(io::Error::other(format!(
            "plugin [{}] returned null {} pointer",
            plugin_path,
            T::NAME
        )));
    }
    let declared_size = ptr.cast::<usize>().read();
    if declared_size < T::REQUIRED_SIZE {
        return Err(io::Error::other(format!(
            "plugin [{}] {} size {} is smaller than the {} bytes required by ABI {}.x",
            plugin_path,
            T::NAME,
            declared_size,
            T::REQUIRED_SIZE,
            PLUGIN_ABI_MAJOR
        )));
    }
    Ok(read_struct_prefix(ptr, declared_size))
}

fn ensure_required_struct_size<T: AbiStruct>(
    actual_size: usize,
    plugin_path: &str,
) -> io::Result<()> {
    if actual_size < T::REQUIRED_SIZE {
        return Err(io::Error::other(format!(
            "plugin [{}] {} size {} is smaller than the {} bytes required by ABI {}.x",
            plugin_path,
            T::NAME,
            actual_size,
            T::REQUIRED_SIZE,
            PLUGIN_ABI_MAJOR
        )));
    }
    Ok(())
}

fn cstr_to_string(ptr: *const c_char, field_name: &str, plugin_path: &str) -> io::Result<String> {
    if ptr.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "plugin [{}] has null metadata field [{}]",
                plugin_path, field_name
            ),
        ));
    }
    // Bounded, like every other string an engine hands over: a name that never
    // terminates is a plugin the host should refuse, not one it should follow
    // through memory. Refused rather than truncated, because this one is read
    // once, at load, where there is somewhere to report it.
    let length = (0..=MAX_PLUGIN_METADATA_LEN).find(|offset| unsafe { *ptr.add(*offset) } == 0);
    if length.is_none_or(|length| length > MAX_PLUGIN_METADATA_LEN) {
        return Err(io::Error::other(format!(
            "plugin [{}] metadata field [{}] is not terminated within {} bytes",
            plugin_path, field_name, MAX_PLUGIN_METADATA_LEN
        )));
    }
    let value = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "plugin [{}] metadata field [{}] is not valid UTF-8: {}",
                    plugin_path, field_name, err
                ),
            )
        })?
        .to_owned();
    if value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "plugin [{}] metadata field [{}] is empty",
                plugin_path, field_name
            ),
        ));
    }
    Ok(value)
}

pub fn socks_addr_to_plugin_address(addr: &crate::session::SocksAddr) -> (Vec<u8>, PluginAddress) {
    match addr {
        crate::session::SocksAddr::Ip(SocketAddr::V4(v4)) => {
            let data = v4.ip().octets().to_vec();
            let address = PluginAddress {
                kind: ADDRESS_KIND_IPV4,
                port: v4.port(),
                data: data.as_ptr(),
                data_len: data.len(),
            };
            (data, address)
        }
        crate::session::SocksAddr::Ip(SocketAddr::V6(v6)) => {
            let data = v6.ip().octets().to_vec();
            let address = PluginAddress {
                kind: ADDRESS_KIND_IPV6,
                port: v6.port(),
                data: data.as_ptr(),
                data_len: data.len(),
            };
            (data, address)
        }
        crate::session::SocksAddr::Domain(domain, port) => {
            let data = domain.as_bytes().to_vec();
            let address = PluginAddress {
                kind: ADDRESS_KIND_DOMAIN,
                port: *port,
                data: data.as_ptr(),
                data_len: data.len(),
            };
            (data, address)
        }
    }
}

pub fn plugin_address_to_socks_addr(
    address: &PluginAddress,
) -> io::Result<crate::session::SocksAddr> {
    let data = if address.data.is_null() || address.data_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(address.data, address.data_len) }
    };
    match address.kind {
        ADDRESS_KIND_IPV4 => {
            if data.len() != 4 {
                return Err(io::Error::other(format!(
                    "invalid IPv4 plugin address length: {}",
                    data.len()
                )));
            }
            Ok(crate::session::SocksAddr::Ip(SocketAddr::from((
                Ipv4Addr::new(data[0], data[1], data[2], data[3]),
                address.port,
            ))))
        }
        ADDRESS_KIND_IPV6 => {
            if data.len() != 16 {
                return Err(io::Error::other(format!(
                    "invalid IPv6 plugin address length: {}",
                    data.len()
                )));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(data);
            Ok(crate::session::SocksAddr::Ip(SocketAddr::from((
                Ipv6Addr::from(octets),
                address.port,
            ))))
        }
        ADDRESS_KIND_DOMAIN => {
            let domain = std::str::from_utf8(data).map_err(|err| {
                io::Error::other(format!("invalid domain plugin address UTF-8: {}", err))
            })?;
            if domain.is_empty() {
                return Err(io::Error::other("plugin address domain is empty"));
            }
            // Built through the same constructor as every other domain in the
            // proxy rather than by hand, because that is what enforces the
            // 255-byte limit the wire format has room for. `SocksAddr::write_buf`
            // writes the length as a single byte, so a longer name would be
            // truncated there without complaint and desynchronise whatever
            // parses the result -- a SOCKS5 UDP reply header, for one.
            crate::session::SocksAddr::try_from((domain.to_string(), address.port))
                .map_err(|err| io::Error::other(format!("invalid domain plugin address: {}", err)))
        }
        other => Err(io::Error::other(format!(
            "invalid plugin address kind: {}",
            other
        ))),
    }
}

fn build_engine_create_args(
    sess: &Session,
    engine_args: &str,
    metadata: &LoadedPluginMetadata,
) -> io::Result<(
    std::ffi::CString,
    Vec<u8>,
    Box<PluginAddress>,
    PluginInstanceHandle,
    Box<HostCallbacks>,
    EngineCreateArgs,
)> {
    let engine_args = std::ffi::CString::new(engine_args).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "invalid engine args for plugin [{}]: {}",
                metadata.name, err
            ),
        )
    })?;
    let (destination_data, destination) = socks_addr_to_plugin_address(&sess.destination);
    let destination = Box::new(destination);
    let log_context = PluginInstanceHandle::register(PluginInstanceContext {
        span: sess.span(),
        plugin: metadata.name.clone(),
        read_waker: futures::task::AtomicWaker::new(),
        write_waker: futures::task::AtomicWaker::new(),
    });
    let host_callbacks = Box::new(HostCallbacks {
        size: std::mem::size_of::<HostCallbacks>(),
        log: Some(host_log_callback),
        wake: Some(host_wake_callback),
        host_ctx: log_context.host_ctx(),
    });
    let create_args = EngineCreateArgs {
        size: std::mem::size_of::<EngineCreateArgs>(),
        plugin_args: engine_args.as_ptr(),
        destination: destination.as_ref(),
        host_callbacks: host_callbacks.as_ref(),
        host_abi_major: PLUGIN_ABI_MAJOR,
        host_abi_minor: PLUGIN_ABI_MINOR,
    };
    Ok((
        engine_args,
        destination_data,
        destination,
        log_context,
        host_callbacks,
        create_args,
    ))
}

fn datagram_encode_input_hint_len(payload_len: usize, target: &crate::session::SocksAddr) -> usize {
    payload_len.saturating_add(target.size())
}

/// Runs the body of a host callback behind a panic barrier.
///
/// A callback returns into the plugin's frames -- C, Go or Zig, none of which
/// can be unwound through -- so Rust turns a panic out of an `extern "C"`
/// function into an abort. Without this, a mistake anywhere in a callback, or
/// in the tracing layer underneath one, takes the whole proxy down on behalf
/// of a plugin that did nothing worse than log. The panic still reaches stderr
/// through the default hook; what this adds is that the plugin gets its call
/// back and the process survives.
fn guard_host_callback(body: impl FnOnce()) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
}

/// Copies a NUL-terminated string an engine supplied, reading at most
/// `max_len` bytes of it.
///
/// `CStr::from_ptr` scans to the NUL however far away it is, which trusts the
/// plugin for the one thing a wrong pointer makes unbounded. This stops at the
/// cap instead, and goes through `from_utf8_lossy`, so a multi-byte character
/// straddling the cut costs a replacement character rather than the panic that
/// slicing a `str` at a byte index would raise.
unsafe fn read_plugin_cstr(ptr: *const c_char, max_len: usize) -> String {
    let mut len = 0;
    while len < max_len && *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(ptr.cast::<u8>(), len)).into_owned()
}

unsafe extern "C" fn host_wake_callback(host_ctx: *mut c_void) {
    guard_host_callback(|| {
        // `None` is an engine waking an instance that has already been
        // destroyed, which is out of contract but must not be fatal.
        let Some(ctx) = plugin_instance_context(host_ctx) else {
            return;
        };
        ctx.read_waker.wake();
        ctx.write_waker.wake();
    })
}

unsafe extern "C" fn host_log_callback(
    host_ctx: *mut c_void,
    level: u32,
    target: *const c_char,
    message: *const u8,
    message_len: usize,
) {
    guard_host_callback(|| host_log(host_ctx, level, target, message, message_len))
}

unsafe fn host_log(
    host_ctx: *mut c_void,
    level: u32,
    target: *const c_char,
    message: *const u8,
    message_len: usize,
) {
    let Some(ctx) = plugin_instance_context(host_ctx) else {
        return;
    };
    let plugin_target = if target.is_null() {
        "leaf.plugin".to_string()
    } else {
        sanitize_plugin_text(read_plugin_cstr(target, MAX_PLUGIN_LOG_TARGET_LEN).trim())
    };
    let plugin_target = if plugin_target.is_empty() {
        "leaf.plugin".to_string()
    } else {
        plugin_target
    };
    // Truncated before it is copied: the length is the plugin's word, and a
    // wrong one should cost a short log line rather than the process.
    let message = if message_len == 0 || message.is_null() {
        String::new()
    } else {
        let len = message_len.min(MAX_PLUGIN_LOG_LEN);
        sanitize_plugin_text(&String::from_utf8_lossy(std::slice::from_raw_parts(
            message, len,
        )))
    };
    let plugin_target = plugin_target.as_str();
    let _guard = ctx.span.enter();
    match level {
        LOG_LEVEL_ERROR => tracing::error!(
            target: "leaf::plugin",
            plugin = %ctx.plugin,
            plugin_target = plugin_target,
            "{message}"
        ),
        LOG_LEVEL_WARN => tracing::warn!(
            target: "leaf::plugin",
            plugin = %ctx.plugin,
            plugin_target = plugin_target,
            "{message}"
        ),
        LOG_LEVEL_INFO => tracing::info!(
            target: "leaf::plugin",
            plugin = %ctx.plugin,
            plugin_target = plugin_target,
            "{message}"
        ),
        LOG_LEVEL_DEBUG => tracing::debug!(
            target: "leaf::plugin",
            plugin = %ctx.plugin,
            plugin_target = plugin_target,
            "{message}"
        ),
        LOG_LEVEL_TRACE => tracing::trace!(
            target: "leaf::plugin",
            plugin = %ctx.plugin,
            plugin_target = plugin_target,
            "{message}"
        ),
        other => tracing::debug!(
            target: "leaf::plugin",
            plugin = %ctx.plugin,
            plugin_target = plugin_target,
            log_level = other,
            "{message}"
        ),
    }
}

unsafe fn read_plugin_error(
    get_last_error: PluginLastErrorFn,
    instance: *mut std::ffi::c_void,
    fallback_status: i32,
) -> Option<(i32, String)> {
    let mut code = fallback_status;
    let mut required = 0usize;
    if get_last_error(instance, &mut code, std::ptr::null_mut(), 0, &mut required) != 0 {
        return None;
    }
    if required == 0 {
        return Some((code, String::new()));
    }
    // The length is the engine's word and nothing checks it, so cap it here
    // rather than let a wrong one become an allocation the process cannot
    // satisfy. A truncated message still says what went wrong.
    let capacity = required.min(MAX_PLUGIN_ERROR_LEN);
    let mut buffer = vec![0u8; capacity];
    if get_last_error(
        instance,
        &mut code,
        buffer.as_mut_ptr(),
        buffer.len(),
        &mut required,
    ) != 0
    {
        return None;
    }
    buffer.truncate(required.min(capacity));
    Some((
        code,
        sanitize_plugin_text(&String::from_utf8_lossy(&buffer)),
    ))
}

/// Makes a plugin-supplied string safe to put in a log line or an error.
///
/// Both end up in the host's log verbatim, so an embedded newline would let a
/// plugin forge an entry of its own. Control characters are escaped rather than
/// dropped, so what the plugin actually said stays recoverable.
fn sanitize_plugin_text(input: &str) -> String {
    if !input.chars().any(char::is_control) {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_control() {
            out.extend(ch.escape_debug());
        } else {
            out.push(ch);
        }
    }
    out
}

fn format_plugin_error(
    engine_kind: &str,
    label: &str,
    status_code: i32,
    detail: Option<(i32, String)>,
) -> String {
    match detail {
        Some((plugin_code, message)) if !message.is_empty() && plugin_code != status_code => {
            format!(
                "{} {} failed with status {} (plugin code {}): {}",
                engine_kind, label, status_code, plugin_code, message
            )
        }
        Some((_, message)) if !message.is_empty() => {
            format!(
                "{} {} failed with status {}: {}",
                engine_kind, label, status_code, message
            )
        }
        _ => format!(
            "{} {} failed with status {}",
            engine_kind, label, status_code
        ),
    }
}

fn format_plugin_error_suffix(detail: Option<(i32, String)>) -> String {
    match detail {
        Some((code, message)) if !message.is_empty() => {
            format!(": status {}: {}", code, message)
        }
        Some((code, _)) => format!(": status {}", code),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// A stream engine driven entirely from the test, used to put the host's
    /// poll loop into states a well-behaved plugin reaches but the reference
    /// plugins do not.
    #[derive(Default)]
    struct MockEngine {
        /// Bytes the engine is holding for the network.
        net_out: Vec<u8>,
        /// Bytes the engine is holding for the application.
        app_out: Vec<u8>,
        /// Refuse application input once this much is queued for the network.
        net_out_limit: Option<usize>,
        /// Take nothing and ask for nothing, whatever the host does.
        always_stall: bool,
        /// Withhold application input until the peer has sent something.
        wait_for_net_input: bool,
        got_net_input: bool,
        /// Withhold application input until the host has drained what the
        /// engine is holding for the application.
        refuse_while_app_output_pending: bool,
        /// Report `BLOCKED` and take nothing until this is set, standing in for
        /// an engine waiting on work of its own.
        blocked_until: Option<Arc<std::sync::atomic::AtomicBool>>,
        /// Hold back the network output until this is set, standing in for an
        /// engine whose own work produces the first bytes on the wire.
        net_out_release: Option<Arc<std::sync::atomic::AtomicBool>>,
        /// Claim to have consumed more than it was given.
        overreport_consumed: bool,
        /// Claim to have produced more than the buffer holds.
        overreport_produced: bool,
    }

    impl MockEngine {
        /// Builds an `EngineStream` over `stream` driven by this engine.
        ///
        /// The returned pointer stays owned by the caller for the lifetime of
        /// the stream; the vtable's `destroy_instance` is a no-op so the test
        /// keeps its handle on the state.
        fn into_stream(
            self,
            stream: AnyStream,
        ) -> (EngineStream, *mut MockEngine, *mut std::ffi::c_void) {
            let instance = Box::into_raw(Box::new(self));
            let engine = Arc::new(StreamEnginePlugin {
                size: std::mem::size_of::<StreamEnginePlugin>(),
                connect_type: STREAM_CONNECT_TYPE_NEXT,
                create_instance: None,
                destroy_instance: Some(mock_destroy),
                poll_state: Some(mock_poll_state),
                push: Some(mock_push),
                pull: Some(mock_pull),
                close: Some(mock_close),
                get_last_error: Some(mock_get_last_error),
                suggest_output_size: Some(mock_suggest_output_size),
                suggest_output_batch: Some(mock_suggest_output_batch),
            });
            let log_context = PluginInstanceHandle::register(PluginInstanceContext {
                span: tracing::Span::none(),
                plugin: "mock".to_string(),
                read_waker: futures::task::AtomicWaker::new(),
                write_waker: futures::task::AtomicWaker::new(),
            });
            let host_ctx = log_context.host_ctx();
            let engine_stream = EngineStream::new(
                stream,
                engine,
                instance as *mut std::ffi::c_void,
                log_context,
                None,
            );
            (engine_stream, instance, host_ctx)
        }
    }

    unsafe extern "C" fn mock_destroy(_instance: *mut std::ffi::c_void) {}

    unsafe extern "C" fn mock_poll_state(
        instance: *mut std::ffi::c_void,
        state_flags: *mut u32,
    ) -> i32 {
        let engine = &*(instance as *const MockEngine);
        let mut flags = STREAM_ENGINE_STATE_ESTABLISHED;
        if !engine.net_out.is_empty() && engine.net_out_ready() {
            flags |= STREAM_ENGINE_STATE_HAS_NET_OUTPUT;
        }
        if !engine.app_out.is_empty() {
            flags |= STREAM_ENGINE_STATE_HAS_APP_OUTPUT;
        }
        if engine.is_blocked() {
            flags |= STREAM_ENGINE_STATE_BLOCKED;
        } else if !engine.always_stall {
            flags |= STREAM_ENGINE_STATE_WANT_NET_INPUT;
            if engine.accepts_app_input() {
                flags |= STREAM_ENGINE_STATE_WANT_APP_INPUT;
            }
        }
        *state_flags = flags;
        ENGINE_STATUS_OK
    }

    impl MockEngine {
        fn is_blocked(&self) -> bool {
            self.blocked_until
                .as_ref()
                .is_some_and(|flag| !flag.load(std::sync::atomic::Ordering::SeqCst))
        }

        fn net_out_ready(&self) -> bool {
            self.net_out_release
                .as_ref()
                .is_none_or(|flag| flag.load(std::sync::atomic::Ordering::SeqCst))
        }

        fn accepts_app_input(&self) -> bool {
            if self.always_stall {
                return false;
            }
            if self.wait_for_net_input && !self.got_net_input {
                return false;
            }
            if self.refuse_while_app_output_pending && !self.app_out.is_empty() {
                return false;
            }
            if self.is_blocked() {
                return false;
            }
            match self.net_out_limit {
                Some(limit) => self.net_out.len() < limit,
                None => true,
            }
        }
    }

    unsafe extern "C" fn mock_push(
        instance: *mut std::ffi::c_void,
        side: u32,
        input: *const u8,
        input_len: usize,
        consumed: *mut usize,
    ) -> i32 {
        let engine = &mut *(instance as *mut MockEngine);
        let input = if input_len == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(input, input_len)
        };
        match side {
            STREAM_SIDE_APP => {
                if !engine.accepts_app_input() {
                    *consumed = 0;
                    return ENGINE_STATUS_OK;
                }
                let room = match engine.net_out_limit {
                    Some(limit) => limit - engine.net_out.len(),
                    None => input.len(),
                };
                let take = input.len().min(room);
                engine.net_out.extend_from_slice(&input[..take]);
                *consumed = if engine.overreport_consumed {
                    input.len() + 1
                } else {
                    take
                };
            }
            STREAM_SIDE_NET => {
                engine.got_net_input = true;
                engine.app_out.extend_from_slice(input);
                *consumed = input.len();
            }
            _ => return ENGINE_STATUS_INVALID_ARGUMENT,
        }
        ENGINE_STATUS_OK
    }

    unsafe extern "C" fn mock_pull(
        instance: *mut std::ffi::c_void,
        side: u32,
        output: *mut u8,
        output_cap: usize,
        produced: *mut usize,
    ) -> i32 {
        let engine = &mut *(instance as *mut MockEngine);
        if side == STREAM_SIDE_NET && !engine.net_out_ready() {
            *produced = 0;
            return ENGINE_STATUS_OK;
        }
        let source = match side {
            STREAM_SIDE_APP => &mut engine.app_out,
            STREAM_SIDE_NET => &mut engine.net_out,
            _ => return ENGINE_STATUS_INVALID_ARGUMENT,
        };
        let take = source.len().min(output_cap);
        if take > 0 {
            std::slice::from_raw_parts_mut(output, output_cap)[..take]
                .copy_from_slice(&source[..take]);
            source.drain(..take);
        }
        *produced = if engine.overreport_produced {
            output_cap + 1
        } else {
            take
        };
        ENGINE_STATUS_OK
    }

    unsafe extern "C" fn mock_close(_instance: *mut std::ffi::c_void, _flags: u32) -> i32 {
        ENGINE_STATUS_OK
    }

    unsafe extern "C" fn mock_get_last_error(
        _instance: *mut std::ffi::c_void,
        _code: *mut i32,
        _output: *mut u8,
        _output_cap: usize,
        required: *mut usize,
    ) -> i32 {
        *required = 0;
        ENGINE_STATUS_OK
    }

    unsafe extern "C" fn mock_suggest_output_size(
        _instance: *mut std::ffi::c_void,
        _side: u32,
    ) -> usize {
        4096
    }

    unsafe extern "C" fn mock_suggest_output_batch(
        _instance: *mut std::ffi::c_void,
        _side: u32,
    ) -> usize {
        4
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// An engine that hands back short writes must still get the whole buffer
    /// through, in as many rounds as it takes.
    #[test]
    fn write_all_completes_when_the_engine_accepts_input_in_small_chunks() {
        let payload = vec![0xabu8; 64 * 1024];
        let expected = payload.clone();
        block_on(async move {
            let (near, far) = tokio::io::duplex(4096);
            let reader = tokio::spawn(async move {
                let mut far = far;
                let mut got = Vec::new();
                far.read_to_end(&mut got).await.unwrap();
                got
            });

            let engine = MockEngine {
                // Far smaller than the payload, so the host has to drain and
                // retry many times to get it all through.
                net_out_limit: Some(1024),
                ..Default::default()
            };
            let (mut stream, instance, _host_ctx) = engine.into_stream(Box::new(near) as AnyStream);
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            drop(stream);
            unsafe { drop(Box::from_raw(instance)) };

            assert_eq!(reader.await.unwrap(), expected);
        });
    }

    /// An engine that refuses application input until the host has collected
    /// what it is holding for the application returns `consumed == 0`. That is
    /// backpressure; before, the host reported it as `WriteZero` and killed the
    /// connection.
    #[test]
    fn write_survives_an_engine_that_refuses_input_until_its_output_is_drained() {
        block_on(async move {
            let (near, far) = tokio::io::duplex(4096);
            let peer = tokio::spawn(async move {
                let mut far = far;
                let mut got = vec![0u8; 5];
                far.read_exact(&mut got).await.unwrap();
                got
            });

            let engine = MockEngine {
                refuse_while_app_output_pending: true,
                app_out: b"pending-for-the-app".to_vec(),
                ..Default::default()
            };
            let (mut stream, instance, _host_ctx) = engine.into_stream(Box::new(near) as AnyStream);

            // The engine takes nothing until its application output has been
            // collected, which the write path has to do on its own.
            stream.write_all(b"hello").await.unwrap();
            stream.flush().await.unwrap();
            assert_eq!(peer.await.unwrap(), b"hello".to_vec());

            // The bytes the write path collected are still delivered in order.
            let mut got = vec![0u8; b"pending-for-the-app".len()];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, b"pending-for-the-app".to_vec());

            drop(stream);
            unsafe { drop(Box::from_raw(instance)) };
        });
    }

    /// An engine that withholds application input until the peer has spoken --
    /// a handshake -- must make the write wait for the peer, not fail.
    #[test]
    fn write_waits_for_an_engine_that_needs_network_input_first() {
        block_on(async move {
            let (near, far) = tokio::io::duplex(4096);
            let peer = tokio::spawn(async move {
                let mut far = far;
                // Nothing arrives until the engine has been unblocked, so this
                // write is what lets the pending write through.
                far.write_all(b"server-hello").await.unwrap();
                let mut got = vec![0u8; 5];
                far.read_exact(&mut got).await.unwrap();
                got
            });

            let engine = MockEngine {
                wait_for_net_input: true,
                ..Default::default()
            };
            let (mut stream, instance, _host_ctx) = engine.into_stream(Box::new(near) as AnyStream);
            stream.write_all(b"hello").await.unwrap();
            stream.flush().await.unwrap();

            assert_eq!(peer.await.unwrap(), b"hello".to_vec());
            drop(stream);
            unsafe { drop(Box::from_raw(instance)) };
        });
    }

    /// An engine waiting on work of its own reports `BLOCKED`; the host must
    /// park until the engine's readiness callback fires, rather than spin,
    /// fail, or hang forever.
    #[test]
    fn write_parks_until_a_blocked_engine_signals_readiness() {
        block_on(async move {
            let (near, far) = tokio::io::duplex(4096);
            let peer = tokio::spawn(async move {
                let mut far = far;
                let mut got = vec![0u8; 5];
                far.read_exact(&mut got).await.unwrap();
                got
            });

            let unblock = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let engine = MockEngine {
                blocked_until: Some(Arc::clone(&unblock)),
                ..Default::default()
            };
            let (mut stream, instance, host_ctx) = engine.into_stream(Box::new(near) as AnyStream);

            // Nothing but the callback can get the write moving again, so if
            // the host fails to register the waker this test hangs.
            let host_ctx = host_ctx as usize;
            let waker_thread = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(50));
                unblock.store(true, std::sync::atomic::Ordering::SeqCst);
                unsafe { host_wake_callback(host_ctx as *mut std::ffi::c_void) };
            });

            // A lost wake shows up as a hang, so bound it: the test must fail
            // rather than stall CI.
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                stream.write_all(b"hello").await.unwrap();
                stream.flush().await.unwrap();
                assert_eq!(peer.await.unwrap(), b"hello".to_vec());
            })
            .await
            .expect("the write was never woken");

            waker_thread.join().unwrap();
            drop(stream);
            unsafe { drop(Box::from_raw(instance)) };
        });
    }

    /// The readiness callback has to be honoured even when the host is parked
    /// on the socket rather than on the engine. An engine that produces the
    /// first bytes on the wire from its own work -- a client hello -- wakes
    /// while the host is waiting for a peer that is itself waiting for those
    /// bytes, so a wake that lands on no waker deadlocks the handshake.
    #[test]
    fn a_wake_is_honoured_while_the_host_waits_on_the_socket() {
        block_on(async move {
            let (near, far) = tokio::io::duplex(4096);
            let peer = tokio::spawn(async move {
                let mut far = far;
                let mut got = vec![0u8; 12];
                far.read_exact(&mut got).await.unwrap();
                got
            });

            let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let engine = MockEngine {
                net_out: b"client-hello".to_vec(),
                net_out_release: Some(Arc::clone(&release)),
                ..Default::default()
            };
            let (stream, instance, host_ctx) = engine.into_stream(Box::new(near) as AnyStream);

            // The read parks on the socket: the engine is not blocked, it wants
            // network input, and the peer sends nothing until it has been
            // greeted.
            let reader = tokio::spawn(async move {
                let mut stream = stream;
                let mut buf = [0u8; 1];
                let _ = stream.read(&mut buf).await;
                stream
            });

            let host_ctx = host_ctx as usize;
            let waker_thread = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(50));
                release.store(true, std::sync::atomic::Ordering::SeqCst);
                unsafe { host_wake_callback(host_ctx as *mut std::ffi::c_void) };
            });

            // A lost wake shows up as a hang, so bound it.
            let got = tokio::time::timeout(std::time::Duration::from_secs(5), peer)
                .await
                .expect("the engine output was never flushed after the wake")
                .unwrap();
            assert_eq!(got, b"client-hello".to_vec());

            waker_thread.join().unwrap();
            reader.abort();
            let _ = reader.await;
            unsafe { drop(Box::from_raw(instance)) };
        });
    }

    /// A count larger than the buffer it describes must be rejected. Trusting
    /// it would either panic on a buffer split or silently misreport how much
    /// of the caller's data was written.
    #[test]
    fn rejects_an_engine_that_overreports_what_it_consumed() {
        block_on(async move {
            let (near, _far) = tokio::io::duplex(4096);
            let engine = MockEngine {
                overreport_consumed: true,
                ..Default::default()
            };
            let (mut stream, instance, _host_ctx) = engine.into_stream(Box::new(near) as AnyStream);
            let err = stream.write_all(b"hello").await.unwrap_err();
            assert!(
                err.to_string()
                    .contains("consumed 6 bytes of a 5 byte input"),
                "unexpected error: {err}"
            );
            drop(stream);
            unsafe { drop(Box::from_raw(instance)) };
        });
    }

    #[test]
    fn rejects_an_engine_that_overreports_what_it_produced() {
        block_on(async move {
            let (near, _far) = tokio::io::duplex(4096);
            let engine = MockEngine {
                app_out: b"decoded".to_vec(),
                overreport_produced: true,
                ..Default::default()
            };
            let (mut stream, instance, _host_ctx) = engine.into_stream(Box::new(near) as AnyStream);
            let mut buf = [0u8; 16];
            let err = stream.read(&mut buf).await.unwrap_err();
            assert!(
                err.to_string().contains("produced"),
                "unexpected error: {err}"
            );
            drop(stream);
            unsafe { drop(Box::from_raw(instance)) };
        });
    }

    /// An engine that takes nothing and asks for nothing is broken. The host
    /// must say so rather than spin or hang.
    #[test]
    fn write_reports_an_engine_that_can_never_make_progress() {
        block_on(async move {
            let (near, _far) = tokio::io::duplex(4096);
            let engine = MockEngine {
                always_stall: true,
                ..Default::default()
            };
            let (mut stream, instance, _host_ctx) = engine.into_stream(Box::new(near) as AnyStream);
            let err = stream.write_all(b"hello").await.unwrap_err();
            assert!(
                err.to_string().contains("made no progress"),
                "unexpected error: {err}"
            );
            drop(stream);
            unsafe { drop(Box::from_raw(instance)) };
        });
    }

    fn demo_descriptor(
        name: &CString,
        version: &CString,
        abi_major: u32,
        abi_minor: u32,
    ) -> PluginDescriptor {
        PluginDescriptor {
            size: std::mem::size_of::<PluginDescriptor>(),
            abi_major,
            abi_minor,
            name: name.as_ptr(),
            version: version.as_ptr(),
            stream: std::ptr::null(),
            datagram: std::ptr::null(),
            flags: 0,
        }
    }

    #[test]
    fn validates_supported_plugin_descriptor() {
        let name = CString::new("demo-plugin").unwrap();
        let version = CString::new("0.1.0").unwrap();
        let descriptor = demo_descriptor(&name, &version, PLUGIN_ABI_MAJOR, PLUGIN_ABI_MINOR);

        let parsed = validate_plugin_descriptor(&descriptor, "demo.so").unwrap();
        assert_eq!(parsed.name, "demo-plugin");
        assert_eq!(parsed.version, "0.1.0");
        assert_eq!(parsed.abi_major, PLUGIN_ABI_MAJOR);
    }

    #[test]
    fn rejects_incompatible_abi_major_version() {
        let name = CString::new("demo-plugin").unwrap();
        let version = CString::new("0.1.0").unwrap();
        let descriptor = demo_descriptor(&name, &version, PLUGIN_ABI_MAJOR + 1, PLUGIN_ABI_MINOR);

        let err = validate_plugin_descriptor(&descriptor, "demo.so").unwrap_err();
        assert!(err.to_string().contains("ABI major version"));
    }

    #[test]
    fn accepts_any_abi_minor_version() {
        let name = CString::new("demo-plugin").unwrap();
        let version = CString::new("0.1.0").unwrap();
        // Both an older plugin and one from the future are fine: the minor
        // version never gates loading, the per-struct `size` does.
        for minor in [0, PLUGIN_ABI_MINOR + 7] {
            let descriptor = demo_descriptor(&name, &version, PLUGIN_ABI_MAJOR, minor);
            let parsed = validate_plugin_descriptor(&descriptor, "demo.so").unwrap();
            assert_eq!(parsed.abi_minor, minor);
        }
    }

    #[test]
    fn reads_descriptor_from_a_plugin_that_declared_only_the_required_prefix() {
        let name = CString::new("demo-plugin").unwrap();
        let version = CString::new("0.1.0").unwrap();
        let descriptor = demo_descriptor(&name, &version, PLUGIN_ABI_MAJOR, PLUGIN_ABI_MINOR);

        let parsed =
            unsafe { read_abi_struct(&descriptor as *const PluginDescriptor, "demo.so") }.unwrap();
        assert_eq!(parsed.abi_major, PLUGIN_ABI_MAJOR);
        assert!(parsed.stream.is_null());
    }

    #[test]
    fn rejects_a_struct_shorter_than_the_required_prefix() {
        let name = CString::new("demo-plugin").unwrap();
        let version = CString::new("0.1.0").unwrap();
        let mut descriptor = demo_descriptor(&name, &version, PLUGIN_ABI_MAJOR, PLUGIN_ABI_MINOR);
        descriptor.size = PluginDescriptor::REQUIRED_SIZE - 1;

        let err = unsafe { read_abi_struct(&descriptor as *const PluginDescriptor, "demo.so") }
            .unwrap_err();
        assert!(err.to_string().contains("is smaller than"));
    }

    #[test]
    fn ignores_trailing_bytes_from_a_plugin_built_against_a_newer_minor_version() {
        // A future plugin appends fields and reports the larger size. The host
        // must read the prefix it knows and ignore the rest rather than
        // rejecting the plugin.
        #[repr(C)]
        struct FutureDescriptor {
            base: PluginDescriptor,
            appended: u64,
        }
        let name = CString::new("demo-plugin").unwrap();
        let version = CString::new("0.1.0").unwrap();
        let future = FutureDescriptor {
            base: PluginDescriptor {
                size: std::mem::size_of::<FutureDescriptor>(),
                ..demo_descriptor(&name, &version, PLUGIN_ABI_MAJOR, PLUGIN_ABI_MINOR + 1)
            },
            appended: 0xdead_beef,
        };

        let parsed = unsafe {
            read_abi_struct(
                &future as *const FutureDescriptor as *const PluginDescriptor,
                "demo.so",
            )
        }
        .unwrap();
        assert_eq!(parsed.abi_minor, PLUGIN_ABI_MINOR + 1);
        assert_eq!(parsed.size, std::mem::size_of::<FutureDescriptor>());
    }

    #[test]
    fn converts_plugin_address_roundtrip() {
        let addr = crate::session::SocksAddr::Domain("example.com".to_string(), 443);
        let (storage, plugin_addr) = socks_addr_to_plugin_address(&addr);
        let plugin_addr = PluginAddress {
            data: storage.as_ptr(),
            ..plugin_addr
        };

        let decoded = plugin_address_to_socks_addr(&plugin_addr).unwrap();
        assert_eq!(decoded, addr);
    }

    /// A name with no directory part is not a path to the dynamic loader: it is
    /// a lookup along `LD_LIBRARY_PATH` or the DLL search order. Loading
    /// whatever that finds is not a decision a config should delegate to the
    /// environment.
    #[test]
    fn refuses_a_bare_plugin_library_name() {
        let err = resolve_plugin_path(OsStr::new("libplugin.so")).unwrap_err();
        assert!(err.to_string().contains("bare library name"), "{}", err);

        // A path with a directory part is resolved instead of refused, so this
        // one fails for the ordinary reason.
        let err = resolve_plugin_path(OsStr::new("./libplugin.so")).unwrap_err();
        assert!(err.to_string().contains("failed to resolve"), "{}", err);

        let existing = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let resolved = resolve_plugin_path(existing.as_os_str()).unwrap();
        assert!(resolved.is_absolute(), "{}", resolved.display());
    }

    /// An engine can hand back a source address longer than the wire format has
    /// room for. `SocksAddr::write_buf` writes the length as one byte and would
    /// truncate it without complaint, desynchronising whatever parses the
    /// result -- the SOCKS5 UDP reply header a decoded source ends up in, for
    /// one -- so the conversion refuses it instead.
    #[test]
    fn rejects_a_plugin_address_domain_the_wire_format_cannot_carry() {
        let too_long = "a".repeat(256);
        let address = PluginAddress {
            kind: ADDRESS_KIND_DOMAIN,
            port: 443,
            data: too_long.as_ptr(),
            data_len: too_long.len(),
        };
        let err = plugin_address_to_socks_addr(&address).unwrap_err();
        assert!(err.to_string().contains("domain too long"), "{}", err);

        let longest = "a".repeat(255);
        let address = PluginAddress {
            data: longest.as_ptr(),
            data_len: longest.len(),
            ..address
        };
        assert_eq!(
            plugin_address_to_socks_addr(&address).unwrap(),
            crate::session::SocksAddr::Domain(longest, 443)
        );
    }

    /// The host caps the decoded bytes it holds, but an engine that keeps
    /// decoding buffers them where the host can neither see nor bound them. So
    /// once the reader has stopped taking what is already decoded, the write
    /// path stops feeding the engine and reports it rather than feeding a
    /// backlog it cannot measure.
    #[test]
    fn write_reports_decoded_output_the_reader_never_takes() {
        block_on(async move {
            let (near, _far) = tokio::io::duplex(4096);
            let engine = MockEngine {
                always_stall: true,
                ..Default::default()
            };
            let (mut stream, instance, _host_ctx) = engine.into_stream(Box::new(near) as AnyStream);
            stream
                .read_decoded
                .extend_from_slice(&vec![0u8; MAX_BUFFERED_APP_OUTPUT]);

            let err = stream.write_all(b"hello").await.unwrap_err();
            assert!(
                err.to_string().contains("the reader has not taken"),
                "{}",
                err
            );

            drop(stream);
            unsafe { drop(Box::from_raw(instance)) };
        });
    }

    /// Control characters in text an engine supplies are escaped, so a plugin
    /// cannot put a line of its own invention into the host's log.
    #[test]
    fn escapes_control_characters_in_plugin_text() {
        assert_eq!(sanitize_plugin_text("plain message"), "plain message");
        assert_eq!(
            sanitize_plugin_text("first\nERROR forged second"),
            "first\\nERROR forged second"
        );
    }

    /// The ABI says an engine must not use `host_ctx` once `destroy_instance`
    /// has returned. One that does -- easy enough for a plugin with threads of
    /// its own -- would reach a freed context if the host handed out a pointer.
    /// It hands out an id, so the call finds nothing and is dropped.
    #[test]
    fn a_callback_from_a_destroyed_instance_is_dropped() {
        let handle = PluginInstanceHandle::register(PluginInstanceContext {
            span: tracing::Span::none(),
            plugin: "mock".to_string(),
            read_waker: futures::task::AtomicWaker::new(),
            write_waker: futures::task::AtomicWaker::new(),
        });
        let host_ctx = handle.host_ctx();
        assert!(plugin_instance_context(host_ctx).is_some());

        drop(handle);
        assert!(plugin_instance_context(host_ctx).is_none());

        // Ids are never reused, so this stays a no-op however many instances
        // are registered after it.
        let later = PluginInstanceHandle::register(PluginInstanceContext {
            span: tracing::Span::none(),
            plugin: "mock".to_string(),
            read_waker: futures::task::AtomicWaker::new(),
            write_waker: futures::task::AtomicWaker::new(),
        });
        assert_ne!(later.host_ctx(), host_ctx);
        unsafe { host_wake_callback(host_ctx) };
        unsafe {
            host_log_callback(
                host_ctx,
                LOG_LEVEL_INFO,
                std::ptr::null(),
                b"gone".as_ptr(),
                4,
            )
        };
    }

    /// A target longer than the cap, cut inside a multi-byte character.
    ///
    /// Truncating that by slicing a `str` at a byte index panics, and a panic
    /// in a callback the plugin invoked unwinds into the plugin's frames,
    /// which aborts the process. The whole of this test is that it returns.
    #[test]
    fn a_long_multibyte_log_target_is_truncated_rather_than_fatal() {
        let handle = PluginInstanceHandle::register(PluginInstanceContext {
            span: tracing::Span::none(),
            plugin: "mock".to_string(),
            read_waker: futures::task::AtomicWaker::new(),
            write_waker: futures::task::AtomicWaker::new(),
        });

        let mut target = "a".repeat(MAX_PLUGIN_LOG_TARGET_LEN - 1).into_bytes();
        target.extend_from_slice("\u{4e2d}\u{4e2d}".as_bytes());
        target.push(0);
        unsafe {
            host_log_callback(
                handle.host_ctx(),
                LOG_LEVEL_INFO,
                target.as_ptr() as *const c_char,
                b"still logged".as_ptr(),
                12,
            )
        };

        // And one with no terminator at all, which is the other half of what
        // the cap is for.
        let unterminated = vec![b'x'; 4096];
        unsafe {
            host_log_callback(
                handle.host_ctx(),
                LOG_LEVEL_INFO,
                unterminated.as_ptr() as *const c_char,
                b"still logged".as_ptr(),
                12,
            )
        };
    }

    #[test]
    fn a_plugin_string_is_read_no_further_than_its_cap() {
        let terminated = b"leaf.plugin.example\0and whatever follows it";
        assert_eq!(
            unsafe { read_plugin_cstr(terminated.as_ptr() as *const c_char, 64) },
            "leaf.plugin.example"
        );

        // No NUL within the cap: the scan stops at the cap rather than running
        // on into memory the plugin never promised anything about.
        let unterminated = vec![b'x'; 512];
        assert_eq!(
            unsafe { read_plugin_cstr(unterminated.as_ptr() as *const c_char, 16) }.len(),
            16
        );

        // A character straddling the cut costs a character, not a panic.
        let mut straddling = "a".repeat(15).into_bytes();
        straddling.extend_from_slice("\u{4e2d}".as_bytes());
        straddling.push(0);
        assert_eq!(
            unsafe { read_plugin_cstr(straddling.as_ptr() as *const c_char, 16) },
            format!("{}\u{fffd}", "a".repeat(15))
        );
    }

    /// A panic in a callback would unwind into the plugin, which aborts. The
    /// barrier has to swallow it and let the plugin have its call back.
    #[test]
    fn a_panicking_callback_body_does_not_escape_the_boundary() {
        // The default hook would print this one, and it is expected.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        guard_host_callback(|| panic!("from inside a host callback"));
        std::panic::set_hook(previous);
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("leaf-plugin-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The digest is the only check here that still means something against
    /// someone who can write the file, so it has to be exact.
    #[test]
    fn a_pinned_plugin_must_match_its_digest() {
        let dir = scratch_dir("digest");
        let file = dir.join("plugin.so");
        std::fs::write(&file, b"not really a library").unwrap();
        let digest = hex::encode(Sha256::digest(b"not really a library"));

        verify_plugin_digest(&file, &digest).unwrap();
        // Case and surrounding space are the operator's, not the file's.
        verify_plugin_digest(&file, &format!("  {}  ", digest.to_uppercase())).unwrap();

        let err = verify_plugin_digest(&file, &"0".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match its sha256 pin"), "{err}");

        // A pin that is not a digest at all is a configuration error, not
        // something to shrug at and load anyway.
        assert!(verify_plugin_digest(&file, "not hex at all").is_err());
        assert!(verify_plugin_digest(&file, "abcd").is_err());

        std::fs::write(&file, b"something else entirely").unwrap();
        assert!(verify_plugin_digest(&file, &digest).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Loading a library runs whatever its last writer put there. If that
    /// writer can be anyone, the config does not get to say it is fine.
    #[cfg(unix)]
    #[test]
    fn a_plugin_anyone_can_rewrite_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir("permissions");
        std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o755)).unwrap();
        let file = dir.join("plugin.so");
        std::fs::write(&file, b"library").unwrap();

        std::fs::set_permissions(&file, PermissionsExt::from_mode(0o644)).unwrap();
        assert!(check_plugin_file_permissions(&file).unwrap().is_empty());

        // A group is a named set of people, so this is worth saying and not
        // worth refusing -- and it has to reach the caller to be said at all.
        std::fs::set_permissions(&file, PermissionsExt::from_mode(0o664)).unwrap();
        let warnings = check_plugin_file_permissions(&file).unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("group-writable"), "{warnings:?}");

        std::fs::set_permissions(&file, PermissionsExt::from_mode(0o666)).unwrap();
        let err = check_plugin_file_permissions(&file)
            .unwrap_err()
            .to_string();
        assert!(err.contains("world-writable"), "{err}");

        // The file's own mode is not the whole story: a directory anyone can
        // write is a directory anyone can swap the file in.
        std::fs::set_permissions(&file, PermissionsExt::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o777)).unwrap();
        let err = check_plugin_file_permissions(&file)
            .unwrap_err()
            .to_string();
        assert!(err.contains("world-writable directory"), "{err}");

        // Unless the sticky bit is there to stop them, as it is on /tmp --
        // which is still worth a word, because it is the bit and not the
        // directory's own mode that is holding.
        std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o1777)).unwrap();
        let warnings = check_plugin_file_permissions(&file).unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("world-writable directory"),
            "{warnings:?}"
        );

        std::fs::set_permissions(&dir, PermissionsExt::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An engine with more to send than one poll should move must not keep the
    /// executor thread until it runs out. The write goes through either way;
    /// what this asserts is that it took several polls to get there.
    #[test]
    fn a_flood_of_engine_output_yields_between_polls() {
        block_on(async move {
            // Deep enough to swallow everything the engine has without a
            // reader, so the only thing that can pause the flush is the budget.
            let (near, _far) = tokio::io::duplex(8 * 1024 * 1024);
            let engine = MockEngine {
                net_out: vec![0x5au8; 3 * MAX_NET_FLUSH_PER_POLL],
                ..Default::default()
            };
            let (mut stream, instance, _host_ctx) = engine.into_stream(Box::new(near) as AnyStream);

            let mut polls = 0usize;
            let written = std::future::poll_fn(|cx| {
                polls += 1;
                Pin::new(&mut stream).poll_write(cx, b"payload")
            })
            .await
            .unwrap();

            assert_eq!(written, b"payload".len());
            assert!(
                polls >= 3,
                "three megabytes went out in {polls} poll(s), so the flush never yielded"
            );
            drop(stream);
            unsafe { drop(Box::from_raw(instance)) };
        });
    }

    #[test]
    fn datagram_encode_hint_uses_socksaddr_wire_size() {
        let ipv4 = crate::session::SocksAddr::try_from(("1.2.3.4", 53)).unwrap();
        let domain = crate::session::SocksAddr::Domain("example.com".to_string(), 443);

        assert_eq!(datagram_encode_input_hint_len(5, &ipv4), 12);
        assert_eq!(datagram_encode_input_hint_len(5, &domain), 20);
    }

    /// Inspection is worth having only if it refuses what loading refuses, and
    /// refuses it before opening anything. These are the checks that run ahead
    /// of the library, which is why they can be asserted without one.
    #[test]
    fn inspection_refuses_what_loading_would_refuse_before_opening_it() {
        let dir = scratch_dir("inspect");
        let file = dir.join("plugin.so");
        std::fs::write(&file, b"not really a library").unwrap();
        let digest = hex::encode(Sha256::digest(b"not really a library"));

        // A bare name is refused by both, and for the same reason: neither
        // gets to hand the library search path a decision.
        let err = unsafe { inspect_plugin(OsStr::new("plugin.so"), None) }
            .unwrap_err()
            .to_string();
        assert!(err.contains("bare library name"), "{err}");

        let err = unsafe { inspect_plugin(OsStr::new("./no/such/plugin.so"), None) }
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to resolve plugin path"), "{err}");

        // A pin that does not match stops the run here, with the library
        // unopened -- the whole point of pinning being that the file is not
        // trusted until it has matched.
        let err = unsafe { inspect_plugin(file.as_os_str(), Some(&"0".repeat(64))) }
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match its sha256 pin"), "{err}");

        // A pin that does match gets past the digest and fails at the
        // descriptor, which is as far as a file of this kind can get.
        let err = unsafe { inspect_plugin(file.as_os_str(), Some(&digest)) }
            .unwrap_err()
            .to_string();
        assert!(!err.contains("sha256"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The report is read by a person deciding whether a config is right, so
    /// what it says about the endpoint has to be the rule the loader keeps.
    #[test]
    fn a_report_states_the_endpoint_rule_the_loader_enforces() {
        let report = PluginReport {
            path: PathBuf::from("/plugins/tls.so"),
            sha256: "0".repeat(64),
            name: "tls".to_string(),
            version: "0.1.0".to_string(),
            abi_major: PLUGIN_ABI_MAJOR,
            abi_minor: PLUGIN_ABI_MINOR,
            embeds_runtime: false,
            warnings: vec!["group-writable".to_string()],
            stream: Some(StreamEngineReport {
                connect_type: "next",
                needs_endpoint: false,
            }),
            datagram: None,
        };
        let rendered = report.to_string();
        assert!(rendered.contains("connect_type=next"), "{rendered}");
        assert!(rendered.contains("must not set host and port"), "{rendered}");
        assert!(rendered.contains("datagram:  none"), "{rendered}");
        assert!(rendered.contains("warning:   group-writable"), "{rendered}");
        // A plugin with no runtime says nothing about one: the line exists to
        // explain a library that will never be unmapped.
        assert!(!rendered.contains("runtime:"), "{rendered}");

        let proxy = PluginReport {
            stream: Some(StreamEngineReport {
                connect_type: "proxy-tcp",
                needs_endpoint: true,
            }),
            datagram: Some(DatagramEngineReport {
                transport_type: "unreliable",
            }),
            embeds_runtime: true,
            ..report
        };
        let rendered = proxy.to_string();
        assert!(rendered.contains("must set host and port"), "{rendered}");
        assert!(rendered.contains("transport_type=unreliable"), "{rendered}");
        assert!(rendered.contains("runtime:   embedded"), "{rendered}");
    }
}
