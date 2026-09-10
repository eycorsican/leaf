//! The C ABI shared between the leaf plugin host and out-of-tree plugins.
//!
//! This crate is intentionally free of dependencies and of `std`, so that a
//! plugin can depend on the ABI without linking a second copy of the proxy
//! engine into the process. The canonical C declaration of everything defined
//! here lives in `include/leaf_plugin_abi.h`; the two are kept in sync by
//! `tests/header_parity.rs`.
//!
//! # Object lifetimes
//!
//! | Object | Valid for |
//! | --- | --- |
//! | [`PluginDescriptor`], the vtables it points to, and its `name` / `version` strings | from library load until unload; static and immutable |
//! | [`EngineCreateArgs`] and its `plugin_args`, `destination` and the [`HostCallbacks`] **struct** | the `create_instance` call only -- a plugin must copy anything it needs |
//! | `host_ctx` and the `log` / `wake` **function pointers** copied out of [`HostCallbacks`] | from `create_instance` being entered until `destroy_instance` returns; `host_ctx` is opaque and must never be dereferenced |
//! | input buffers passed to `push`, `encode_packet`, `decode_packet` | that call only |
//! | output buffers passed to `pull`, `encode_packet`, `decode_packet`, `get_last_error` | that call only; owned by the host |
//! | the [`PluginAddress`] `decode_packet` fills in | that call only; the host supplies `data`, the engine writes into it and sets `data_len`, and must not replace the pointer |
//!
//! Because the callbacks stay valid until `destroy_instance` **returns**, a
//! plugin that calls them from its own threads has to make sure none is in
//! flight, and none can start, by the time it returns from `destroy_instance`.
//!
//! # Threading
//!
//! * The host never makes two calls on the same instance at the same time, but
//!   successive calls may come from different threads, so an instance must not
//!   be tied to one.
//! * `destroy_instance` never overlaps another call on that instance.
//! * Instances are independent of each other, and
//!   `leaf_plugin_get_descriptor` must be pure and safe to call concurrently.
//! * `log` and `wake` are re-entrant and callable from any thread, including
//!   from inside another engine call. The host never calls back into the
//!   plugin from either.
//!
//! # Blocking
//!
//! Engine calls run on the host's async executor threads, so they must return
//! promptly: no sleeping, no I/O, no waiting on another thread. Work that
//! cannot be finished immediately is what
//! [`STREAM_ENGINE_STATE_BLOCKED`] and the `wake` callback are for.
//!
//! `destroy_instance` is the one exception; it may block briefly to join the
//! plugin's own threads, as the lifetime rules above require.
//!
//! A plugin must not panic, abort or unwind across the boundary. Failures are
//! reported as a status code, with detail available from `get_last_error`. The
//! host runs its own callbacks behind a panic barrier, but that only covers the
//! host's frames: an unwind out of an engine call still has nowhere to go.
//!
//! # What the host validates
//!
//! The host defends against a plugin that is wrong, not one that is hostile: a
//! plugin runs in the host process with the host's privileges, and nothing here
//! changes that. What it does reject, rather than trust, is a `consumed` larger
//! than the input, a `produced` larger than the output buffer, an address
//! longer than the buffer it was given, a swapped-out address pointer, and an
//! address that could not be put back on the wire. Every size an engine
//! reports -- including the length `get_last_error` asks for and the length
//! passed to `log` -- is clamped before the host acts on it, and text an engine
//! supplies has its control characters escaped before it reaches a log.
//!
//! Nor does the host scan a NUL-terminated string an engine hands it any
//! further than its own cap: a `log` target that never terminates costs a
//! truncated target, and the descriptor's `name` and `version` must terminate
//! within 256 bytes or the plugin is refused. Truncation happens on the bytes,
//! not on characters, so a multi-byte character straddling the cut is replaced
//! rather than fatal.
//!
//! `host_ctx` is a handle the host looks up, not a pointer into its memory, so
//! an engine that calls `log` or `wake` after `destroy_instance` has returned
//! -- a contract violation, but a plausible one for a plugin with threads of
//! its own -- loses the call instead of corrupting the host. Do not rely on it:
//! the wakeup is gone either way.
//!
//! What remains on trust, because the host cannot check it: the truthfulness of
//! each struct's `size` field, that the structs are suitably aligned, that the
//! vtable entries are real functions, and that an engine writes no more than
//! the `produced` and `consumed` it goes on to report.
//!
//! Before any of that, the host has to be willing to open the file at all: a
//! bare library name is refused rather than looked up along the loader's search
//! path, as is a library anyone on the machine can rewrite, and an outbound may
//! pin the sha256 the file has to have.
//!
//! # A note on runtimes with their own threads
//!
//! A plugin that embeds a language runtime, such as a Go `c-shared` build,
//! makes a host thread that calls into it unable to exit cleanly while the
//! plugin is loaded: the runtime's thread-exit hook does not return. Long-lived
//! executor threads satisfy this in practice; short-lived ones do not.
//!
//! Such a plugin must also set [`PLUGIN_FLAG_EMBEDS_RUNTIME`], because the
//! host would otherwise unmap it. Everything the host holds a plugin library
//! for -- a handler, a live stream, a datagram session -- it can count; the
//! threads a runtime starts for itself it cannot, and they keep running code
//! in the library after the last thing the host counted has gone. Unmapping
//! then takes the code out from under them. The flag is the plugin saying that
//! it cannot be unmapped, and the host answers by keeping it mapped for the
//! life of the process.
//!
//! Two such plugins in one process is two runtimes in one process, which the
//! runtimes' own projects generally decline to guarantee -- Go's, the one this
//! repository ships plugins for, treats it as a configuration it does not
//! support rather than one it has broken. In practice each runtime keeps to
//! itself: on Windows a fault is claimed by whichever runtime's module the
//! faulting instruction is in, and on the platforms where signal handlers are
//! process-wide the same question is settled by forwarding. The host therefore
//! allows it, warns once when a process ends up holding more than one, and
//! tests it under fault rather than assuming either way.

#![no_std]

use core::ffi::{c_char, c_void};
use core::mem::{size_of, MaybeUninit};

/// The symbol every plugin must export, as a NUL-terminated name suitable for
/// `dlsym`/`GetProcAddress`.
pub const PLUGIN_DESCRIPTOR_SYMBOL: &[u8] = b"leaf_plugin_get_descriptor\0";

/// The major ABI version implemented by this crate.
///
/// A host loads a plugin only when the major versions match exactly. Every
/// breaking change bumps it.
pub const PLUGIN_ABI_MAJOR: u32 = 2;

/// The minor ABI version implemented by this crate.
///
/// Minor versions are additive within a major version and never participate in
/// the compatibility decision: a peer discovers which trailing fields actually
/// exist from the `size` field of each struct, not from this number, which is
/// informational only. Appending a field bumps it.
///
/// 1 added [`PluginDescriptor::flags`].
pub const PLUGIN_ABI_MINOR: u32 = 1;

/// [`PluginDescriptor::flags`]: this plugin embeds a language runtime and must
/// never be unmapped.
///
/// A Go `c-shared` build is the standard case. See the note on runtimes with
/// their own threads above for why the host cannot work this out for itself,
/// and what it does about it.
pub const PLUGIN_FLAG_EMBEDS_RUNTIME: u64 = 1 << 0;

/// The call succeeded. Every vtable entry that returns a status returns this or
/// one of the negative values below, with detail left for `get_last_error`.
pub const ENGINE_STATUS_OK: i32 = 0;
/// The call carried something the engine cannot accept, such as a `side` or an
/// address kind it does not implement. The host treats it as fatal.
pub const ENGINE_STATUS_INVALID_ARGUMENT: i32 = -1;
/// The output buffer was too small for what the call had to produce. The engine
/// must have consumed nothing, so that the host can retry the same input with a
/// larger buffer; it grows the buffer a bounded number of times before giving
/// up on the engine.
pub const ENGINE_STATUS_BUFFER_TOO_SMALL: i32 = -2;
/// The engine does not implement this operation at all, so retrying cannot
/// help.
pub const ENGINE_STATUS_UNSUPPORTED: i32 = -3;
/// The engine failed for a reason of its own. The host turns it into an I/O
/// error and tears the connection down.
pub const ENGINE_STATUS_PLUGIN_FAILURE: i32 = -4;

/// Levels accepted by [`PluginHostLogFn`]. They mirror the host's own levels,
/// so a message logged above the level the host is configured for is dropped.
pub const LOG_LEVEL_ERROR: u32 = 1;
/// See [`LOG_LEVEL_ERROR`].
pub const LOG_LEVEL_WARN: u32 = 2;
/// See [`LOG_LEVEL_ERROR`].
pub const LOG_LEVEL_INFO: u32 = 3;
/// See [`LOG_LEVEL_ERROR`].
pub const LOG_LEVEL_DEBUG: u32 = 4;
/// See [`LOG_LEVEL_ERROR`].
pub const LOG_LEVEL_TRACE: u32 = 5;

/// [`PluginAddress::data`] holds the four octets of an IPv4 address, in network
/// order. `port` is a plain `u16` in host order, as it is for every kind.
pub const ADDRESS_KIND_IPV4: u16 = 1;
/// [`PluginAddress::data`] holds the sixteen octets of an IPv6 address, in
/// network order.
pub const ADDRESS_KIND_IPV6: u16 = 2;
/// [`PluginAddress::data`] holds a domain name as UTF-8, without a trailing
/// NUL. The host rejects an empty one, and one longer than 255 bytes: that is
/// all the length byte in the wire formats it re-encodes the address into has
/// room for.
pub const ADDRESS_KIND_DOMAIN: u16 = 3;

/// The host is asking about, or performing, the outbound direction:
/// `encode_packet`, turning one of the application's datagrams into wire bytes.
pub const DATAGRAM_DIRECTION_ENCODE: u32 = 1;
/// The host is asking about, or performing, the inbound direction:
/// `decode_packet`, turning wire bytes back into a datagram.
pub const DATAGRAM_DIRECTION_DECODE: u32 = 2;

/// The engine's datagrams ride a byte stream, so the host puts the datagram
/// engine on top of the stream transport the chain already established and the
/// engine frames each datagram itself. One read can carry a partial frame or
/// several, which is what `decode_packet`'s `consumed` exists for.
pub const DATAGRAM_TRANSPORT_TYPE_RELIABLE: u32 = 1;
/// The engine's datagrams ride a datagram transport, one whole frame per call
/// in each direction.
///
/// Either transport type makes the outbound's `host`/`port` settings required:
/// a datagram engine always talks to a configured server.
pub const DATAGRAM_TRANSPORT_TYPE_UNRELIABLE: u32 = 2;

/// The engine speaks a proxy protocol, so the host connects a TCP socket to the
/// `host`/`port` in the outbound's settings and hands the engine that stream.
/// Both must be configured.
pub const STREAM_CONNECT_TYPE_PROXY_TCP: u32 = 1;
/// The host connects straight to the session's destination and hands the engine
/// that stream. The outbound's settings must not carry a `host`/`port`.
pub const STREAM_CONNECT_TYPE_DIRECT: u32 = 2;
/// The engine is a transport layered on whatever the previous outbound in the
/// chain produced, as TLS is; the host hands it that stream. The outbound's
/// settings must not carry a `host`/`port`.
pub const STREAM_CONNECT_TYPE_NEXT: u32 = 3;

/// The application side of a stream engine: plaintext going to and coming from
/// whatever the proxy is carrying.
pub const STREAM_SIDE_APP: u32 = 1;
/// The network side of a stream engine: encoded bytes going to and coming from
/// the socket.
pub const STREAM_SIDE_NET: u32 = 2;

/// The engine can take more application input; the host may `push` with
/// [`STREAM_SIDE_APP`]. Advisory -- `push` reporting a short `consumed` is the
/// authoritative signal.
pub const STREAM_ENGINE_STATE_WANT_APP_INPUT: u32 = 1 << 0;
/// The engine is waiting on bytes from the peer; the host reads the socket and
/// pushes with [`STREAM_SIDE_NET`]. This, not
/// [`STREAM_ENGINE_STATE_BLOCKED`], is what an engine reports while it waits
/// for the other end.
pub const STREAM_ENGINE_STATE_WANT_NET_INPUT: u32 = 1 << 1;
/// The engine has decoded bytes for the application; the host `pull`s with
/// [`STREAM_SIDE_APP`]. A `pull` that then produces nothing is believed over
/// the flag, so an engine that leaves it set with nothing to give only costs a
/// wasted call.
pub const STREAM_ENGINE_STATE_HAS_APP_OUTPUT: u32 = 1 << 2;
/// The engine has bytes for the socket; the host `pull`s with
/// [`STREAM_SIDE_NET`] and writes them. Set it during a handshake too: the host
/// keeps this side moving even while the application is only reading.
pub const STREAM_ENGINE_STATE_HAS_NET_OUTPUT: u32 = 1 << 3;
/// The engine has not finished its handshake. Informational; the host drives it
/// from the other flags either way.
pub const STREAM_ENGINE_STATE_HANDSHAKING: u32 = 1 << 4;
/// The handshake is done and the engine is carrying application data.
/// Informational.
pub const STREAM_ENGINE_STATE_ESTABLISHED: u32 = 1 << 5;
/// The peer closed its side. Once the engine has no application output left,
/// the host reports end of stream to the application.
pub const STREAM_ENGINE_STATE_PEER_CLOSED: u32 = 1 << 6;
/// The engine is unusable. The host fails the connection as soon as it sees
/// this, whatever the call that reported it returned.
pub const STREAM_ENGINE_STATE_FATAL: u32 = 1 << 7;
/// The engine cannot make progress from anything the host can hand it right
/// now, and will call [`PluginHostWakeFn`] once that changes.
///
/// This is what an engine reports when it is waiting on work of its own rather
/// than on the peer: more input would not help, so the host stops polling and
/// waits to be woken. An engine that is merely waiting for the peer reports
/// [`STREAM_ENGINE_STATE_WANT_NET_INPUT`] instead.
pub const STREAM_ENGINE_STATE_BLOCKED: u32 = 1 << 8;

/// Passed to `close`: the application has finished writing, so the engine
/// should emit whatever its protocol uses to say so.
pub const STREAM_ENGINE_CLOSE_APP: u32 = 1 << 0;
/// Passed to `close`: the socket reached end of file, so nothing more will
/// arrive from the peer.
pub const STREAM_ENGINE_CLOSE_NET: u32 = 1 << 1;

/// `leaf_plugin_get_descriptor`.
pub type PluginDescriptorFn = unsafe extern "C" fn() -> *const PluginDescriptor;

/// The `get_last_error` entry shared by both engine vtables.
///
/// Signature: `(instance, code_out, output, output_cap, written_out)`. The
/// engine writes its own status code through `code_out` and a UTF-8 message,
/// without a trailing NUL, into `output`.
///
/// The host asks twice: once with a null `output` and `output_cap` of zero, to
/// learn the length from `written_out`, and again with a buffer that size. So
/// `written_out` is the length the message needs when the buffer is too small,
/// and the length actually written otherwise, and the message must survive
/// being read twice.
///
/// `instance` is null when `create_instance` returned null and there is no
/// instance to ask, so an engine that wants to report why a creation failed has
/// to keep that message somewhere reachable without one, such as a thread-local.
/// A non-zero return means the engine has nothing to say, and the host falls
/// back to the status code of the call that failed.
pub type PluginLastErrorFn =
    unsafe extern "C" fn(*mut c_void, *mut i32, *mut u8, usize, *mut usize) -> i32;

/// The host-provided logging callback.
pub type PluginHostLogFn = unsafe extern "C" fn(*mut c_void, u32, *const c_char, *const u8, usize);

/// The host-provided readiness callback.
///
/// An engine that reports [`STREAM_ENGINE_STATE_BLOCKED`] calls this once it
/// can make progress again. It may be called from any thread and at any time
/// between `create_instance` being entered and `destroy_instance` returning,
/// including from inside another engine call. The host never calls back into
/// the plugin from it, and a call made while the host is not waiting is
/// harmless. A call made after `destroy_instance` has returned is still a
/// contract violation, but the host drops it rather than acting on it.
pub type PluginHostWakeFn = unsafe extern "C" fn(*mut c_void);

/// The root object returned by `leaf_plugin_get_descriptor`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PluginDescriptor {
    /// `sizeof` this struct as the plugin built it. See [`AbiStruct`] for what
    /// the host does with it.
    pub size: usize,
    /// [`PLUGIN_ABI_MAJOR`] the plugin was built against. The host loads the
    /// plugin only if it matches its own exactly.
    pub abi_major: u32,
    /// [`PLUGIN_ABI_MINOR`] the plugin was built against. Informational.
    pub abi_minor: u32,
    /// The plugin's name, for logs and diagnostics. NUL-terminated, static.
    pub name: *const c_char,
    /// The plugin's own version, for logs and diagnostics. NUL-terminated,
    /// static.
    pub version: *const c_char,
    /// The stream vtable, or null if the plugin has no stream engine -- a
    /// UDP-only protocol has nothing to put here.
    pub stream: *const StreamEnginePlugin,
    /// The datagram vtable, or null if the plugin has no datagram engine.
    ///
    /// A plugin that exports neither is rejected. One that exports both is
    /// registered for both, and the outbound then carries TCP through the
    /// stream engine and UDP through this one; one that exports a single engine
    /// makes an outbound that only handles that kind of traffic.
    pub datagram: *const DatagramEnginePlugin,
    /// Properties of the plugin as a library, rather than of either engine.
    ///
    /// Currently only [`PLUGIN_FLAG_EMBEDS_RUNTIME`]. A plugin built against an
    /// older minor version does not provide this field at all and it reads back
    /// as zero, which is what a plugin with nothing to declare would have
    /// written anyway. The host ignores bits it does not know, so a plugin may
    /// set a flag from a later minor version without being refused by an older
    /// host -- it simply will not be honoured, which is why a flag may only
    /// ever ask for treatment that is safe to omit for a plugin that never
    /// asked.
    pub flags: u64,
}

// SAFETY: Plugin descriptors are exported as process-lifetime immutable static
// data. The raw pointers are required for C ABI compatibility and are only
// expected to point to immutable NUL-terminated strings and static vtables.
unsafe impl Sync for PluginDescriptor {}

/// Callbacks the host offers to an engine instance.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HostCallbacks {
    /// `sizeof` this struct as the host built it.
    pub size: usize,
    /// Writes a message into the host's log. May be `None`, in which case the
    /// plugin has nowhere to log.
    pub log: Option<PluginHostLogFn>,
    /// May be `None`, in which case an engine must not report
    /// [`STREAM_ENGINE_STATE_BLOCKED`]: there would be no way to un-block it.
    pub wake: Option<PluginHostWakeFn>,
    /// Passed back as the first argument of `log` and `wake`.
    ///
    /// Entirely opaque: it is a handle the host resolves, not necessarily a
    /// pointer to anything, so a plugin must pass it back unchanged and must
    /// never dereference it. Valid for as long as those function pointers are.
    pub host_ctx: *mut c_void,
}

/// A network address passed across the boundary.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PluginAddress {
    /// One of the `ADDRESS_KIND_*` values, which says how to read `data`.
    pub kind: u16,
    /// The port, in host byte order.
    pub port: u16,
    /// The address bytes, whose meaning depends on `kind`.
    pub data: *const u8,
    /// How many bytes `data` holds.
    pub data_len: usize,
}

/// Arguments passed to both `create_instance` entries.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EngineCreateArgs {
    /// `sizeof` this struct as the host built it.
    pub size: usize,
    /// The outbound's `args` setting, verbatim and NUL-terminated. Its shape is
    /// the plugin's own business -- the host never looks inside.
    pub plugin_args: *const c_char,
    /// Where the session is ultimately headed, which is what a protocol engine
    /// encodes into its header. Not the server the host connected to.
    pub destination: *const PluginAddress,
    /// The callbacks this instance may use. Never null; the struct itself is
    /// borrowed only for this call.
    pub host_callbacks: *const HostCallbacks,
    /// The host's own ABI version, so a plugin built against a newer minor
    /// version can tell what the host will actually understand.
    pub host_abi_major: u32,
    pub host_abi_minor: u32,
}

/// The stream engine vtable.
///
/// An instance is a byte-stream codec with two sides, [`STREAM_SIDE_APP`] and
/// [`STREAM_SIDE_NET`]. The host owns all the I/O and drives the instance in a
/// loop: read `poll_state`, `push` what that asks for, `pull` what it offers,
/// and repeat. The engine never touches a socket and never blocks.
///
/// Every entry here is required: the host refuses to load a plugin whose stream
/// vtable leaves one null.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StreamEnginePlugin {
    pub size: usize,
    /// One of the `STREAM_CONNECT_TYPE_*` values, saying what stream the host
    /// should hand this engine. Read once at load time, so it is a property of
    /// the plugin rather than of an instance.
    pub connect_type: u32,
    /// Creates an instance, or returns null and leaves the reason in
    /// `get_last_error`, which the host then calls with a null instance.
    pub create_instance: Option<unsafe extern "C" fn(*const EngineCreateArgs) -> *mut c_void>,
    /// Destroys an instance. Never overlaps another call on it, and must not
    /// return until no `log` or `wake` call the plugin makes can still be in
    /// flight; this is the one entry that may block, and only briefly.
    pub destroy_instance: Option<unsafe extern "C" fn(*mut c_void)>,
    /// Reports what the engine wants next, as a bitmask of the
    /// `STREAM_ENGINE_STATE_*` flags written through the out-parameter.
    ///
    /// The host calls this between every other operation, so it must be cheap
    /// and must not itself advance the protocol.
    pub poll_state: Option<unsafe extern "C" fn(*mut c_void, *mut u32) -> i32>,
    /// Hands the engine input for one side and reports how much of it was taken
    /// through `consumed`.
    ///
    /// A short or zero `consumed` is backpressure, not failure: the host keeps
    /// the rest and offers it again. `consumed` must never exceed `input_len`;
    /// the host rejects a plugin that says otherwise.
    pub push: Option<unsafe extern "C" fn(*mut c_void, u32, *const u8, usize, *mut usize) -> i32>,
    /// Takes output for one side into the host's buffer and reports how much
    /// through `produced`.
    ///
    /// `produced == 0` means nothing more is available right now, even if
    /// `poll_state` advertised output; the host believes the bytes over the
    /// flag. Filling the buffer completely invites the host to call again.
    /// `produced` must never exceed `output_cap`.
    pub pull: Option<unsafe extern "C" fn(*mut c_void, u32, *mut u8, usize, *mut usize) -> i32>,
    /// Tells the engine that one or both sides are finished, as a bitmask of
    /// the `STREAM_ENGINE_CLOSE_*` flags.
    ///
    /// The engine may still have output to hand over afterwards -- a close
    /// notify record, a final frame -- and the host still drains it.
    pub close: Option<unsafe extern "C" fn(*mut c_void, u32) -> i32>,
    pub get_last_error: Option<PluginLastErrorFn>,
    /// How big a buffer the engine would like for a `pull` on this side. The
    /// host clamps the answer to a sane range, so a wild hint costs efficiency
    /// rather than memory.
    pub suggest_output_size: Option<unsafe extern "C" fn(*mut c_void, u32) -> usize>,
    /// How many `pull` calls of that size the host should make in a row before
    /// going back to the socket. Also clamped.
    pub suggest_output_batch: Option<unsafe extern "C" fn(*mut c_void, u32) -> usize>,
}

/// The datagram engine vtable.
///
/// An instance is a packet codec: one datagram and its address in, wire bytes
/// out, and back. As with the stream vtable the host owns the transport, and
/// every entry here is required for the plugin to load.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DatagramEnginePlugin {
    pub size: usize,
    /// One of the `DATAGRAM_TRANSPORT_TYPE_*` values, saying what the host
    /// should carry these datagrams over. Read once at load time.
    pub transport_type: u32,
    /// Creates an instance, or returns null and leaves the reason in
    /// `get_last_error`, which the host then calls with a null instance.
    pub create_instance: Option<unsafe extern "C" fn(*const EngineCreateArgs) -> *mut c_void>,
    /// Destroys an instance, under the same rules as the stream vtable's entry.
    pub destroy_instance: Option<unsafe extern "C" fn(*mut c_void)>,
    /// Encodes one datagram for `target` into `output`, reporting the length
    /// through `produced`.
    ///
    /// Returning [`ENGINE_STATUS_BUFFER_TOO_SMALL`] makes the host grow the
    /// buffer and retry the same datagram, a bounded number of times, so a
    /// conservative `max_output_size` costs an extra call rather than the
    /// packet. `produced` must never exceed `output_cap`.
    pub encode_packet: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const u8,
            usize,
            *const PluginAddress,
            *mut u8,
            usize,
            *mut usize,
        ) -> i32,
    >,
    /// Decodes at most one datagram out of `input`.
    ///
    /// Reliable transports carry framed datagrams over a byte stream, so a
    /// single read can hand the engine a partial frame or several frames at
    /// once. `consumed` is how the engine reports which of those happened:
    ///
    /// * `consumed == 0 && produced == 0` -- the input holds an incomplete
    ///   frame. The host reads more bytes and calls again with the frame's
    ///   bytes still at the front of the buffer.
    /// * `consumed > 0 && produced == 0` -- a frame that carries no datagram,
    ///   such as a keepalive, was consumed. The host drops those bytes and
    ///   calls again.
    /// * `consumed > 0 && produced > 0` -- one datagram was decoded.
    ///
    /// `consumed` must never exceed `input_len`. On
    /// [`ENGINE_STATUS_BUFFER_TOO_SMALL`] the engine must consume nothing, so
    /// that the host can retry the same input with a larger output buffer.
    ///
    /// Unreliable transports get one whole frame per call and always consume
    /// all of it.
    pub decode_packet: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const u8,
            usize,
            *mut usize,
            *mut u8,
            usize,
            *mut usize,
            *mut PluginAddress,
        ) -> i32,
    >,
    /// The buffer size the engine wants for an input of `input_len` bytes in
    /// the given `DATAGRAM_DIRECTION_*` direction. Advisory and clamped by the
    /// host, which grows the buffer anyway on
    /// [`ENGINE_STATUS_BUFFER_TOO_SMALL`].
    pub max_output_size: Option<unsafe extern "C" fn(*mut c_void, usize, u32) -> usize>,
    /// The largest address the engine can write into the [`PluginAddress`]
    /// buffer the host supplies to `decode_packet`. Also clamped.
    pub max_address_size: Option<unsafe extern "C" fn(*mut c_void, u32) -> usize>,
    pub get_last_error: Option<PluginLastErrorFn>,
}

mod sealed {
    pub trait Sealed {}
}

/// A `size`-prefixed ABI struct exchanged across the boundary.
///
/// Both peers declare how many bytes of the struct they actually wrote in its
/// leading `size` field. The receiver requires at least [`Self::REQUIRED_SIZE`]
/// bytes -- the prefix frozen when this major version was published, which
/// never grows -- and treats anything beyond that as present only if `size`
/// covers it. That is what lets an old plugin run against a newer host that has
/// appended fields, and a newer plugin run against an older host that will
/// ignore the tail.
///
/// # Safety
///
/// Implementors must be `#[repr(C)]` and must have no bit pattern of all zeros
/// that is invalid, so that a short struct can be zero-extended by
/// [`read_struct_prefix`].
pub unsafe trait AbiStruct: Copy + sealed::Sealed {
    /// The prefix every conforming peer must provide. Frozen for the lifetime
    /// of [`PLUGIN_ABI_MAJOR`]: appending a field must not change it.
    const REQUIRED_SIZE: usize;
    /// Human-readable name used in diagnostics.
    const NAME: &'static str;
}

macro_rules! impl_abi_struct {
    ($t:ty, $name:literal, last = $field:ident : $field_ty:ty) => {
        impl sealed::Sealed for $t {}
        // SAFETY: `$t` is `#[repr(C)]` and is built only from integers, raw
        // pointers and `Option<extern "C" fn>`, for each of which an all-zero
        // bit pattern is a valid value (null pointer, `None`, zero).
        unsafe impl AbiStruct for $t {
            const REQUIRED_SIZE: usize = core::mem::offset_of!($t, $field) + size_of::<$field_ty>();
            const NAME: &'static str = $name;
        }
    };
}

// `datagram` and not `flags`: the required prefix is frozen for the lifetime
// of the major version, so a field appended in a minor version must never
// enlarge it. Moving this on would refuse every plugin built before that
// minor.
impl_abi_struct!(
    PluginDescriptor,
    "descriptor",
    last = datagram: *const DatagramEnginePlugin
);
impl_abi_struct!(HostCallbacks, "host callbacks", last = host_ctx: *mut c_void);
impl_abi_struct!(
    EngineCreateArgs,
    "engine create args",
    last = host_abi_minor: u32
);
impl_abi_struct!(
    StreamEnginePlugin,
    "stream engine",
    last = suggest_output_batch: Option<unsafe extern "C" fn(*mut c_void, u32) -> usize>
);
impl_abi_struct!(
    DatagramEnginePlugin,
    "datagram engine",
    last = get_last_error: Option<PluginLastErrorFn>
);

/// Copies a peer-provided ABI struct out of `ptr`, zero-extending it when the
/// peer is older and wrote fewer bytes than this build knows about, and
/// ignoring the tail when the peer is newer and wrote more.
///
/// Fields the peer did not provide read back as `None`, null or zero, so a
/// caller checks for those exactly as it would for a field a peer chose not to
/// populate.
///
/// # Safety
///
/// `ptr` must be non-null and point to at least `declared_size` readable bytes,
/// and `declared_size` must be the value the peer wrote into the struct's
/// leading `size` field. Callers must reject `declared_size <
/// T::REQUIRED_SIZE` before calling.
pub unsafe fn read_struct_prefix<T: AbiStruct>(ptr: *const T, declared_size: usize) -> T {
    debug_assert!(!ptr.is_null());
    debug_assert!(declared_size >= T::REQUIRED_SIZE);
    let readable = if declared_size < size_of::<T>() {
        declared_size
    } else {
        size_of::<T>()
    };
    let mut out = MaybeUninit::<T>::zeroed();
    core::ptr::copy_nonoverlapping(ptr.cast::<u8>(), out.as_mut_ptr().cast::<u8>(), readable);
    // SAFETY: `AbiStruct` guarantees an all-zero `T` is valid, and the bytes the
    // peer did provide have been copied over that zeroed value.
    out.assume_init()
}
