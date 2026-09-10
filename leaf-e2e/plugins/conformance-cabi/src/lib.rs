//! A plugin that misbehaves on purpose.
//!
//! The host treats plugins as untrusted for memory-safety purposes: it rejects
//! a `consumed` larger than the input it gave, a `produced` larger than the
//! buffer it owns, and it clamps the size hints an engine returns. Those rules
//! are what stand between an accidentally wrong plugin and a corrupted host, so
//! they deserve to be exercised across a real `dlopen` boundary rather than
//! against structures a test fabricated in-process.
//!
//! Two things are configurable, and they are configured differently because the
//! host learns them at different times:
//!
//! * The **descriptor** -- ABI versions, structure sizes, which entries are
//!   null -- is read once when the library is mapped, before any config is
//!   parsed. It comes from `LEAF_CONFORMANCE_DESCRIPTOR`, and every value
//!   returns a distinct `static`, so a case selects one simply by owning its
//!   process.
//! * The **engine's behaviour** is chosen per instance, so it comes from the
//!   plugin arguments in the outbound config: `fault=<name>`.
//!
//! The working engine is a plain relay: whatever the application writes goes to
//! the network unchanged and back. That makes it a usable outbound in its own
//! right, so a fault can be judged against the same traffic that succeeds
//! without one.

use std::collections::VecDeque;
use std::ffi::{c_char, c_void, CStr};
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use leaf_plugin_abi::*;

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

static NAME: &[u8] = b"leaf-conformance-plugin\0";
static VERSION: &[u8] = b"0.1.0\0";
static EMPTY: &[u8] = b"\0";
/// Not valid UTF-8, so the host has to reject it rather than lossily accept it.
static INVALID_UTF8_NAME: [u8; 4] = [b'a', 0xff, 0xfe, 0];

// ---------------------------------------------------------------------------
// Instance accounting, readable from the test process
// ---------------------------------------------------------------------------

static CREATED: AtomicU64 = AtomicU64::new(0);
static DESTROYED: AtomicU64 = AtomicU64::new(0);
static DESCRIPTOR_READS: AtomicU64 = AtomicU64::new(0);

/// Counters a test reads back by opening this same library.
///
/// Exported outside the ABI on purpose: the host needs no part of this, and
/// adding it to the ABI to make a test possible would be the wrong trade.
#[repr(C)]
pub struct ConformanceStats {
    pub instances_created: u64,
    pub instances_destroyed: u64,
    pub descriptor_reads: u64,
}

/// # Safety
///
/// `out` must point to a writable `ConformanceStats`.
#[no_mangle]
pub unsafe extern "C" fn leaf_conformance_stats(out: *mut ConformanceStats) {
    if out.is_null() {
        return;
    }
    *out = ConformanceStats {
        instances_created: CREATED.load(Ordering::SeqCst),
        instances_destroyed: DESTROYED.load(Ordering::SeqCst),
        descriptor_reads: DESCRIPTOR_READS.load(Ordering::SeqCst),
    };
}

// ---------------------------------------------------------------------------
// Faults
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    /// Claim to have taken more than it was given.
    OverreportConsumed,
    /// Claim to have written more than the buffer holds.
    OverreportProduced,
    /// Ask for buffers no host should agree to allocate.
    HugeSizeHints,
    /// Take nothing, produce nothing, want nothing: a deadlock the host has to
    /// name rather than wait on.
    Stall,
    /// Fail to create an instance, with something to say about why.
    CreateNull,
    /// Go fatal once the application has written something.
    FatalAfterWrite,
    /// Accept one byte per call, forever.
    OneByteConsumer,
    /// Never take anything from the network, so the host's buffer of undelivered
    /// input has to be bounded by something.
    RefuseNetInput,
    /// Call the host's readiness callback from a thread of the engine's own,
    /// continuously, for as long as the instance exists.
    WakeFromThread,
    /// Log through targets no host should copy blindly: one longer than any
    /// cap, cut mid-character, and one with no terminator at all.
    BadLogTarget,
    /// Fail a call and then claim the explanation is `usize::MAX` bytes long.
    HugeErrorLength,
}

impl Fault {
    fn parse(args: &str) -> Fault {
        for field in args.split(';') {
            let Some(value) = field.trim().strip_prefix("fault=") else {
                continue;
            };
            return match value.trim() {
                "overreport-consumed" => Fault::OverreportConsumed,
                "overreport-produced" => Fault::OverreportProduced,
                "huge-size-hints" => Fault::HugeSizeHints,
                "stall" => Fault::Stall,
                "create-null" => Fault::CreateNull,
                "fatal-after-write" => Fault::FatalAfterWrite,
                "one-byte-consumer" => Fault::OneByteConsumer,
                "refuse-net-input" => Fault::RefuseNetInput,
                "wake-from-thread" => Fault::WakeFromThread,
                "bad-log-target" => Fault::BadLogTarget,
                "huge-error-length" => Fault::HugeErrorLength,
                _ => Fault::None,
            };
        }
        Fault::None
    }
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// The host's readiness callback, carried to the engine's own threads.
///
/// The ABI says `wake` may be called from any thread, at any time between
/// `create_instance` being entered and `destroy_instance` returning. Sending it
/// across a thread boundary is exactly what that permits -- and what makes the
/// join in `destroy_instance` mandatory.
struct HostWaker {
    wake: PluginHostWakeFn,
    host_ctx: *mut c_void,
}

// SAFETY: the ABI declares `wake` re-entrant and callable from any thread.
unsafe impl Send for HostWaker {}

impl HostWaker {
    fn wake(&self) {
        // SAFETY: valid until `destroy_instance` returns, which is after the
        // thread holding this has been joined.
        unsafe { (self.wake)(self.host_ctx) }
    }
}

struct Engine {
    fault: Fault,
    /// Bytes waiting to go to the network.
    net_out: VecDeque<u8>,
    /// Bytes waiting to go to the application.
    app_out: VecDeque<u8>,
    app_in_closed: bool,
    net_in_closed: bool,
    app_wrote: bool,
    last_error: Option<(i32, String)>,
    /// A thread calling the host's readiness callback, and the flag that stops
    /// it. Joined in `destroy_instance`, as the ABI requires.
    waker: Option<(Arc<AtomicBool>, std::thread::JoinHandle<()>)>,
}

impl Engine {
    fn new(fault: Fault) -> Self {
        Self {
            fault,
            net_out: VecDeque::new(),
            app_out: VecDeque::new(),
            app_in_closed: false,
            net_in_closed: false,
            app_wrote: false,
            last_error: None,
            waker: None,
        }
    }

    /// Starts a thread that wakes the host until the instance goes away.
    fn start_waker(&mut self, waker: HostWaker) {
        let running = Arc::new(AtomicBool::new(true));
        let stop = Arc::clone(&running);
        let handle = std::thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                waker.wake();
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        });
        self.waker = Some((stop, handle));
    }

    /// Stops the waking thread and waits for it.
    ///
    /// `destroy_instance` may block briefly to do this, and must: the host
    /// context stays valid only until it returns.
    fn stop_waker(&mut self) {
        if let Some((stop, handle)) = self.waker.take() {
            stop.store(false, Ordering::SeqCst);
            let _ = handle.join();
        }
    }
}

/// Reads the host callbacks out of the creation arguments, honouring the size
/// prefix the way any plugin has to.
unsafe fn host_waker(args: *const EngineCreateArgs) -> Option<HostWaker> {
    if args.is_null() {
        return None;
    }
    let args = &*args;
    if args.size < <EngineCreateArgs as AbiStruct>::REQUIRED_SIZE || args.host_callbacks.is_null() {
        return None;
    }
    let declared = args.host_callbacks.cast::<usize>().read();
    if declared < <HostCallbacks as AbiStruct>::REQUIRED_SIZE {
        return None;
    }
    let callbacks = read_struct_prefix(args.host_callbacks, declared);
    callbacks.wake.map(|wake| HostWaker {
        wake,
        host_ctx: callbacks.host_ctx,
    })
}

/// A log target of 129 bytes whose 128th falls inside a multi-byte character.
///
/// A host that truncates it by slicing a `str` at that byte index panics, and
/// a panic in a callback the plugin invoked is an abort. NUL-terminated, so
/// only the length is wrong.
static STRADDLING_TARGET: [u8; 134] = {
    let mut buf = [b'a'; 134];
    // "\u{4e2d}\u{4e2d}" -- three bytes each, starting at 127, so byte 128 is
    // inside the first of them.
    buf[127] = 0xe4;
    buf[128] = 0xb8;
    buf[129] = 0xad;
    buf[130] = 0xe4;
    buf[131] = 0xb8;
    buf[132] = 0xad;
    buf[133] = 0;
    buf
};

/// A log target with no terminator anywhere in it. A host that scans for one
/// reads off the end of this object; a host that stops at its own cap does
/// not.
static UNTERMINATED_TARGET: [u8; 4096] = [b'x'; 4096];

/// The host's log callback, for the faults that abuse it.
struct HostLogger {
    log: PluginHostLogFn,
    host_ctx: *mut c_void,
}

impl HostLogger {
    unsafe fn log_with_target(&self, target: *const u8, message: &str) {
        (self.log)(
            self.host_ctx,
            LOG_LEVEL_INFO,
            target as *const c_char,
            message.as_ptr(),
            message.len(),
        );
    }
}

unsafe fn host_logger(args: *const EngineCreateArgs) -> Option<HostLogger> {
    if args.is_null() {
        return None;
    }
    let args = &*args;
    if args.size < <EngineCreateArgs as AbiStruct>::REQUIRED_SIZE || args.host_callbacks.is_null() {
        return None;
    }
    let declared = args.host_callbacks.cast::<usize>().read();
    if declared < <HostCallbacks as AbiStruct>::REQUIRED_SIZE {
        return None;
    }
    let callbacks = read_struct_prefix(args.host_callbacks, declared);
    callbacks.log.map(|log| HostLogger {
        log,
        host_ctx: callbacks.host_ctx,
    })
}

/// The message a failed `create_instance` leaves behind. Read with a null
/// instance, which is all the host has at that point.
static CREATE_FAILURE: &str = "conformance plugin refused to create an instance on purpose";

unsafe fn engine<'a>(instance: *mut c_void) -> Option<&'a mut Engine> {
    (!instance.is_null()).then(|| &mut *(instance as *mut Engine))
}

unsafe extern "C" fn create_instance(args: *const EngineCreateArgs) -> *mut c_void {
    let mut plugin_args = String::new();
    if !args.is_null() {
        let args = &*args;
        if args.size >= <EngineCreateArgs as AbiStruct>::REQUIRED_SIZE
            && !args.plugin_args.is_null()
        {
            plugin_args = CStr::from_ptr(args.plugin_args)
                .to_string_lossy()
                .into_owned();
        }
    }
    let fault = Fault::parse(&plugin_args);
    if fault == Fault::CreateNull {
        return std::ptr::null_mut();
    }
    CREATED.fetch_add(1, Ordering::SeqCst);
    let mut engine = Engine::new(fault);
    if fault == Fault::WakeFromThread {
        if let Some(waker) = host_waker(args) {
            engine.start_waker(waker);
        }
    }
    if fault == Fault::BadLogTarget {
        if let Some(logger) = host_logger(args) {
            logger.log_with_target(
                STRADDLING_TARGET.as_ptr(),
                "logged under a target cut inside a character",
            );
            logger.log_with_target(
                UNTERMINATED_TARGET.as_ptr(),
                "logged under a target with no terminator",
            );
        }
    }
    Box::into_raw(Box::new(engine)) as *mut c_void
}

unsafe extern "C" fn destroy_instance(instance: *mut c_void) {
    if instance.is_null() {
        return;
    }
    let mut engine = Box::from_raw(instance as *mut Engine);
    engine.stop_waker();
    drop(engine);
    DESTROYED.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn poll_state(instance: *mut c_void, state_flags: *mut u32) -> i32 {
    let Some(engine) = engine(instance) else {
        return ENGINE_STATUS_INVALID_ARGUMENT;
    };
    if state_flags.is_null() {
        return ENGINE_STATUS_INVALID_ARGUMENT;
    }

    if engine.fault == Fault::FatalAfterWrite && engine.app_wrote {
        *state_flags = STREAM_ENGINE_STATE_ESTABLISHED | STREAM_ENGINE_STATE_FATAL;
        engine.last_error = Some((
            ENGINE_STATUS_PLUGIN_FAILURE,
            "conformance plugin went fatal on purpose".to_string(),
        ));
        return ENGINE_STATUS_OK;
    }

    let mut flags = STREAM_ENGINE_STATE_ESTABLISHED;
    if !engine.net_out.is_empty() {
        flags |= STREAM_ENGINE_STATE_HAS_NET_OUTPUT;
    }
    if !engine.app_out.is_empty() {
        flags |= STREAM_ENGINE_STATE_HAS_APP_OUTPUT;
    }
    if engine.fault != Fault::Stall {
        if !engine.app_in_closed {
            flags |= STREAM_ENGINE_STATE_WANT_APP_INPUT;
        }
        if !engine.net_in_closed {
            flags |= STREAM_ENGINE_STATE_WANT_NET_INPUT;
        }
    }
    if engine.net_in_closed {
        flags |= STREAM_ENGINE_STATE_PEER_CLOSED;
    }
    *state_flags = flags;
    ENGINE_STATUS_OK
}

unsafe extern "C" fn push(
    instance: *mut c_void,
    side: u32,
    input: *const u8,
    input_len: usize,
    consumed: *mut usize,
) -> i32 {
    let Some(engine) = engine(instance) else {
        return ENGINE_STATUS_INVALID_ARGUMENT;
    };
    if consumed.is_null() {
        return ENGINE_STATUS_INVALID_ARGUMENT;
    }
    let input = if input_len == 0 || input.is_null() {
        &[][..]
    } else {
        std::slice::from_raw_parts(input, input_len)
    };

    if engine.fault == Fault::Stall {
        *consumed = 0;
        return ENGINE_STATUS_OK;
    }

    if engine.fault == Fault::HugeErrorLength && side == STREAM_SIDE_APP {
        *consumed = 0;
        engine.last_error = Some((
            ENGINE_STATUS_PLUGIN_FAILURE,
            "conformance plugin failed with an error length it made up".to_string(),
        ));
        return ENGINE_STATUS_PLUGIN_FAILURE;
    }

    let take = match engine.fault {
        Fault::OneByteConsumer if side == STREAM_SIDE_APP => input.len().min(1),
        _ => input.len(),
    };

    match side {
        STREAM_SIDE_APP => {
            engine.app_wrote |= take > 0;
            engine.net_out.extend(&input[..take]);
        }
        STREAM_SIDE_NET => {
            if engine.fault == Fault::RefuseNetInput {
                // Takes nothing, ever. The host has to stop reading rather than
                // buffer the peer without limit.
                *consumed = 0;
                return ENGINE_STATUS_OK;
            }
            engine.app_out.extend(&input[..take]);
        }
        _ => return ENGINE_STATUS_INVALID_ARGUMENT,
    }

    *consumed = if engine.fault == Fault::OverreportConsumed {
        // One more than we were given, which is exactly what the host must not
        // believe.
        input.len() + 1
    } else {
        take
    };
    ENGINE_STATUS_OK
}

unsafe extern "C" fn pull(
    instance: *mut c_void,
    side: u32,
    output: *mut u8,
    output_cap: usize,
    produced: *mut usize,
) -> i32 {
    let Some(engine) = engine(instance) else {
        return ENGINE_STATUS_INVALID_ARGUMENT;
    };
    if produced.is_null() {
        return ENGINE_STATUS_INVALID_ARGUMENT;
    }
    let source = match side {
        STREAM_SIDE_APP => &mut engine.app_out,
        STREAM_SIDE_NET => &mut engine.net_out,
        _ => return ENGINE_STATUS_INVALID_ARGUMENT,
    };

    let take = source.len().min(output_cap);
    if take > 0 && !output.is_null() {
        let out = std::slice::from_raw_parts_mut(output, output_cap);
        for (slot, byte) in out.iter_mut().zip(source.drain(..take)) {
            *slot = byte;
        }
    }

    *produced = if engine.fault == Fault::OverreportProduced {
        // More than the host's buffer holds.
        output_cap + 1
    } else {
        take
    };
    ENGINE_STATUS_OK
}

unsafe extern "C" fn close(instance: *mut c_void, flags: u32) -> i32 {
    let Some(engine) = engine(instance) else {
        return ENGINE_STATUS_INVALID_ARGUMENT;
    };
    if (flags & STREAM_ENGINE_CLOSE_APP) != 0 {
        engine.app_in_closed = true;
    }
    if (flags & STREAM_ENGINE_CLOSE_NET) != 0 {
        engine.net_in_closed = true;
    }
    ENGINE_STATUS_OK
}

unsafe extern "C" fn get_last_error(
    instance: *mut c_void,
    code: *mut i32,
    output: *mut u8,
    output_cap: usize,
    required: *mut usize,
) -> i32 {
    if required.is_null() {
        return ENGINE_STATUS_INVALID_ARGUMENT;
    }
    // A null instance is the `create_instance` failure path: the host has
    // nothing else to ask.
    let detail = match engine(instance) {
        Some(engine) => engine.last_error.clone(),
        None => Some((ENGINE_STATUS_PLUGIN_FAILURE, CREATE_FAILURE.to_string())),
    };
    let Some((detail_code, message)) = detail else {
        *required = 0;
        return ENGINE_STATUS_OK;
    };
    if !code.is_null() {
        *code = detail_code;
    }
    if output_cap == 0
        && engine(instance).is_some_and(|engine| engine.fault == Fault::HugeErrorLength)
    {
        // The probe call, which is where the host learns how much to allocate.
        // It has to disbelieve this rather than try to satisfy it.
        *required = usize::MAX;
        return ENGINE_STATUS_OK;
    }
    *required = message.len();
    if output.is_null() || output_cap < message.len() {
        return ENGINE_STATUS_OK;
    }
    std::slice::from_raw_parts_mut(output, output_cap)[..message.len()]
        .copy_from_slice(message.as_bytes());
    ENGINE_STATUS_OK
}

unsafe extern "C" fn suggest_output_size(instance: *mut c_void, _side: u32) -> usize {
    match engine(instance) {
        Some(engine) if engine.fault == Fault::HugeSizeHints => usize::MAX,
        _ => 4096,
    }
}

unsafe extern "C" fn suggest_output_batch(instance: *mut c_void, _side: u32) -> usize {
    match engine(instance) {
        Some(engine) if engine.fault == Fault::HugeSizeHints => usize::MAX,
        _ => 4,
    }
}

// ---------------------------------------------------------------------------
// Descriptors
// ---------------------------------------------------------------------------

const STREAM_TEMPLATE: StreamEnginePlugin = StreamEnginePlugin {
    size: size_of::<StreamEnginePlugin>(),
    // Names its own server, so the outbound config carries host and port and
    // the engine is usable on its own rather than only inside a chain.
    connect_type: STREAM_CONNECT_TYPE_PROXY_TCP,
    create_instance: Some(create_instance),
    destroy_instance: Some(destroy_instance),
    poll_state: Some(poll_state),
    push: Some(push),
    pull: Some(pull),
    close: Some(close),
    get_last_error: Some(get_last_error),
    suggest_output_size: Some(suggest_output_size),
    suggest_output_batch: Some(suggest_output_batch),
};

static STREAM_OK: StreamEnginePlugin = STREAM_TEMPLATE;
static STREAM_NULL_PULL: StreamEnginePlugin = StreamEnginePlugin {
    pull: None,
    ..STREAM_TEMPLATE
};
static STREAM_SHORT: StreamEnginePlugin = StreamEnginePlugin {
    size: <StreamEnginePlugin as AbiStruct>::REQUIRED_SIZE - 1,
    ..STREAM_TEMPLATE
};
static STREAM_BAD_CONNECT_TYPE: StreamEnginePlugin = StreamEnginePlugin {
    connect_type: 99,
    ..STREAM_TEMPLATE
};

/// A stream engine as a newer minor version might publish it: the frozen prefix
/// this major version defines, followed by fields this host has never heard of.
#[repr(C)]
struct ExtendedStreamEngine {
    base: StreamEnginePlugin,
    future_fields: [usize; 3],
}
// SAFETY: process-lifetime immutable static, like every other descriptor here.
unsafe impl Sync for ExtendedStreamEngine {}

static STREAM_EXTENDED: ExtendedStreamEngine = ExtendedStreamEngine {
    base: StreamEnginePlugin {
        size: size_of::<ExtendedStreamEngine>(),
        ..STREAM_TEMPLATE
    },
    future_fields: [usize::MAX; 3],
};

const DESCRIPTOR_TEMPLATE: PluginDescriptor = PluginDescriptor {
    size: size_of::<PluginDescriptor>(),
    abi_major: PLUGIN_ABI_MAJOR,
    abi_minor: PLUGIN_ABI_MINOR,
    name: NAME.as_ptr() as *const c_char,
    version: VERSION.as_ptr() as *const c_char,
    stream: &STREAM_OK,
    datagram: std::ptr::null(),
    flags: 0,
};

static DESCRIPTOR_OK: PluginDescriptor = DESCRIPTOR_TEMPLATE;
/// A flag from a minor version this host has never heard of. The host must
/// ignore the bit and load the plugin: that is what makes a flag additive, and
/// it is why a flag may only ever ask for treatment that is safe to omit.
static DESCRIPTOR_UNKNOWN_FLAG: PluginDescriptor = PluginDescriptor {
    abi_minor: PLUGIN_ABI_MINOR + 1,
    flags: PLUGIN_FLAG_EMBEDS_RUNTIME | (1 << 63),
    ..DESCRIPTOR_TEMPLATE
};
static DESCRIPTOR_MAJOR_LOWER: PluginDescriptor = PluginDescriptor {
    abi_major: PLUGIN_ABI_MAJOR - 1,
    ..DESCRIPTOR_TEMPLATE
};
static DESCRIPTOR_MAJOR_HIGHER: PluginDescriptor = PluginDescriptor {
    abi_major: PLUGIN_ABI_MAJOR + 1,
    ..DESCRIPTOR_TEMPLATE
};
static DESCRIPTOR_SHORT: PluginDescriptor = PluginDescriptor {
    size: <PluginDescriptor as AbiStruct>::REQUIRED_SIZE - 1,
    ..DESCRIPTOR_TEMPLATE
};
static DESCRIPTOR_NULL_NAME: PluginDescriptor = PluginDescriptor {
    name: std::ptr::null(),
    ..DESCRIPTOR_TEMPLATE
};
static DESCRIPTOR_INVALID_UTF8_NAME: PluginDescriptor = PluginDescriptor {
    name: INVALID_UTF8_NAME.as_ptr() as *const c_char,
    ..DESCRIPTOR_TEMPLATE
};
static DESCRIPTOR_EMPTY_VERSION: PluginDescriptor = PluginDescriptor {
    version: EMPTY.as_ptr() as *const c_char,
    ..DESCRIPTOR_TEMPLATE
};
static DESCRIPTOR_NO_ENGINE: PluginDescriptor = PluginDescriptor {
    stream: std::ptr::null(),
    datagram: std::ptr::null(),
    ..DESCRIPTOR_TEMPLATE
};
static DESCRIPTOR_NULL_PULL: PluginDescriptor = PluginDescriptor {
    stream: &STREAM_NULL_PULL,
    ..DESCRIPTOR_TEMPLATE
};
static DESCRIPTOR_SHORT_STREAM: PluginDescriptor = PluginDescriptor {
    stream: &STREAM_SHORT,
    ..DESCRIPTOR_TEMPLATE
};
static DESCRIPTOR_BAD_CONNECT_TYPE: PluginDescriptor = PluginDescriptor {
    stream: &STREAM_BAD_CONNECT_TYPE,
    ..DESCRIPTOR_TEMPLATE
};

/// A descriptor as a newer minor version might publish it: larger structures
/// with trailing fields this host does not know about, which it must ignore
/// rather than refuse.
#[repr(C)]
struct ExtendedDescriptor {
    base: PluginDescriptor,
    future_fields: [usize; 3],
}
// SAFETY: process-lifetime immutable static.
unsafe impl Sync for ExtendedDescriptor {}

static DESCRIPTOR_NEWER_MINOR: ExtendedDescriptor = ExtendedDescriptor {
    base: PluginDescriptor {
        size: size_of::<ExtendedDescriptor>(),
        abi_minor: PLUGIN_ABI_MINOR + 1,
        stream: &STREAM_EXTENDED.base,
        ..DESCRIPTOR_TEMPLATE
    },
    future_fields: [usize::MAX; 3],
};

/// The one symbol the host looks for.
///
/// Re-read from the environment on every call rather than cached: a case owns
/// its process, and reading here keeps every variant a plain static with no
/// initialisation order to get wrong.
#[no_mangle]
pub extern "C" fn leaf_plugin_get_descriptor() -> *const PluginDescriptor {
    DESCRIPTOR_READS.fetch_add(1, Ordering::SeqCst);
    let variant = std::env::var("LEAF_CONFORMANCE_DESCRIPTOR").unwrap_or_default();
    match variant.as_str() {
        "abi-major-lower" => &DESCRIPTOR_MAJOR_LOWER,
        "abi-major-higher" => &DESCRIPTOR_MAJOR_HIGHER,
        "newer-minor" => &DESCRIPTOR_NEWER_MINOR.base,
        "short-descriptor" => &DESCRIPTOR_SHORT,
        "short-stream-engine" => &DESCRIPTOR_SHORT_STREAM,
        "null-name" => &DESCRIPTOR_NULL_NAME,
        "invalid-utf8-name" => &DESCRIPTOR_INVALID_UTF8_NAME,
        "empty-version" => &DESCRIPTOR_EMPTY_VERSION,
        "no-engine" => &DESCRIPTOR_NO_ENGINE,
        "null-required-fn" => &DESCRIPTOR_NULL_PULL,
        "unknown-flag" => &DESCRIPTOR_UNKNOWN_FLAG,
        "bad-connect-type" => &DESCRIPTOR_BAD_CONNECT_TYPE,
        "bad-transport-type" => &DESCRIPTOR_BAD_TRANSPORT_TYPE,
        "datagram-unreliable" => &DESCRIPTOR_DATAGRAM_UNRELIABLE,
        "datagram-reliable" => &DESCRIPTOR_DATAGRAM_RELIABLE,
        "datagram-only" => &DESCRIPTOR_DATAGRAM_ONLY,
        _ => &DESCRIPTOR_OK,
    }
}

// ---------------------------------------------------------------------------
// The datagram engine
// ---------------------------------------------------------------------------
//
// Frames are deliberately trivial, because the point is the host's handling of
// them rather than the format:
//
//     'K'                                                  -- a keepalive
//     'D' kind:u8 port:u16 addr_len:u16 addr payload_len:u16 payload
//
// All integers are big-endian. `leaf_e2e::framing` writes and reads the same
// shape, so a test can play the peer -- and can split, batch or interleave
// frames to put the host's `consumed` handling through its cases.

const FRAME_DATA: u8 = b'D';
const FRAME_KEEPALIVE: u8 = b'K';
/// Head of a data frame up to and including `addr_len`.
const DATA_HEAD: usize = 1 + 1 + 2 + 2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DatagramFault {
    None,
    /// Report an address longer than the buffer the host provided.
    AddressOverrun,
    /// Hand back an address buffer of the engine's own.
    AddressPointerSwap,
    /// Ask for a bigger output buffer once, to make the host grow and retry.
    BufferTooSmallOnce,
    /// Ask for buffers no host should agree to allocate.
    HugeHints,
    /// Claim to have taken more of the input than there was.
    OverreportConsumed,
    /// Never finish a frame, so the host's reassembly buffer has to be bounded
    /// by something.
    NeverCompletes,
    /// Ask for half of what is needed, so the host has to notice and grow.
    UnderstatedHints,
    /// Decode the first datagram into more bytes than any caller's buffer
    /// holds. The host has to drop that packet and carry on, the way it does
    /// for one that failed to decode -- ending the session over it would let
    /// the server kill it with a single reply.
    OversizePayloadOnce,
}

impl DatagramFault {
    fn parse(args: &str) -> DatagramFault {
        for field in args.split(';') {
            let Some(value) = field.trim().strip_prefix("dgram-fault=") else {
                continue;
            };
            return match value.trim() {
                "address-overrun" => DatagramFault::AddressOverrun,
                "address-pointer-swap" => DatagramFault::AddressPointerSwap,
                "buffer-too-small-once" => DatagramFault::BufferTooSmallOnce,
                "huge-hints" => DatagramFault::HugeHints,
                "overreport-consumed" => DatagramFault::OverreportConsumed,
                "oversize-payload-once" => DatagramFault::OversizePayloadOnce,
                "never-completes" => DatagramFault::NeverCompletes,
                "understated-hints" => DatagramFault::UnderstatedHints,
                _ => DatagramFault::None,
            };
        }
        DatagramFault::None
    }
}

struct DatagramEngine {
    fault: DatagramFault,
    /// Cleared after the first refusal, so the retry succeeds and the host's
    /// growth path is observed working rather than looping.
    refuse_once: bool,
    /// Cleared after the first oversized datagram, so what follows it is
    /// ordinary traffic and the session is seen to survive.
    oversize_once: bool,
    last_error: Option<(i32, String)>,
}

/// An address buffer of the engine's own, for the pointer-swap fault.
static STOLEN_ADDRESS: [u8; 4] = [127, 0, 0, 1];

unsafe fn datagram<'a>(instance: *mut c_void) -> Option<&'a mut DatagramEngine> {
    (!instance.is_null()).then(|| &mut *(instance as *mut DatagramEngine))
}

unsafe extern "C" fn datagram_create_instance(args: *const EngineCreateArgs) -> *mut c_void {
    let mut plugin_args = String::new();
    if !args.is_null() {
        let args = &*args;
        if args.size >= <EngineCreateArgs as AbiStruct>::REQUIRED_SIZE
            && !args.plugin_args.is_null()
        {
            plugin_args = CStr::from_ptr(args.plugin_args)
                .to_string_lossy()
                .into_owned();
        }
    }
    let fault = DatagramFault::parse(&plugin_args);
    CREATED.fetch_add(1, Ordering::SeqCst);
    Box::into_raw(Box::new(DatagramEngine {
        fault,
        refuse_once: fault == DatagramFault::BufferTooSmallOnce,
        oversize_once: fault == DatagramFault::OversizePayloadOnce,
        last_error: None,
    })) as *mut c_void
}

unsafe extern "C" fn datagram_destroy_instance(instance: *mut c_void) {
    if instance.is_null() {
        return;
    }
    drop(Box::from_raw(instance as *mut DatagramEngine));
    DESTROYED.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn encode_packet(
    instance: *mut c_void,
    payload: *const u8,
    payload_len: usize,
    target: *const PluginAddress,
    output: *mut u8,
    output_cap: usize,
    produced: *mut usize,
) -> i32 {
    let Some(engine) = datagram(instance) else {
        return ENGINE_STATUS_INVALID_ARGUMENT;
    };
    if produced.is_null() || target.is_null() {
        return ENGINE_STATUS_INVALID_ARGUMENT;
    }
    let target = &*target;
    let addr = if target.data.is_null() || target.data_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(target.data, target.data_len)
    };
    let payload = if payload_len == 0 || payload.is_null() {
        &[][..]
    } else {
        std::slice::from_raw_parts(payload, payload_len)
    };

    let needed = DATA_HEAD + addr.len() + payload.len();
    if needed > output_cap {
        engine.last_error = Some((
            ENGINE_STATUS_BUFFER_TOO_SMALL,
            format!("encode needs {} bytes, was given {}", needed, output_cap),
        ));
        *produced = 0;
        return ENGINE_STATUS_BUFFER_TOO_SMALL;
    }

    let mut frame = Vec::with_capacity(needed);
    frame.push(FRAME_DATA);
    frame.push(target.kind as u8);
    frame.extend_from_slice(&target.port.to_be_bytes());
    frame.extend_from_slice(&(addr.len() as u16).to_be_bytes());
    frame.extend_from_slice(addr);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);

    std::slice::from_raw_parts_mut(output, output_cap)[..frame.len()].copy_from_slice(&frame);
    *produced = frame.len();
    ENGINE_STATUS_OK
}

unsafe extern "C" fn decode_packet(
    instance: *mut c_void,
    input: *const u8,
    input_len: usize,
    consumed: *mut usize,
    output: *mut u8,
    output_cap: usize,
    produced: *mut usize,
    address: *mut PluginAddress,
) -> i32 {
    let Some(engine) = datagram(instance) else {
        return ENGINE_STATUS_INVALID_ARGUMENT;
    };
    if consumed.is_null() || produced.is_null() || address.is_null() {
        return ENGINE_STATUS_INVALID_ARGUMENT;
    }
    *consumed = 0;
    *produced = 0;

    let input = if input_len == 0 || input.is_null() {
        &[][..]
    } else {
        std::slice::from_raw_parts(input, input_len)
    };
    if input.is_empty() || engine.fault == DatagramFault::NeverCompletes {
        // Nothing consumed and nothing produced is "come back with more", which
        // for this fault is never true.
        return ENGINE_STATUS_OK;
    }

    // A keepalive: bytes to drop, no datagram. The host has to take those
    // bytes off the front and ask again.
    if input[0] == FRAME_KEEPALIVE {
        *consumed = 1;
        return ENGINE_STATUS_OK;
    }
    if input[0] != FRAME_DATA {
        engine.last_error = Some((
            ENGINE_STATUS_PLUGIN_FAILURE,
            format!("unknown frame tag {:#04x}", input[0]),
        ));
        return ENGINE_STATUS_PLUGIN_FAILURE;
    }

    // Anything short of a whole frame is "come back with more".
    if input.len() < DATA_HEAD {
        return ENGINE_STATUS_OK;
    }
    let kind = input[1] as u16;
    let port = u16::from_be_bytes([input[2], input[3]]);
    let addr_len = u16::from_be_bytes([input[4], input[5]]) as usize;
    if input.len() < DATA_HEAD + addr_len + 2 {
        return ENGINE_STATUS_OK;
    }
    let addr = &input[DATA_HEAD..DATA_HEAD + addr_len];
    let payload_start = DATA_HEAD + addr_len + 2;
    let payload_len =
        u16::from_be_bytes([input[payload_start - 2], input[payload_start - 1]]) as usize;
    if input.len() < payload_start + payload_len {
        return ENGINE_STATUS_OK;
    }
    let payload = &input[payload_start..payload_start + payload_len];

    if engine.refuse_once {
        // Consumes nothing, as the ABI requires, so the host can present the
        // same input again with a larger buffer.
        engine.refuse_once = false;
        engine.last_error = Some((
            ENGINE_STATUS_BUFFER_TOO_SMALL,
            "refusing the first output buffer on purpose".to_string(),
        ));
        return ENGINE_STATUS_BUFFER_TOO_SMALL;
    }
    if payload.len() > output_cap {
        return ENGINE_STATUS_BUFFER_TOO_SMALL;
    }

    if engine.oversize_once {
        // Fills the whole buffer the host was talked into allocating, which is
        // more than the caller receiving the datagram can take.
        engine.oversize_once = false;
        std::slice::from_raw_parts_mut(output, output_cap).fill(0x5a);
        *produced = output_cap;
        *consumed = payload_start + payload_len;
        let address = &mut *address;
        address.kind = kind;
        address.port = port;
        if address.data.is_null() || address.data_len < addr.len() {
            return ENGINE_STATUS_BUFFER_TOO_SMALL;
        }
        std::slice::from_raw_parts_mut(address.data as *mut u8, address.data_len)[..addr.len()]
            .copy_from_slice(addr);
        address.data_len = addr.len();
        return ENGINE_STATUS_OK;
    }

    std::slice::from_raw_parts_mut(output, output_cap)[..payload.len()].copy_from_slice(payload);
    *produced = payload.len();
    *consumed = if engine.fault == DatagramFault::OverreportConsumed {
        input.len() + 1
    } else {
        payload_start + payload_len
    };

    let address = &mut *address;
    address.kind = kind;
    address.port = port;
    match engine.fault {
        DatagramFault::AddressPointerSwap => {
            // The host owns that buffer; handing back one of ours is exactly
            // what it must refuse.
            address.data = STOLEN_ADDRESS.as_ptr();
            address.data_len = STOLEN_ADDRESS.len();
        }
        DatagramFault::AddressOverrun => {
            if !address.data.is_null() && address.data_len >= addr.len() {
                std::slice::from_raw_parts_mut(address.data as *mut u8, address.data_len)
                    [..addr.len()]
                    .copy_from_slice(addr);
            }
            // Longer than anything the host would have allocated.
            address.data_len = DATAGRAM_ADDRESS_HINT * 4;
        }
        _ => {
            if address.data.is_null() || address.data_len < addr.len() {
                return ENGINE_STATUS_BUFFER_TOO_SMALL;
            }
            std::slice::from_raw_parts_mut(address.data as *mut u8, address.data_len)[..addr.len()]
                .copy_from_slice(addr);
            address.data_len = addr.len();
        }
    }
    ENGINE_STATUS_OK
}

/// Room for the longest address this framing carries, plus slack.
const DATAGRAM_ADDRESS_HINT: usize = 260;

unsafe extern "C" fn max_output_size(
    instance: *mut c_void,
    input_len: usize,
    _direction: u32,
) -> usize {
    let honest = input_len + DATA_HEAD + DATAGRAM_ADDRESS_HINT;
    match datagram(instance) {
        Some(engine) if engine.fault == DatagramFault::HugeHints => usize::MAX,
        // Half of what is needed, so one growth is enough and the host's retry
        // is observed working rather than exhausting its attempts.
        Some(engine) if engine.fault == DatagramFault::UnderstatedHints => honest / 2 + 1,
        // Enough rope to decode a datagram into more than any caller's buffer
        // holds. The host clamps this to its own ceiling.
        Some(engine) if engine.fault == DatagramFault::OversizePayloadOnce => usize::MAX,
        _ => honest,
    }
}

unsafe extern "C" fn max_address_size(instance: *mut c_void, _direction: u32) -> usize {
    match datagram(instance) {
        Some(engine) if engine.fault == DatagramFault::HugeHints => usize::MAX,
        _ => DATAGRAM_ADDRESS_HINT,
    }
}

unsafe extern "C" fn datagram_get_last_error(
    instance: *mut c_void,
    code: *mut i32,
    output: *mut u8,
    output_cap: usize,
    required: *mut usize,
) -> i32 {
    if required.is_null() {
        return ENGINE_STATUS_INVALID_ARGUMENT;
    }
    let detail = datagram(instance).and_then(|engine| engine.last_error.clone());
    let Some((detail_code, message)) = detail else {
        *required = 0;
        return ENGINE_STATUS_OK;
    };
    if !code.is_null() {
        *code = detail_code;
    }
    *required = message.len();
    if output.is_null() || output_cap < message.len() {
        return ENGINE_STATUS_OK;
    }
    std::slice::from_raw_parts_mut(output, output_cap)[..message.len()]
        .copy_from_slice(message.as_bytes());
    ENGINE_STATUS_OK
}

const DATAGRAM_TEMPLATE: DatagramEnginePlugin = DatagramEnginePlugin {
    size: size_of::<DatagramEnginePlugin>(),
    transport_type: DATAGRAM_TRANSPORT_TYPE_UNRELIABLE,
    create_instance: Some(datagram_create_instance),
    destroy_instance: Some(datagram_destroy_instance),
    encode_packet: Some(encode_packet),
    decode_packet: Some(decode_packet),
    max_output_size: Some(max_output_size),
    max_address_size: Some(max_address_size),
    get_last_error: Some(datagram_get_last_error),
};

static DATAGRAM_UNRELIABLE: DatagramEnginePlugin = DATAGRAM_TEMPLATE;
static DATAGRAM_RELIABLE: DatagramEnginePlugin = DatagramEnginePlugin {
    transport_type: DATAGRAM_TRANSPORT_TYPE_RELIABLE,
    ..DATAGRAM_TEMPLATE
};
static DATAGRAM_BAD_TRANSPORT_TYPE: DatagramEnginePlugin = DatagramEnginePlugin {
    transport_type: 99,
    ..DATAGRAM_TEMPLATE
};

static DESCRIPTOR_DATAGRAM_UNRELIABLE: PluginDescriptor = PluginDescriptor {
    datagram: &DATAGRAM_UNRELIABLE,
    ..DESCRIPTOR_TEMPLATE
};
static DESCRIPTOR_DATAGRAM_RELIABLE: PluginDescriptor = PluginDescriptor {
    datagram: &DATAGRAM_RELIABLE,
    ..DESCRIPTOR_TEMPLATE
};
static DESCRIPTOR_BAD_TRANSPORT_TYPE: PluginDescriptor = PluginDescriptor {
    datagram: &DATAGRAM_BAD_TRANSPORT_TYPE,
    ..DESCRIPTOR_TEMPLATE
};
/// A plugin that carries datagrams and nothing else, which the ABI allows: a
/// UDP-only protocol has no stream engine to export.
static DESCRIPTOR_DATAGRAM_ONLY: PluginDescriptor = PluginDescriptor {
    stream: core::ptr::null(),
    datagram: &DATAGRAM_UNRELIABLE,
    ..DESCRIPTOR_TEMPLATE
};
