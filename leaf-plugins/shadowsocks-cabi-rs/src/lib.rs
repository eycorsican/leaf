//! A Shadowsocks AEAD plugin for the leaf C ABI, and the reference for what a
//! protocol plugin written in Rust looks like.
//!
//! It exports both engines: a stream engine with
//! [`STREAM_CONNECT_TYPE_PROXY_TCP`], so the host connects to the configured
//! server and the engine writes the salt and the Shadowsocks header itself, and
//! an unreliable datagram engine for the UDP path.
//!
//! `args` is `cipher;password[;prefix]` -- for example
//! `chacha20-ietf-poly1305;hunter2`. The cipher is one of the AEAD ciphers leaf
//! itself supports (`chacha20-ietf-poly1305`, `aes-256-gcm`, `aes-128-gcm`),
//! keyed the classic way, by EVP_BytesToKey over the password and HKDF-SHA1 per
//! session. The optional third field is a percent-encoded prefix prepended to
//! the first request. The outbound must also set `host` and `port`, which is
//! where the host connects.
//!
//! Being a plugin rather than a built-in, everything it needs of the boundary
//! is here: it owns no I/O, never blocks, and reports backpressure by consuming
//! less than it was given.

use std::cell::RefCell;
use std::ffi::{c_char, c_void, CStr};

use anyhow::{anyhow, Result};
use bytes::{BufMut, BytesMut};
use hkdf::Hkdf;
use leaf::app::outbound::plugin::{plugin_address_to_socks_addr, socks_addr_to_plugin_address};
use leaf::common::crypto::{
    aead::{AeadCipher, AeadDecryptor, AeadEncryptor},
    Cipher, Decryptor, Encryptor, NonceSequence, SizedCipher,
};
use leaf::session::{SocksAddr, SocksAddrWireType};
use leaf_plugin_abi::{
    AbiStruct, DatagramEnginePlugin, EngineCreateArgs, HostCallbacks, PluginAddress,
    PluginDescriptor, PluginHostLogFn, StreamEnginePlugin, DATAGRAM_DIRECTION_DECODE,
    DATAGRAM_DIRECTION_ENCODE, DATAGRAM_TRANSPORT_TYPE_UNRELIABLE, ENGINE_STATUS_BUFFER_TOO_SMALL,
    ENGINE_STATUS_INVALID_ARGUMENT, ENGINE_STATUS_OK, ENGINE_STATUS_PLUGIN_FAILURE,
    LOG_LEVEL_DEBUG, LOG_LEVEL_ERROR, LOG_LEVEL_INFO, PLUGIN_ABI_MAJOR, PLUGIN_ABI_MINOR,
    STREAM_CONNECT_TYPE_PROXY_TCP, STREAM_ENGINE_CLOSE_APP, STREAM_ENGINE_CLOSE_NET,
    STREAM_ENGINE_STATE_ESTABLISHED, STREAM_ENGINE_STATE_FATAL, STREAM_ENGINE_STATE_HANDSHAKING,
    STREAM_ENGINE_STATE_HAS_APP_OUTPUT, STREAM_ENGINE_STATE_HAS_NET_OUTPUT,
    STREAM_ENGINE_STATE_PEER_CLOSED, STREAM_ENGINE_STATE_WANT_APP_INPUT,
    STREAM_ENGINE_STATE_WANT_NET_INPUT, STREAM_SIDE_APP, STREAM_SIDE_NET,
};
use md5::{Digest, Md5};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha1::Sha1;

const MAX_SHADOWSOCKS_CHUNK_SIZE: usize = 0x3fff;
const SUBKEY_INFO: &[u8] = b"ss-subkey";

const APP_OUTPUT_SIZE_HINT: usize = 16 * 1024;
const NET_OUTPUT_SIZE_HINT: usize = 18 * 1024;
const OUTPUT_BATCH_HINT: usize = 4;

static PLUGIN_NAME: &[u8] = b"leaf-shadowsocks-cabi-rs-plugin\0";
static PLUGIN_VERSION: &[u8] = b"0.1.0\0";
static STREAM_LOG_TARGET: &[u8] = b"leaf.plugin.shadowsocks.stream\0";
static DATAGRAM_LOG_TARGET: &[u8] = b"leaf.plugin.shadowsocks.datagram\0";

#[derive(Default)]
struct LastErrorState {
    code: i32,
    message: String,
}

thread_local! {
    static LAST_ERROR: RefCell<LastErrorState> = RefCell::new(LastErrorState::default());
}

#[derive(Clone, Copy, Default)]
struct HostLogger {
    callback: Option<PluginHostLogFn>,
    host_ctx: *mut c_void,
    target: *const c_char,
}

impl HostLogger {
    fn with_target(mut self, target: &'static [u8]) -> Self {
        self.target = target.as_ptr() as *const c_char;
        self
    }

    fn log(&self, level: u32, message: impl AsRef<str>) {
        let message = message.as_ref();
        if let Some(callback) = self.callback {
            unsafe {
                callback(
                    self.host_ctx,
                    level,
                    self.target,
                    message.as_ptr(),
                    message.len(),
                );
            }
        }
    }
}

#[repr(C)]
struct ShadowsocksEngineState {
    cipher: AeadCipher,
    logger: HostLogger,
    psk: Vec<u8>,
    prefix: Option<Vec<u8>>,
    enc: Option<AeadEncryptor<ShadowsocksNonceSequence>>,
    dec: Option<AeadDecryptor<ShadowsocksNonceSequence>>,
    destination: Vec<u8>,
    app_input: BytesMut,
    app_output: BytesMut,
    net_input: BytesMut,
    net_output: BytesMut,
    sent_header: bool,
    pending_payload_len: Option<usize>,
    app_closed: bool,
    net_closed: bool,
    peer_closed: bool,
    fatal: bool,
}

#[repr(C)]
struct ShadowsocksDatagramState {
    cipher: AeadCipher,
    logger: HostLogger,
    psk: Vec<u8>,
}

#[no_mangle]
pub static LEAF_PLUGIN_DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    size: std::mem::size_of::<PluginDescriptor>(),
    abi_major: PLUGIN_ABI_MAJOR,
    abi_minor: PLUGIN_ABI_MINOR,
    name: PLUGIN_NAME.as_ptr() as *const c_char,
    version: PLUGIN_VERSION.as_ptr() as *const c_char,
    stream: &LEAF_STREAM_ENGINE_PLUGIN,
    datagram: &LEAF_DATAGRAM_ENGINE_PLUGIN,
    // No runtime of its own: a Rust cdylib is code and static data, and the
    // host may unmap it when the last handler goes.
    flags: 0,
};

#[no_mangle]
pub static LEAF_STREAM_ENGINE_PLUGIN: StreamEnginePlugin = StreamEnginePlugin {
    size: std::mem::size_of::<StreamEnginePlugin>(),
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

#[no_mangle]
pub static LEAF_DATAGRAM_ENGINE_PLUGIN: DatagramEnginePlugin = DatagramEnginePlugin {
    size: std::mem::size_of::<DatagramEnginePlugin>(),
    transport_type: DATAGRAM_TRANSPORT_TYPE_UNRELIABLE,
    create_instance: Some(create_datagram_instance),
    destroy_instance: Some(destroy_datagram_instance),
    encode_packet: Some(encode_packet),
    decode_packet: Some(decode_packet),
    max_output_size: Some(datagram_max_output_size),
    max_address_size: Some(datagram_max_address_size),
    get_last_error: Some(get_last_error),
};

#[no_mangle]
pub extern "C" fn leaf_plugin_get_descriptor() -> *const PluginDescriptor {
    &LEAF_PLUGIN_DESCRIPTOR
}

/// Runs the body of an ABI entry point behind a panic barrier.
///
/// The host calls these across a C boundary, where an unwind out of an
/// `extern "C"` function aborts the process. A panic in here is a bug in this
/// plugin either way, but the ABI is explicit that it must not reach the host:
/// it should cost the connection, not the proxy that loaded the plugin.
/// `fallback` is what the host is told when one is caught.
fn guard<T>(fallback: T, body: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_) => {
            set_last_error(
                ENGINE_STATUS_PLUGIN_FAILURE,
                "panic across the ABI boundary",
            );
            fallback
        }
    }
}

unsafe extern "C" fn create_instance(args: *const EngineCreateArgs) -> *mut c_void {
    guard(std::ptr::null_mut(), || {
        let logger = resolve_stream_host_logger(args);
        match create_state(args, logger) {
            Ok(state) => {
                clear_last_error();
                Box::into_raw(Box::new(state)) as *mut c_void
            }
            Err(err) => {
                logger.log(
                    LOG_LEVEL_ERROR,
                    format!("create stream engine instance failed: {}", err),
                );
                set_last_error(
                    ENGINE_STATUS_PLUGIN_FAILURE,
                    format!("create stream engine instance failed: {}", err),
                );
                std::ptr::null_mut()
            }
        }
    })
}

unsafe extern "C" fn destroy_instance(instance: *mut c_void) {
    guard((), || {
        if !instance.is_null() {
            let _ = Box::from_raw(instance as *mut ShadowsocksEngineState);
        }
    })
}

unsafe extern "C" fn create_datagram_instance(args: *const EngineCreateArgs) -> *mut c_void {
    guard(std::ptr::null_mut(), || {
        let logger = resolve_datagram_host_logger(args);
        match create_datagram_state(args, logger) {
            Ok(state) => {
                clear_last_error();
                Box::into_raw(Box::new(state)) as *mut c_void
            }
            Err(err) => {
                logger.log(
                    LOG_LEVEL_ERROR,
                    format!("create datagram engine instance failed: {}", err),
                );
                set_last_error(
                    ENGINE_STATUS_PLUGIN_FAILURE,
                    format!("create datagram engine instance failed: {}", err),
                );
                std::ptr::null_mut()
            }
        }
    })
}

unsafe extern "C" fn destroy_datagram_instance(instance: *mut c_void) {
    guard((), || {
        if !instance.is_null() {
            let _ = Box::from_raw(instance as *mut ShadowsocksDatagramState);
        }
    })
}

unsafe extern "C" fn poll_state(instance: *mut c_void, state_flags: *mut u32) -> i32 {
    guard(ENGINE_STATUS_PLUGIN_FAILURE, || {
        match poll_state_impl(instance, state_flags) {
            Ok(()) => {
                clear_last_error();
                ENGINE_STATUS_OK
            }
            Err(code) => code,
        }
    })
}

unsafe extern "C" fn push(
    instance: *mut c_void,
    side: u32,
    input: *const u8,
    input_len: usize,
    consumed: *mut usize,
) -> i32 {
    guard(ENGINE_STATUS_PLUGIN_FAILURE, || {
        let result = match side {
            STREAM_SIDE_APP => push_app_input_impl(instance, input, input_len, consumed),
            STREAM_SIDE_NET => push_net_input_impl(instance, input, input_len, consumed),
            _ => Err(set_last_error(
                ENGINE_STATUS_INVALID_ARGUMENT,
                format!("invalid stream side for push: {}", side),
            )),
        };
        match result {
            Ok(()) => {
                clear_last_error();
                ENGINE_STATUS_OK
            }
            Err(code) => code,
        }
    })
}

unsafe extern "C" fn pull(
    instance: *mut c_void,
    side: u32,
    output: *mut u8,
    output_cap: usize,
    produced: *mut usize,
) -> i32 {
    guard(ENGINE_STATUS_PLUGIN_FAILURE, || {
        let result = match side {
            STREAM_SIDE_APP => pull_app_output_impl(instance, output, output_cap, produced),
            STREAM_SIDE_NET => pull_net_output_impl(instance, output, output_cap, produced),
            _ => Err(set_last_error(
                ENGINE_STATUS_INVALID_ARGUMENT,
                format!("invalid stream side for pull: {}", side),
            )),
        };
        match result {
            Ok(()) => {
                clear_last_error();
                ENGINE_STATUS_OK
            }
            Err(code) => code,
        }
    })
}

unsafe extern "C" fn close(instance: *mut c_void, close_flags: u32) -> i32 {
    guard(ENGINE_STATUS_PLUGIN_FAILURE, || {
        match close_impl(instance, close_flags) {
            Ok(()) => {
                clear_last_error();
                ENGINE_STATUS_OK
            }
            Err(code) => code,
        }
    })
}

unsafe extern "C" fn get_last_error(
    _instance: *mut c_void,
    code: *mut i32,
    output: *mut u8,
    output_cap: usize,
    written: *mut usize,
) -> i32 {
    guard(ENGINE_STATUS_PLUGIN_FAILURE, || {
        if code.is_null() || written.is_null() {
            return ENGINE_STATUS_INVALID_ARGUMENT;
        }
        if output_cap > 0 && output.is_null() {
            return ENGINE_STATUS_INVALID_ARGUMENT;
        }
        LAST_ERROR.with(|state| {
            let state = state.borrow();
            *code = state.code;
            *written = state.message.len();
            if output_cap > 0 {
                let to_copy = state.message.len().min(output_cap);
                std::ptr::copy_nonoverlapping(state.message.as_ptr(), output, to_copy);
                *written = to_copy;
            }
        });
        ENGINE_STATUS_OK
    })
}

unsafe extern "C" fn suggest_output_size(_instance: *mut c_void, side: u32) -> usize {
    guard(4096, || match side {
        STREAM_SIDE_APP => APP_OUTPUT_SIZE_HINT,
        STREAM_SIDE_NET => NET_OUTPUT_SIZE_HINT,
        _ => 4096,
    })
}

unsafe extern "C" fn suggest_output_batch(_instance: *mut c_void, _side: u32) -> usize {
    guard(OUTPUT_BATCH_HINT, || OUTPUT_BATCH_HINT)
}

unsafe fn poll_state_impl(
    instance: *mut c_void,
    state_flags: *mut u32,
) -> std::result::Result<(), i32> {
    if instance.is_null() || state_flags.is_null() {
        return Err(set_last_error(
            ENGINE_STATUS_INVALID_ARGUMENT,
            "poll_state received null pointer",
        ));
    }
    let state = &mut *(instance as *mut ShadowsocksEngineState);
    *state_flags = build_state_flags(state);
    Ok(())
}

unsafe fn push_app_input_impl(
    instance: *mut c_void,
    input: *const u8,
    input_len: usize,
    consumed: *mut usize,
) -> std::result::Result<(), i32> {
    if instance.is_null() || consumed.is_null() {
        return Err(set_last_error(
            ENGINE_STATUS_INVALID_ARGUMENT,
            "push_app_input received null instance or consumed pointer",
        ));
    }
    if input_len > 0 && input.is_null() {
        return Err(set_last_error(
            ENGINE_STATUS_INVALID_ARGUMENT,
            "push_app_input received null input with non-zero length",
        ));
    }

    let state = &mut *(instance as *mut ShadowsocksEngineState);
    *consumed = 0;
    if state.app_closed || state.fatal {
        return Err(set_last_error(
            ENGINE_STATUS_PLUGIN_FAILURE,
            "push_app_input called after application side was closed or entered fatal state",
        ));
    }

    if input_len > 0 {
        let input = std::slice::from_raw_parts(input, input_len);
        state.app_input.extend_from_slice(input);
    }
    encode_pending_chunks(state).map_err(|err| {
        mark_fatal(
            state,
            ENGINE_STATUS_PLUGIN_FAILURE,
            format!("encode pending chunks failed: {}", err),
        )
    })?;
    *consumed = input_len;
    Ok(())
}

unsafe fn push_net_input_impl(
    instance: *mut c_void,
    input: *const u8,
    input_len: usize,
    consumed: *mut usize,
) -> std::result::Result<(), i32> {
    if instance.is_null() || consumed.is_null() {
        return Err(set_last_error(
            ENGINE_STATUS_INVALID_ARGUMENT,
            "push_net_input received null instance or consumed pointer",
        ));
    }
    if input_len > 0 && input.is_null() {
        return Err(set_last_error(
            ENGINE_STATUS_INVALID_ARGUMENT,
            "push_net_input received null input with non-zero length",
        ));
    }

    let state = &mut *(instance as *mut ShadowsocksEngineState);
    *consumed = 0;
    if state.net_closed || state.fatal {
        return Err(set_last_error(
            ENGINE_STATUS_PLUGIN_FAILURE,
            "push_net_input called after network side was closed or entered fatal state",
        ));
    }

    if input_len > 0 {
        let input = std::slice::from_raw_parts(input, input_len);
        state.net_input.extend_from_slice(input);
    }
    *consumed = input_len;
    decode_pending_chunks(state).map_err(|err| {
        mark_fatal(
            state,
            ENGINE_STATUS_PLUGIN_FAILURE,
            format!("decode pending chunks failed: {}", err),
        )
    })?;
    Ok(())
}

unsafe fn pull_app_output_impl(
    instance: *mut c_void,
    output: *mut u8,
    output_cap: usize,
    produced: *mut usize,
) -> std::result::Result<(), i32> {
    if instance.is_null() || output.is_null() || produced.is_null() {
        return Err(set_last_error(
            ENGINE_STATUS_INVALID_ARGUMENT,
            "pull_app_output received null pointer",
        ));
    }

    let state = &mut *(instance as *mut ShadowsocksEngineState);
    *produced = 0;
    if state.fatal {
        return Err(set_last_error(
            ENGINE_STATUS_PLUGIN_FAILURE,
            "pull_app_output called after fatal error",
        ));
    }

    let to_copy = state.app_output.len().min(output_cap);
    if to_copy > 0 {
        let output = std::slice::from_raw_parts_mut(output, output_cap);
        output[..to_copy].copy_from_slice(&state.app_output.split_to(to_copy));
    }
    *produced = to_copy;
    Ok(())
}

unsafe fn pull_net_output_impl(
    instance: *mut c_void,
    output: *mut u8,
    output_cap: usize,
    produced: *mut usize,
) -> std::result::Result<(), i32> {
    if instance.is_null() || output.is_null() || produced.is_null() {
        return Err(set_last_error(
            ENGINE_STATUS_INVALID_ARGUMENT,
            "pull_net_output received null pointer",
        ));
    }

    let state = &mut *(instance as *mut ShadowsocksEngineState);
    *produced = 0;
    if state.fatal {
        return Err(set_last_error(
            ENGINE_STATUS_PLUGIN_FAILURE,
            "pull_net_output called after fatal error",
        ));
    }

    let to_copy = state.net_output.len().min(output_cap);
    if to_copy > 0 {
        let output = std::slice::from_raw_parts_mut(output, output_cap);
        output[..to_copy].copy_from_slice(&state.net_output.split_to(to_copy));
    }
    *produced = to_copy;
    Ok(())
}

unsafe fn close_impl(instance: *mut c_void, close_flags: u32) -> std::result::Result<(), i32> {
    if instance.is_null() {
        return Err(set_last_error(
            ENGINE_STATUS_INVALID_ARGUMENT,
            "close received null instance",
        ));
    }
    let state = &mut *(instance as *mut ShadowsocksEngineState);
    if (close_flags & STREAM_ENGINE_CLOSE_APP) != 0 {
        state.app_closed = true;
        state
            .logger
            .log(LOG_LEVEL_DEBUG, "marked application input as closed");
    }
    if (close_flags & STREAM_ENGINE_CLOSE_NET) != 0 {
        state.net_closed = true;
        state.peer_closed = true;
        state
            .logger
            .log(LOG_LEVEL_DEBUG, "marked network input as closed");
    }
    Ok(())
}

unsafe fn create_state(
    args: *const EngineCreateArgs,
    logger: HostLogger,
) -> Result<ShadowsocksEngineState> {
    if args.is_null() {
        return Err(anyhow!("missing create args"));
    }
    let args = &*args;
    if args.size < EngineCreateArgs::REQUIRED_SIZE {
        return Err(anyhow!(
            "engine create args too small: {} < {}",
            args.size,
            EngineCreateArgs::REQUIRED_SIZE
        ));
    }
    let plugin_args = if args.plugin_args.is_null() {
        ""
    } else {
        CStr::from_ptr(args.plugin_args).to_str()?
    };
    let destination = if args.destination.is_null() {
        return Err(anyhow!("shadowsocks stream engine requires destination"));
    } else {
        plugin_address_to_socks_addr(&*args.destination)?
    };
    let mut destination_buf = BytesMut::new();
    destination.write_buf(&mut destination_buf, SocksAddrWireType::PortLast);
    if destination_buf.is_empty() {
        return Err(anyhow!("shadowsocks stream engine requires destination"));
    }

    let (cipher_name, password, prefix) = parse_plugin_args(plugin_args)?;
    logger.log(
        LOG_LEVEL_INFO,
        format!(
            "creating Shadowsocks stream engine with cipher={}",
            cipher_name
        ),
    );
    let cipher = AeadCipher::new(&cipher_name)?;
    let key_len = cipher.key_len();
    if let Some(prefix) = prefix.as_ref() {
        if prefix.len() > key_len {
            return Err(anyhow!(
                "prefix length exceeding cipher key length: {} > {}",
                prefix.len(),
                key_len
            ));
        }
    }

    let mut state = ShadowsocksEngineState {
        logger,
        psk: kdf(&password, key_len)?,
        cipher,
        prefix,
        enc: None,
        dec: None,
        destination: destination_buf.to_vec(),
        app_input: BytesMut::new(),
        app_output: BytesMut::new(),
        net_input: BytesMut::new(),
        net_output: BytesMut::new(),
        sent_header: false,
        pending_payload_len: None,
        app_closed: false,
        net_closed: false,
        peer_closed: false,
        fatal: false,
    };
    // The salt and the request header go out as soon as the engine exists,
    // rather than waiting for something to encode. A session where the peer
    // speaks first -- any download, a mail or SSH greeting -- writes nothing
    // until it has been answered, and the server cannot answer a request it
    // was never sent.
    encode_pending_chunks(&mut state)?;
    Ok(state)
}

unsafe fn create_datagram_state(
    args: *const EngineCreateArgs,
    logger: HostLogger,
) -> Result<ShadowsocksDatagramState> {
    if args.is_null() {
        return Err(anyhow!("missing create args"));
    }
    let args = &*args;
    if args.size < EngineCreateArgs::REQUIRED_SIZE {
        return Err(anyhow!(
            "engine create args too small: {} < {}",
            args.size,
            EngineCreateArgs::REQUIRED_SIZE
        ));
    }
    let plugin_args = if args.plugin_args.is_null() {
        ""
    } else {
        CStr::from_ptr(args.plugin_args).to_str()?
    };
    let (cipher_name, password, _) = parse_plugin_args(plugin_args)?;
    logger.log(
        LOG_LEVEL_INFO,
        format!(
            "creating Shadowsocks datagram engine with cipher={}",
            cipher_name
        ),
    );
    let cipher = AeadCipher::new(&cipher_name)?;
    let key_len = cipher.key_len();
    Ok(ShadowsocksDatagramState {
        logger,
        psk: kdf(&password, key_len)?,
        cipher,
    })
}

fn parse_plugin_args(raw: &str) -> Result<(String, String, Option<Vec<u8>>)> {
    let mut parts = raw.splitn(3, ';');
    let cipher = parts
        .next()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("missing shadowsocks cipher"))?
        .to_string();
    let password = parts
        .next()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("missing shadowsocks password"))?
        .to_string();
    let prefix = parts
        .next()
        .filter(|v| !v.is_empty())
        .map(|v| {
            percent_encoding::percent_decode(v.as_bytes())
                .decode_utf8()
                .map(|s| s.into_owned().into_bytes())
                .map_err(|e| anyhow!("invalid prefix encoding: {}", e))
        })
        .transpose()?;
    Ok((cipher, password, prefix))
}

fn encode_pending_chunks(state: &mut ShadowsocksEngineState) -> Result<()> {
    // Runs once with nothing to encode while the header is still unsent, so
    // the salt and the request leave in a chunk of their own at creation time.
    // After that there is nothing to send but application data.
    while !state.app_input.is_empty() || !state.sent_header {
        if state.enc.is_none() {
            init_encryptor(state)?;
        }

        let header = if state.sent_header {
            Vec::new()
        } else {
            state.destination.clone()
        };
        if header.len() >= MAX_SHADOWSOCKS_CHUNK_SIZE {
            return Err(anyhow!("destination too large"));
        }

        let max_plain_payload = MAX_SHADOWSOCKS_CHUNK_SIZE - header.len();
        let input_to_consume = state.app_input.len().min(max_plain_payload);

        let mut plaintext = BytesMut::new();
        plaintext.extend_from_slice(&header);
        plaintext.extend_from_slice(&state.app_input.split_to(input_to_consume));

        let mut length_buf = BytesMut::new();
        length_buf.put_u16(plaintext.len() as u16);

        let enc = state
            .enc
            .as_mut()
            .ok_or_else(|| anyhow!("missing encryptor"))?;
        enc.encrypt(&mut length_buf)?;
        enc.encrypt(&mut plaintext)?;

        state.net_output.extend_from_slice(&length_buf);
        state.net_output.extend_from_slice(&plaintext);
        state.sent_header = true;
    }
    Ok(())
}

fn decode_pending_chunks(state: &mut ShadowsocksEngineState) -> Result<()> {
    if state.dec.is_none() {
        let salt_len = state.cipher.key_len();
        if state.net_input.len() < salt_len {
            return Ok(());
        }
        let salt = state.net_input.split_to(salt_len);
        init_decryptor(state, &salt)?;
    }

    let tag_len = state.cipher.tag_len();
    loop {
        if state.pending_payload_len.is_none() {
            let length_size = 2 + tag_len;
            if state.net_input.len() < length_size {
                return Ok(());
            }
            let mut length_buf = state.net_input.split_to(length_size);
            let dec = state
                .dec
                .as_mut()
                .ok_or_else(|| anyhow!("missing decryptor"))?;
            dec.decrypt(&mut length_buf)?;
            let payload_len = u16::from_be_bytes([length_buf[0], length_buf[1]]) as usize;
            // The length is authenticated, so a wrong one means the peer is
            // not following the protocol rather than that someone tampered
            // with it. Shadowsocks AEAD caps a chunk at 0x3fff; anything
            // larger would have the engine wait for a frame that this side
            // would never have sent, so refuse it here instead.
            if payload_len > MAX_SHADOWSOCKS_CHUNK_SIZE {
                return Err(anyhow!(
                    "shadowsocks chunk of {} bytes exceeds the {} byte maximum",
                    payload_len,
                    MAX_SHADOWSOCKS_CHUNK_SIZE
                ));
            }
            state.pending_payload_len = Some(payload_len);
        }

        let payload_len = state
            .pending_payload_len
            .ok_or_else(|| anyhow!("missing payload len"))?;
        let payload_size = payload_len + tag_len;
        if state.net_input.len() < payload_size {
            return Ok(());
        }

        let mut payload = state.net_input.split_to(payload_size);
        let dec = state
            .dec
            .as_mut()
            .ok_or_else(|| anyhow!("missing decryptor"))?;
        dec.decrypt(&mut payload)?;
        state.app_output.extend_from_slice(&payload[..payload_len]);
        state.pending_payload_len = None;
    }
}

fn init_encryptor(state: &mut ShadowsocksEngineState) -> Result<()> {
    let salt_len = state.cipher.key_len();
    let mut salt = vec![0u8; salt_len];
    let mut rng = StdRng::from_entropy();
    if let Some(prefix) = state.prefix.as_ref() {
        salt[..prefix.len()].copy_from_slice(prefix);
        rng.fill_bytes(&mut salt[prefix.len()..]);
    } else {
        rng.fill_bytes(&mut salt);
    }

    let key = hkdf_sha1(&state.psk, &salt, SUBKEY_INFO, state.cipher.key_len())?;
    let nonce = ShadowsocksNonceSequence::new(state.cipher.nonce_len());
    let enc = state.cipher.encryptor(&key, nonce)?;
    state.net_output.extend_from_slice(&salt);
    state.enc = Some(enc);
    state.logger.log(
        LOG_LEVEL_DEBUG,
        format!("initialized stream encryptor with {}-byte salt", salt_len),
    );
    Ok(())
}

fn init_decryptor(state: &mut ShadowsocksEngineState, salt: &[u8]) -> Result<()> {
    let key = hkdf_sha1(&state.psk, salt, SUBKEY_INFO, state.cipher.key_len())?;
    let nonce = ShadowsocksNonceSequence::new(state.cipher.nonce_len());
    let dec = state.cipher.decryptor(&key, nonce)?;
    state.dec = Some(dec);
    state.logger.log(
        LOG_LEVEL_DEBUG,
        format!("initialized stream decryptor with {}-byte salt", salt.len()),
    );
    Ok(())
}

fn build_state_flags(state: &ShadowsocksEngineState) -> u32 {
    let mut flags = 0u32;
    if state.fatal {
        flags |= STREAM_ENGINE_STATE_FATAL;
    }
    if !state.app_closed {
        flags |= STREAM_ENGINE_STATE_WANT_APP_INPUT;
    }
    if !state.net_closed {
        flags |= STREAM_ENGINE_STATE_WANT_NET_INPUT;
    }
    if !state.net_output.is_empty() {
        flags |= STREAM_ENGINE_STATE_HAS_NET_OUTPUT;
    }
    if !state.app_output.is_empty() {
        flags |= STREAM_ENGINE_STATE_HAS_APP_OUTPUT;
    }
    flags |= STREAM_ENGINE_STATE_ESTABLISHED;
    if state.peer_closed {
        flags |= STREAM_ENGINE_STATE_PEER_CLOSED;
    }
    let _ = STREAM_ENGINE_STATE_HANDSHAKING;
    flags
}

fn mark_fatal(state: &mut ShadowsocksEngineState, code: i32, message: String) -> i32 {
    state.fatal = true;
    state.logger.log(LOG_LEVEL_ERROR, &message);
    set_last_error(code, message)
}

unsafe fn resolve_stream_host_logger(args: *const EngineCreateArgs) -> HostLogger {
    if args.is_null() {
        return HostLogger::default().with_target(STREAM_LOG_TARGET);
    }
    let args = &*args;
    if args.size < EngineCreateArgs::REQUIRED_SIZE || args.host_callbacks.is_null() {
        return HostLogger::default().with_target(STREAM_LOG_TARGET);
    }
    let callbacks = &*args.host_callbacks;
    if callbacks.size < HostCallbacks::REQUIRED_SIZE {
        return HostLogger::default().with_target(STREAM_LOG_TARGET);
    }
    HostLogger {
        callback: callbacks.log,
        host_ctx: callbacks.host_ctx,
        target: STREAM_LOG_TARGET.as_ptr() as *const c_char,
    }
}

unsafe fn resolve_datagram_host_logger(args: *const EngineCreateArgs) -> HostLogger {
    if args.is_null() {
        return HostLogger::default().with_target(DATAGRAM_LOG_TARGET);
    }
    let args = &*args;
    if args.size < EngineCreateArgs::REQUIRED_SIZE || args.host_callbacks.is_null() {
        return HostLogger::default().with_target(DATAGRAM_LOG_TARGET);
    }
    let callbacks = &*args.host_callbacks;
    if callbacks.size < HostCallbacks::REQUIRED_SIZE {
        return HostLogger::default().with_target(DATAGRAM_LOG_TARGET);
    }
    HostLogger {
        callback: callbacks.log,
        host_ctx: callbacks.host_ctx,
        target: DATAGRAM_LOG_TARGET.as_ptr() as *const c_char,
    }
}

fn clear_last_error() {
    LAST_ERROR.with(|state| {
        *state.borrow_mut() = LastErrorState::default();
    });
}

fn set_last_error(code: i32, message: impl Into<String>) -> i32 {
    LAST_ERROR.with(|state| {
        *state.borrow_mut() = LastErrorState {
            code,
            message: message.into(),
        };
    });
    code
}

struct ShadowsocksNonceSequence(Vec<u8>);

impl ShadowsocksNonceSequence {
    fn new(size: usize) -> Self {
        Self(vec![0xff; size])
    }

    fn inc(&mut self) {
        for x in &mut self.0 {
            *x = (*x).wrapping_add(1);
            if *x != 0 {
                return;
            }
        }
    }
}

impl NonceSequence for ShadowsocksNonceSequence {
    fn advance(&mut self) -> Result<Vec<u8>> {
        self.inc();
        Ok(self.0.clone())
    }
}

fn kdf(pass: &str, size: usize) -> Result<Vec<u8>> {
    let pass = pass.as_bytes();
    let mut key = Vec::new();
    let mut sum = Md5::digest(pass).to_vec();
    std::io::Write::write_all(&mut key, &sum)?;
    while key.len() < size {
        sum = Md5::digest([sum, pass.to_vec()].concat()).to_vec();
        std::io::Write::write_all(&mut key, &sum)?;
    }
    Ok(key)
}

fn hkdf_sha1(key: &[u8], salt: &[u8], info: &[u8], size: usize) -> Result<Vec<u8>> {
    let (_, h) = Hkdf::<Sha1>::extract(Some(salt), key);
    let mut okm = vec![0u8; size];
    h.expand(info, &mut okm)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    Ok(okm)
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
    guard(ENGINE_STATUS_PLUGIN_FAILURE, || {
        if instance.is_null() || output.is_null() || produced.is_null() {
            return set_last_error(
                ENGINE_STATUS_INVALID_ARGUMENT,
                "encode_packet received null pointer",
            );
        }
        if (payload_len > 0 && payload.is_null()) || target.is_null() {
            return set_last_error(
                ENGINE_STATUS_INVALID_ARGUMENT,
                "encode_packet received null payload or target address",
            );
        }
        let state = &mut *(instance as *mut ShadowsocksDatagramState);
        let payload = std::slice::from_raw_parts(payload, payload_len);
        let target = match plugin_address_to_socks_addr(&*target) {
            Ok(v) => v,
            Err(err) => {
                return set_last_error(
                    ENGINE_STATUS_INVALID_ARGUMENT,
                    format!("encode_packet received invalid target address: {}", err),
                )
            }
        };
        let mut target_buf = BytesMut::new();
        target.write_buf(&mut target_buf, SocksAddrWireType::PortLast);
        let mut plaintext = BytesMut::new();
        plaintext.extend_from_slice(&target_buf);
        plaintext.extend_from_slice(payload);
        let ciphertext = match encrypt_datagram_packet(state, plaintext) {
            Ok(v) => v,
            Err(err) => {
                return set_last_error(
                    ENGINE_STATUS_PLUGIN_FAILURE,
                    format!("encrypt datagram packet failed: {}", err),
                )
            }
        };
        if output_cap < ciphertext.len() {
            return set_last_error(
                ENGINE_STATUS_BUFFER_TOO_SMALL,
                "encoded datagram packet does not fit output buffer",
            );
        }
        std::slice::from_raw_parts_mut(output, output_cap)[..ciphertext.len()]
            .copy_from_slice(&ciphertext);
        *produced = ciphertext.len();
        clear_last_error();
        ENGINE_STATUS_OK
    })
}

unsafe extern "C" fn decode_packet(
    instance: *mut c_void,
    input: *const u8,
    input_len: usize,
    consumed: *mut usize,
    output: *mut u8,
    output_cap: usize,
    produced: *mut usize,
    address_output: *mut PluginAddress,
) -> i32 {
    guard(ENGINE_STATUS_PLUGIN_FAILURE, || {
        if instance.is_null()
            || output.is_null()
            || produced.is_null()
            || consumed.is_null()
            || address_output.is_null()
        {
            return set_last_error(
                ENGINE_STATUS_INVALID_ARGUMENT,
                "decode_packet received null payload or address pointer",
            );
        }
        // Shadowsocks UDP is an unreliable transport: the host hands over one whole
        // datagram per call, and nothing is ever left over.
        *consumed = 0;
        if input_len > 0 && input.is_null() {
            return set_last_error(
                ENGINE_STATUS_INVALID_ARGUMENT,
                "decode_packet received null input with non-zero length",
            );
        }
        let state = &mut *(instance as *mut ShadowsocksDatagramState);
        let input = std::slice::from_raw_parts(input, input_len);
        let plaintext = match decrypt_datagram_packet(state, BytesMut::from(input)) {
            Ok(v) => v,
            Err(err) => {
                return set_last_error(
                    ENGINE_STATUS_PLUGIN_FAILURE,
                    format!("decrypt datagram packet failed: {}", err),
                )
            }
        };
        let src_addr = match SocksAddr::try_from((&plaintext[..], SocksAddrWireType::PortLast)) {
            Ok(v) => v,
            Err(err) => {
                return set_last_error(
                    ENGINE_STATUS_PLUGIN_FAILURE,
                    format!("decoded datagram packet is missing target address: {}", err),
                )
            }
        };
        let header_len = src_addr.size();
        let payload_len = plaintext.len().saturating_sub(header_len);
        let address_output = &mut *address_output;
        let address_cap = address_output.data_len;
        if output_cap < payload_len || address_output.data.is_null() {
            return set_last_error(
                ENGINE_STATUS_BUFFER_TOO_SMALL,
                "decoded datagram payload does not fit output buffer",
            );
        }
        // Only the address itself goes into the address buffer -- not the wire
        // header it was parsed out of. The host sizes that buffer from
        // `max_address_size`, which is the 255 bytes a domain name can take;
        // asking it to hold the three extra bytes of the header as well would
        // have a long enough source address fail a packet the host cannot
        // retry any wider.
        std::slice::from_raw_parts_mut(output, output_cap)[..payload_len]
            .copy_from_slice(&plaintext[header_len..header_len + payload_len]);
        let (address_data, mut plugin_address) = socks_addr_to_plugin_address(&src_addr);
        if address_data.len() > address_cap {
            return set_last_error(
                ENGINE_STATUS_BUFFER_TOO_SMALL,
                "decoded datagram address does not fit address data buffer",
            );
        }
        std::slice::from_raw_parts_mut(address_output.data as *mut u8, address_cap)
            [..address_data.len()]
            .copy_from_slice(&address_data);
        plugin_address.data = address_output.data;
        plugin_address.data_len = address_data.len();
        *address_output = plugin_address;
        *produced = payload_len;
        *consumed = input_len;
        clear_last_error();
        ENGINE_STATUS_OK
    })
}

unsafe extern "C" fn datagram_max_output_size(
    instance: *mut c_void,
    input_len: usize,
    direction: u32,
) -> usize {
    guard(input_len, || {
        if instance.is_null() {
            return input_len;
        }
        let state = &*(instance as *mut ShadowsocksDatagramState);
        match direction {
            DATAGRAM_DIRECTION_ENCODE => {
                state.cipher.key_len() + input_len + state.cipher.tag_len()
            }
            DATAGRAM_DIRECTION_DECODE => input_len,
            _ => input_len,
        }
    })
}

unsafe extern "C" fn datagram_max_address_size(_instance: *mut c_void, _direction: u32) -> usize {
    guard(255, || 255)
}

fn encrypt_datagram_packet(
    state: &ShadowsocksDatagramState,
    mut buf: BytesMut,
) -> Result<BytesMut> {
    if buf.is_empty() {
        return Ok(BytesMut::new());
    }
    let salt_len = state.cipher.key_len();
    let mut salt = vec![0u8; salt_len];
    let mut rng = StdRng::from_entropy();
    rng.fill_bytes(&mut salt);
    let key = hkdf_sha1(&state.psk, &salt, SUBKEY_INFO, state.cipher.key_len())?;
    let nonce = ShadowsocksNonceSequence::new(state.cipher.nonce_len());
    let mut enc = state.cipher.encryptor(&key, nonce)?;
    enc.encrypt(&mut buf)?;
    let mut out = BytesMut::new();
    out.extend_from_slice(&salt);
    out.extend_from_slice(&buf);
    Ok(out)
}

fn decrypt_datagram_packet(
    state: &ShadowsocksDatagramState,
    mut buf: BytesMut,
) -> Result<BytesMut> {
    let salt_len = state.cipher.key_len();
    let tag_len = state.cipher.tag_len();
    if buf.len() < salt_len + tag_len {
        return Err(anyhow!("short packet"));
    }
    let salt = buf.split_to(salt_len);
    let original_len = buf.len();
    let key = hkdf_sha1(&state.psk, &salt, SUBKEY_INFO, state.cipher.key_len())?;
    let nonce = ShadowsocksNonceSequence::new(state.cipher.nonce_len());
    let mut dec = state.cipher.decryptor(&key, nonce)?;
    dec.decrypt(&mut buf)?;
    let _ = buf.split_off(original_len - tag_len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_client_state(_destination: &str) -> ShadowsocksEngineState {
        let destination = SocksAddr::try_from(("1.2.3.4", 80)).unwrap();
        let mut destination_buf = BytesMut::new();
        destination.write_buf(&mut destination_buf, SocksAddrWireType::PortLast);
        ShadowsocksEngineState {
            logger: HostLogger::default().with_target(STREAM_LOG_TARGET),
            psk: kdf("test-password", 32).unwrap(),
            cipher: AeadCipher::new("chacha20-ietf-poly1305").unwrap(),
            prefix: None,
            enc: None,
            dec: None,
            destination: destination_buf.to_vec(),
            app_input: BytesMut::new(),
            app_output: BytesMut::new(),
            net_input: BytesMut::new(),
            net_output: BytesMut::new(),
            sent_header: false,
            pending_payload_len: None,
            app_closed: false,
            net_closed: false,
            peer_closed: false,
            fatal: false,
        }
    }

    fn new_server_state() -> ShadowsocksEngineState {
        ShadowsocksEngineState {
            logger: HostLogger::default().with_target(STREAM_LOG_TARGET),
            psk: kdf("test-password", 32).unwrap(),
            cipher: AeadCipher::new("chacha20-ietf-poly1305").unwrap(),
            prefix: None,
            enc: None,
            dec: None,
            destination: Vec::new(),
            app_input: BytesMut::new(),
            app_output: BytesMut::new(),
            net_input: BytesMut::new(),
            net_output: BytesMut::new(),
            sent_header: true,
            pending_payload_len: None,
            app_closed: false,
            net_closed: false,
            peer_closed: false,
            fatal: false,
        }
    }

    fn new_datagram_state() -> ShadowsocksDatagramState {
        ShadowsocksDatagramState {
            logger: HostLogger::default().with_target(DATAGRAM_LOG_TARGET),
            psk: kdf("test-password", 32).unwrap(),
            cipher: AeadCipher::new("chacha20-ietf-poly1305").unwrap(),
        }
    }

    #[test]
    fn shadowsocks_engine_roundtrip() {
        let mut client = new_client_state("1.2.3.4:80");
        let mut server = new_server_state();
        let mut consumed = 0usize;
        let mut produced = 0usize;
        let mut buf = vec![0u8; 65536];

        unsafe {
            push_app_input_impl(
                &mut client as *mut _ as *mut c_void,
                b"hello".as_ptr(),
                5,
                &mut consumed,
            )
            .unwrap();
            assert_eq!(consumed, 5);
            pull_net_output_impl(
                &mut client as *mut _ as *mut c_void,
                buf.as_mut_ptr(),
                buf.len(),
                &mut produced,
            )
            .unwrap();
            assert!(produced > 0);

            push_net_input_impl(
                &mut server as *mut _ as *mut c_void,
                buf.as_ptr(),
                produced,
                &mut consumed,
            )
            .unwrap();
            assert_eq!(consumed, produced);
            pull_app_output_impl(
                &mut server as *mut _ as *mut c_void,
                buf.as_mut_ptr(),
                buf.len(),
                &mut produced,
            )
            .unwrap();
        }

        let target = SocksAddr::try_from((&buf[..], SocksAddrWireType::PortLast)).unwrap();
        let header_len = target.size();
        assert_eq!(target.to_string(), "1.2.3.4:80");
        assert_eq!(&buf[header_len..header_len + 5], b"hello");

        unsafe {
            push_app_input_impl(
                &mut server as *mut _ as *mut c_void,
                b"world".as_ptr(),
                5,
                &mut consumed,
            )
            .unwrap();
            pull_net_output_impl(
                &mut server as *mut _ as *mut c_void,
                buf.as_mut_ptr(),
                buf.len(),
                &mut produced,
            )
            .unwrap();
            push_net_input_impl(
                &mut client as *mut _ as *mut c_void,
                buf.as_ptr(),
                produced,
                &mut consumed,
            )
            .unwrap();
            pull_app_output_impl(
                &mut client as *mut _ as *mut c_void,
                buf.as_mut_ptr(),
                buf.len(),
                &mut produced,
            )
            .unwrap();
        }
        assert_eq!(&buf[..produced], b"world");
    }

    #[test]
    fn shadowsocks_datagram_engine_roundtrip() {
        let mut client = new_datagram_state();
        let mut server = new_datagram_state();
        let mut produced = 0usize;
        let mut consumed = 0usize;
        let mut payload_buf = vec![0u8; 65536];
        let mut packet_buf = vec![0u8; 65536];
        let mut addr_buf = vec![0u8; 512];
        let target = SocksAddr::try_from(("8.8.8.8", 53)).unwrap();
        let (target_data, target_addr) = socks_addr_to_plugin_address(&target);
        let mut decoded_addr = PluginAddress {
            kind: 0,
            port: 0,
            data: addr_buf.as_mut_ptr(),
            data_len: addr_buf.len(),
        };

        unsafe {
            assert_eq!(
                encode_packet(
                    &mut client as *mut _ as *mut c_void,
                    b"hello".as_ptr(),
                    5,
                    &target_addr,
                    packet_buf.as_mut_ptr(),
                    packet_buf.len(),
                    &mut produced,
                ),
                0
            );
            let packet_len = produced;
            assert_eq!(
                decode_packet(
                    &mut server as *mut _ as *mut c_void,
                    packet_buf.as_ptr(),
                    packet_len,
                    &mut consumed,
                    payload_buf.as_mut_ptr(),
                    payload_buf.len(),
                    &mut produced,
                    &mut decoded_addr,
                ),
                0
            );
        }

        let decoded_addr = PluginAddress {
            data: addr_buf.as_ptr(),
            ..decoded_addr
        };
        let decoded_addr = plugin_address_to_socks_addr(&decoded_addr).unwrap();
        drop(target_data);
        assert_eq!(decoded_addr.to_string(), "8.8.8.8:53");
        assert_eq!(&payload_buf[..produced], b"hello");
    }
}
