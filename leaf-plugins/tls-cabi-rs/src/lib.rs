//! A rustls-backed TLS transport plugin for the leaf C ABI, and the reference
//! for what a transport plugin written in Rust looks like.
//!
//! It exports one stream engine with [`STREAM_CONNECT_TYPE_NEXT`]: the host
//! hands it whatever stream the previous outbound in the chain produced, and it
//! layers a TLS client session over it, so the outbound must not set `host` or
//! `port` of its own.
//!
//! `args` is JSON:
//!
//! ```json
//! {
//!   "server_name": "example.com",
//!   "alpn": ["h2", "http/1.1"],
//!   "certificate": "/path/to/ca.pem",
//!   "insecure": false
//! }
//! ```
//!
//! `server_name` is required and is what the certificate is checked against.
//! `certificate` is either a path to a PEM file or the PEM text itself, and
//! replaces the built-in webpki root store rather than adding to it, which is
//! what pins a private CA. `insecure` accepts any certificate at all -- for
//! testing only.
//!
//! The engine owns no I/O: the handshake advances only as the host pushes bytes
//! in and pulls bytes out, which is what lets it run on the host's executor
//! without blocking.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Write};
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{anyhow, Result};
use bytes::BytesMut;
use leaf_plugin_abi::{
    AbiStruct, EngineCreateArgs, HostCallbacks, PluginDescriptor, PluginHostLogFn,
    StreamEnginePlugin, ENGINE_STATUS_INVALID_ARGUMENT, ENGINE_STATUS_OK,
    ENGINE_STATUS_PLUGIN_FAILURE, LOG_LEVEL_DEBUG, LOG_LEVEL_ERROR, LOG_LEVEL_INFO,
    PLUGIN_ABI_MAJOR, PLUGIN_ABI_MINOR, STREAM_CONNECT_TYPE_NEXT, STREAM_ENGINE_CLOSE_APP,
    STREAM_ENGINE_CLOSE_NET, STREAM_ENGINE_STATE_ESTABLISHED, STREAM_ENGINE_STATE_FATAL,
    STREAM_ENGINE_STATE_HANDSHAKING, STREAM_ENGINE_STATE_HAS_APP_OUTPUT,
    STREAM_ENGINE_STATE_HAS_NET_OUTPUT, STREAM_ENGINE_STATE_PEER_CLOSED,
    STREAM_ENGINE_STATE_WANT_APP_INPUT, STREAM_ENGINE_STATE_WANT_NET_INPUT, STREAM_SIDE_APP,
    STREAM_SIDE_NET,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use serde::Deserialize;

/// Client configs, keyed by the `args` string that produced them.
///
/// Building one parses PEM, and when `certificate` names a file it reads that
/// file from disk. Neither belongs in `create_instance`: the ABI has engine
/// calls running on the host's executor threads, where they must not block or
/// do I/O. The config depends on nothing but the args, so the first connection
/// of an outbound pays for it and the rest reuse it.
static CLIENT_CONFIGS: LazyLock<Mutex<HashMap<String, Arc<ClientConfig>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn client_config_for(cache_key: &str, args: &TlsPluginArgs) -> Result<Arc<ClientConfig>> {
    if let Some(config) = CLIENT_CONFIGS
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .get(cache_key)
    {
        return Ok(Arc::clone(config));
    }
    // Built without the lock held, so a config that reads a file does not stall
    // every other connection. Two connections racing on a cold cache both build
    // one and the second overwrites the first, which costs nothing.
    let config = build_client_config(args)?;
    CLIENT_CONFIGS
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .insert(cache_key.to_string(), Arc::clone(&config));
    Ok(config)
}

const APP_OUTPUT_SIZE_HINT: usize = 16 * 1024;
const NET_OUTPUT_SIZE_HINT: usize = 18 * 1024;
const OUTPUT_BATCH_HINT: usize = 4;

static PLUGIN_NAME: &[u8] = b"leaf-tls-cabi-rs-plugin\0";
static PLUGIN_VERSION: &[u8] = b"0.1.0\0";
static TLS_LOG_TARGET: &[u8] = b"leaf.plugin.tls\0";

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
}

impl HostLogger {
    fn log(&self, level: u32, message: impl AsRef<str>) {
        let message = message.as_ref();
        if let Some(callback) = self.callback {
            unsafe {
                callback(
                    self.host_ctx,
                    level,
                    TLS_LOG_TARGET.as_ptr() as *const c_char,
                    message.as_ptr(),
                    message.len(),
                );
            }
        }
    }
}

#[repr(C)]
struct TlsEngineState {
    conn: ClientConnection,
    logger: HostLogger,
    pending_net: BytesMut,
    pending_app_input: BytesMut,
    pending_app_output: BytesMut,
    app_closed: bool,
    net_closed: bool,
    peer_closed: bool,
    fatal: bool,
}

#[derive(Debug, Default, Deserialize)]
struct TlsPluginArgs {
    server_name: Option<String>,
    alpn: Option<Vec<String>>,
    certificate: Option<String>,
    insecure: Option<bool>,
}

#[derive(Debug)]
struct NotVerified;

impl ServerCertVerifier for NotVerified {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let _ = (end_entity, intermediates, server_name, ocsp_response, now);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        let _ = (message, cert, dss);
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        let _ = (message, cert, dss);
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[no_mangle]
pub static LEAF_PLUGIN_DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    size: std::mem::size_of::<PluginDescriptor>(),
    abi_major: PLUGIN_ABI_MAJOR,
    abi_minor: PLUGIN_ABI_MINOR,
    name: PLUGIN_NAME.as_ptr() as *const c_char,
    version: PLUGIN_VERSION.as_ptr() as *const c_char,
    stream: &LEAF_STREAM_ENGINE_PLUGIN,
    datagram: std::ptr::null(),
    // No runtime of its own: a Rust cdylib is code and static data, and the
    // host may unmap it when the last handler goes.
    flags: 0,
};

#[no_mangle]
pub static LEAF_STREAM_ENGINE_PLUGIN: StreamEnginePlugin = StreamEnginePlugin {
    size: std::mem::size_of::<StreamEnginePlugin>(),
    connect_type: STREAM_CONNECT_TYPE_NEXT,
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
        let logger = resolve_host_logger(args);
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
            let _ = Box::from_raw(instance as *mut TlsEngineState);
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
    let state = &mut *(instance as *mut TlsEngineState);
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

    let state = &mut *(instance as *mut TlsEngineState);
    *consumed = 0;
    if state.app_closed || state.fatal {
        return Err(set_last_error(
            ENGINE_STATUS_PLUGIN_FAILURE,
            "push_app_input called after application side was closed or entered fatal state",
        ));
    }

    if input_len > 0 {
        let input = std::slice::from_raw_parts(input, input_len);
        state.pending_app_input.extend_from_slice(input);
    }

    write_pending_app(state).map_err(|err| {
        mark_fatal(
            state,
            ENGINE_STATUS_PLUGIN_FAILURE,
            format!("write app input failed: {}", err),
        )
    })?;
    collect_pending_net(state).map_err(|err| {
        mark_fatal(
            state,
            ENGINE_STATUS_PLUGIN_FAILURE,
            format!("collect tls output failed: {}", err),
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

    let state = &mut *(instance as *mut TlsEngineState);
    *consumed = 0;
    if state.net_closed || state.fatal {
        return Err(set_last_error(
            ENGINE_STATUS_PLUGIN_FAILURE,
            "push_net_input called after network side was closed or entered fatal state",
        ));
    }

    if input_len == 0 {
        return Ok(());
    }

    let input = std::slice::from_raw_parts(input, input_len);
    let mut cursor = Cursor::new(input);
    match state.conn.read_tls(&mut cursor) {
        Ok(n) => *consumed = n,
        Err(err) => {
            return Err(mark_fatal(
                state,
                ENGINE_STATUS_PLUGIN_FAILURE,
                format!("read tls input failed: {}", err),
            ))
        }
    }

    let was_handshaking = state.conn.is_handshaking();
    if state.conn.process_new_packets().is_err() {
        return Err(mark_fatal(
            state,
            ENGINE_STATUS_PLUGIN_FAILURE,
            "process_new_packets failed".to_string(),
        ));
    }
    if was_handshaking && !state.conn.is_handshaking() {
        state.logger.log(LOG_LEVEL_INFO, "TLS handshake completed");
    }
    collect_pending_net(state).map_err(|err| {
        mark_fatal(
            state,
            ENGINE_STATUS_PLUGIN_FAILURE,
            format!("collect tls output failed: {}", err),
        )
    })?;
    collect_pending_plaintext(state).map_err(|err| {
        mark_fatal(
            state,
            ENGINE_STATUS_PLUGIN_FAILURE,
            format!("collect plaintext failed: {}", err),
        )
    })?;
    write_pending_app(state).map_err(|err| {
        mark_fatal(
            state,
            ENGINE_STATUS_PLUGIN_FAILURE,
            format!("write pending app input failed: {}", err),
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
    let state = &mut *(instance as *mut TlsEngineState);
    *produced = 0;
    if state.fatal {
        return Err(set_last_error(
            ENGINE_STATUS_PLUGIN_FAILURE,
            "pull_app_output called after fatal error",
        ));
    }

    collect_pending_plaintext(state).map_err(|err| {
        mark_fatal(
            state,
            ENGINE_STATUS_PLUGIN_FAILURE,
            format!("collect plaintext failed: {}", err),
        )
    })?;
    let to_copy = state.pending_app_output.len().min(output_cap);
    if to_copy > 0 {
        let output = std::slice::from_raw_parts_mut(output, output_cap);
        output[..to_copy].copy_from_slice(&state.pending_app_output.split_to(to_copy));
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
    let state = &mut *(instance as *mut TlsEngineState);
    *produced = 0;
    if state.fatal {
        return Err(set_last_error(
            ENGINE_STATUS_PLUGIN_FAILURE,
            "pull_net_output called after fatal error",
        ));
    }

    collect_pending_net(state).map_err(|err| {
        mark_fatal(
            state,
            ENGINE_STATUS_PLUGIN_FAILURE,
            format!("collect tls output failed: {}", err),
        )
    })?;
    let to_copy = state.pending_net.len().min(output_cap);
    if to_copy > 0 {
        let output = std::slice::from_raw_parts_mut(output, output_cap);
        output[..to_copy].copy_from_slice(&state.pending_net.split_to(to_copy));
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
    let state = &mut *(instance as *mut TlsEngineState);
    if (close_flags & STREAM_ENGINE_CLOSE_APP) != 0 && !state.app_closed {
        state.app_closed = true;
        state.logger.log(
            LOG_LEVEL_DEBUG,
            "closing application input and sending close_notify",
        );
        state.conn.send_close_notify();
        collect_pending_net(state).map_err(|err| {
            mark_fatal(
                state,
                ENGINE_STATUS_PLUGIN_FAILURE,
                format!("collect close_notify output failed: {}", err),
            )
        })?;
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
) -> Result<TlsEngineState> {
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

    let parsed = parse_plugin_args(plugin_args)?;
    let server_name = parsed
        .server_name
        .as_deref()
        .ok_or_else(|| anyhow!("tls plugin args missing server_name"))?;
    logger.log(
        LOG_LEVEL_INFO,
        format!("creating TLS engine for server_name={}", server_name),
    );
    let config = client_config_for(plugin_args, &parsed)?;
    let server_name = ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow!("invalid server_name: {}", server_name))?;
    let conn = ClientConnection::new(config, server_name)?;

    let mut state = TlsEngineState {
        conn,
        logger,
        pending_net: BytesMut::new(),
        pending_app_input: BytesMut::new(),
        pending_app_output: BytesMut::new(),
        app_closed: false,
        net_closed: false,
        peer_closed: false,
        fatal: false,
    };
    collect_pending_net(&mut state)?;
    if !state.pending_net.is_empty() {
        state.logger.log(
            LOG_LEVEL_DEBUG,
            format!(
                "queued {} bytes of initial TLS handshake output",
                state.pending_net.len()
            ),
        );
    }
    Ok(state)
}

fn parse_plugin_args(input: &str) -> Result<TlsPluginArgs> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("tls plugin args must not be empty"));
    }
    if trimmed.starts_with('{') {
        Ok(serde_json::from_str(trimmed)?)
    } else {
        Ok(TlsPluginArgs {
            server_name: Some(trimmed.to_string()),
            ..Default::default()
        })
    }
}

fn build_client_config(args: &TlsPluginArgs) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    if let Some(cert) = args.certificate.as_ref() {
        if cert.contains("-----BEGIN") {
            let mut pem = BufReader::new(Cursor::new(cert.as_bytes()));
            for cert in rustls_pemfile::certs(&mut pem) {
                roots.add(cert?)?;
            }
        } else {
            let mut pem = BufReader::new(File::open(cert)?);
            for cert in rustls_pemfile::certs(&mut pem) {
                roots.add(cert?)?;
            }
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let provider = rustls::crypto::ring::default_provider().into();
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| anyhow!("invalid tls protocol versions: {}", err))?;

    let mut config = if args.insecure.unwrap_or(false) {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NotVerified))
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };

    if let Some(alpn) = args.alpn.as_ref() {
        for item in alpn {
            config.alpn_protocols.push(item.as_bytes().to_vec());
        }
    }
    Ok(Arc::new(config))
}

fn collect_pending_net(state: &mut TlsEngineState) -> Result<()> {
    while state.conn.wants_write() {
        let mut buf = Vec::new();
        let written = state.conn.write_tls(&mut buf)?;
        if written == 0 {
            break;
        }
        state.pending_net.extend_from_slice(&buf);
    }
    Ok(())
}

fn write_pending_app(state: &mut TlsEngineState) -> Result<()> {
    while !state.pending_app_input.is_empty() {
        let written = state.conn.writer().write(&state.pending_app_input)?;
        if written == 0 {
            break;
        }
        let _ = state.pending_app_input.split_to(written);
    }
    Ok(())
}

fn collect_pending_plaintext(state: &mut TlsEngineState) -> Result<()> {
    let mut scratch = [0u8; 4096];
    loop {
        match state.conn.reader().read(&mut scratch) {
            Ok(0) => break,
            Ok(n) => state.pending_app_output.extend_from_slice(&scratch[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(err) => return Err(anyhow!("read plaintext failed: {}", err)),
        }
    }
    Ok(())
}

fn build_state_flags(state: &TlsEngineState) -> u32 {
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
    if !state.pending_net.is_empty() || state.conn.wants_write() {
        flags |= STREAM_ENGINE_STATE_HAS_NET_OUTPUT;
    }
    if !state.pending_app_output.is_empty() {
        flags |= STREAM_ENGINE_STATE_HAS_APP_OUTPUT;
    }
    if state.conn.is_handshaking() {
        flags |= STREAM_ENGINE_STATE_HANDSHAKING;
    } else {
        flags |= STREAM_ENGINE_STATE_ESTABLISHED;
    }
    if state.peer_closed {
        flags |= STREAM_ENGINE_STATE_PEER_CLOSED;
    }

    flags
}

fn mark_fatal(state: &mut TlsEngineState, code: i32, message: String) -> i32 {
    state.fatal = true;
    state.logger.log(LOG_LEVEL_ERROR, &message);
    set_last_error(code, message)
}

unsafe fn resolve_host_logger(args: *const EngineCreateArgs) -> HostLogger {
    if args.is_null() {
        return HostLogger::default();
    }
    let args = &*args;
    if args.size < EngineCreateArgs::REQUIRED_SIZE || args.host_callbacks.is_null() {
        return HostLogger::default();
    }
    let callbacks = &*args.host_callbacks;
    if callbacks.size < HostCallbacks::REQUIRED_SIZE {
        return HostLogger::default();
    }
    HostLogger {
        callback: callbacks.log,
        host_ctx: callbacks.host_ctx,
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

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};

    fn build_server() -> Result<ServerConnection> {
        let cert = generate_simple_self_signed(vec!["localhost".to_string()])?;
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let provider = rustls::crypto::ring::default_provider().into();
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)?;
        Ok(ServerConnection::new(Arc::new(config))?)
    }

    unsafe fn new_state() -> TlsEngineState {
        let args =
            std::ffi::CString::new(r#"{"server_name":"localhost","insecure":true}"#).unwrap();
        let create_args = EngineCreateArgs {
            size: std::mem::size_of::<EngineCreateArgs>(),
            host_abi_major: PLUGIN_ABI_MAJOR,
            host_abi_minor: PLUGIN_ABI_MINOR,
            plugin_args: args.as_ptr(),
            destination: std::ptr::null(),
            host_callbacks: std::ptr::null(),
        };
        create_state(&create_args, HostLogger::default()).unwrap()
    }

    #[test]
    fn tls_engine_handshake_and_roundtrip() {
        let mut client = unsafe { new_state() };
        let mut server = build_server().unwrap();

        let mut c_to_s = vec![0u8; 64 * 1024];
        let mut s_to_c = vec![0u8; 64 * 1024];
        let mut consumed = 0usize;
        let mut produced = 0usize;
        let mut flags = 0u32;

        unsafe {
            poll_state_impl(&mut client as *mut _ as *mut c_void, &mut flags).unwrap();
            assert_ne!(flags & STREAM_ENGINE_STATE_HAS_NET_OUTPUT, 0);

            pull_net_output_impl(
                &mut client as *mut _ as *mut c_void,
                c_to_s.as_mut_ptr(),
                c_to_s.len(),
                &mut produced,
            )
            .unwrap();
        }
        assert!(produced > 0, "client should emit ClientHello");

        let mut cursor = Cursor::new(&c_to_s[..produced]);
        server.read_tls(&mut cursor).unwrap();
        server.process_new_packets().unwrap();
        let mut server_flight = Vec::new();
        server.write_tls(&mut server_flight).unwrap();

        unsafe {
            push_net_input_impl(
                &mut client as *mut _ as *mut c_void,
                server_flight.as_ptr(),
                server_flight.len(),
                &mut consumed,
            )
            .unwrap();
        }
        assert_eq!(consumed, server_flight.len());

        unsafe {
            pull_net_output_impl(
                &mut client as *mut _ as *mut c_void,
                c_to_s.as_mut_ptr(),
                c_to_s.len(),
                &mut produced,
            )
            .unwrap();
        }
        assert!(produced > 0, "client should emit Finished");

        let mut cursor = Cursor::new(&c_to_s[..produced]);
        server.read_tls(&mut cursor).unwrap();
        server.process_new_packets().unwrap();
        assert!(!server.is_handshaking());
        assert!(!client.conn.is_handshaking());

        let plaintext = b"hello tls";
        unsafe {
            push_app_input_impl(
                &mut client as *mut _ as *mut c_void,
                plaintext.as_ptr(),
                plaintext.len(),
                &mut consumed,
            )
            .unwrap();
            pull_net_output_impl(
                &mut client as *mut _ as *mut c_void,
                c_to_s.as_mut_ptr(),
                c_to_s.len(),
                &mut produced,
            )
            .unwrap();
        }
        assert_eq!(consumed, plaintext.len());
        assert!(produced > 0);

        let mut cursor = Cursor::new(&c_to_s[..produced]);
        server.read_tls(&mut cursor).unwrap();
        server.process_new_packets().unwrap();
        let mut server_plain = Vec::new();
        let mut scratch = [0u8; 4096];
        loop {
            match server.reader().read(&mut scratch) {
                Ok(0) => break,
                Ok(n) => server_plain.extend_from_slice(&scratch[..n]),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => panic!("server plaintext read failed: {}", err),
            }
        }
        assert_eq!(server_plain, plaintext);

        server.writer().write_all(b"hello back").unwrap();
        let mut server_app = Vec::new();
        server.write_tls(&mut server_app).unwrap();

        unsafe {
            push_net_input_impl(
                &mut client as *mut _ as *mut c_void,
                server_app.as_ptr(),
                server_app.len(),
                &mut consumed,
            )
            .unwrap();
            pull_app_output_impl(
                &mut client as *mut _ as *mut c_void,
                s_to_c.as_mut_ptr(),
                s_to_c.len(),
                &mut produced,
            )
            .unwrap();
        }
        assert_eq!(&s_to_c[..produced], b"hello back");
    }
}
