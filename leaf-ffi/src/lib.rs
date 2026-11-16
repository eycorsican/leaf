#![allow(clippy::missing_safety_doc)]
use std::{ffi::CStr, os::raw::c_char};

/// No error.
pub const ERR_OK: i32 = 0;
/// Config path error.
pub const ERR_CONFIG_PATH: i32 = 1;
/// Config parsing error.
pub const ERR_CONFIG: i32 = 2;
/// IO error.
pub const ERR_IO: i32 = 3;
/// Config file watcher error.
pub const ERR_WATCHER: i32 = 4;
/// Async channel send error.
pub const ERR_ASYNC_CHANNEL_SEND: i32 = 5;
/// Sync channel receive error.
pub const ERR_SYNC_CHANNEL_RECV: i32 = 6;
/// Runtime manager error.
pub const ERR_RUNTIME_MANAGER: i32 = 7;
/// No associated config file.
pub const ERR_NO_CONFIG_FILE: i32 = 8;
/// No data found.
pub const ERR_NO_DATA: i32 = 9;

fn to_errno(e: leaf::Error) -> i32 {
    match e {
        leaf::Error::Config(..) => ERR_CONFIG,
        leaf::Error::NoConfigFile => ERR_NO_CONFIG_FILE,
        leaf::Error::Io(..) => ERR_IO,
        #[cfg(feature = "auto-reload")]
        leaf::Error::Watcher(..) => ERR_WATCHER,
        leaf::Error::AsyncChannelSend(..) => ERR_ASYNC_CHANNEL_SEND,
        leaf::Error::SyncChannelRecv(..) => ERR_SYNC_CHANNEL_RECV,
        leaf::Error::RuntimeManager => ERR_RUNTIME_MANAGER,
    }
}

/// Starts leaf with options, on a successful start this function blocks the current
/// thread.
///
/// @note This is not a stable API, parameters will change from time to time.
///
/// @param rt_id A unique ID to associate this leaf instance, this is required when
///              calling subsequent FFI functions, e.g. reload, shutdown.
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @param auto_reload Enabls auto reloading when config file changes are detected,
///                    takes effect only when the "auto-reload" feature is enabled.
/// @param multi_thread Whether to use a multi-threaded runtime.
/// @param auto_threads Sets the number of runtime worker threads automatically,
///                     takes effect only when multi_thread is true.
/// @param threads Sets the number of runtime worker threads, takes effect when
///                     multi_thread is true, but can be overridden by auto_threads.
/// @param stack_size Sets stack size of the runtime worker threads, takes effect when
///                   multi_thread is true.
/// @return ERR_OK on finish running, any other errors means a startup failure.
#[no_mangle]
#[allow(unused_variables)]
pub unsafe extern "C" fn leaf_run_with_options(
    rt_id: u16,
    config_path: *const c_char,
    auto_reload: bool, // requires this parameter anyway
    multi_thread: bool,
    auto_threads: bool,
    threads: i32,
    stack_size: i32,
) -> i32 {
    if let Ok(config_path) = unsafe { CStr::from_ptr(config_path).to_str() } {
        if let Err(e) = leaf::util::run_with_options(
            rt_id,
            config_path.to_string(),
            #[cfg(feature = "auto-reload")]
            auto_reload,
            multi_thread,
            auto_threads,
            threads as usize,
            stack_size as usize,
        ) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

/// Starts leaf with a single-threaded runtime, on a successful start this function
/// blocks the current thread.
///
/// @param rt_id A unique ID to associate this leaf instance, this is required when
///              calling subsequent FFI functions, e.g. reload, shutdown.
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @return ERR_OK on finish running, any other errors means a startup failure.
#[no_mangle]
pub unsafe extern "C" fn leaf_run(rt_id: u16, config_path: *const c_char) -> i32 {
    if let Ok(config_path) = unsafe { CStr::from_ptr(config_path).to_str() } {
        let opts = leaf::StartOptions {
            config: leaf::Config::File(config_path.to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: leaf::RuntimeOption::SingleThread,
        };
        if let Err(e) = leaf::start(rt_id, opts) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

#[no_mangle]
pub unsafe extern "C" fn leaf_run_with_config_string(rt_id: u16, config: *const c_char) -> i32 {
    if let Ok(config) = unsafe { CStr::from_ptr(config).to_str() } {
        let opts = leaf::StartOptions {
            config: leaf::Config::Str(config.to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: leaf::RuntimeOption::SingleThread,
        };
        if let Err(e) = leaf::start(rt_id, opts) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

/// Reloads DNS servers, outbounds and routing rules from the config file.
///
/// @param rt_id The ID of the leaf instance to reload.
///
/// @return Returns ERR_OK on success.
#[no_mangle]
pub extern "C" fn leaf_reload(rt_id: u16) -> i32 {
    if let Err(e) = leaf::reload(rt_id) {
        return to_errno(e);
    }
    ERR_OK
}

/// Shuts down leaf.
///
/// @param rt_id The ID of the leaf instance to reload.
///
/// @return Returns true on success, false otherwise.
#[no_mangle]
pub extern "C" fn leaf_shutdown(rt_id: u16) -> bool {
    leaf::shutdown(rt_id)
}

/// Tells leaf that the device's network changed (call it on every path
/// change: `NWPathMonitor` on Apple, `ConnectivityManager.NetworkCallback` on
/// Android). Every `standby` group switches to the state it remembers for
/// `network_id` (up to 16 networks), so the last actor that worked there is
/// tried first; a new or unknown network starts fresh (discovery).
///
/// @param rt_id The ID of the leaf instance.
/// @param network_id An identity of the network (e.g. the Wi-Fi SSID or the
///                   cellular carrier), or NULL / empty if unknown. leaf
///                   keeps only its SHA-256, never the id itself (in memory
///                   and in the state file).
///
/// @return Returns true if the leaf instance runs, false otherwise.
#[no_mangle]
pub unsafe extern "C" fn leaf_network_changed(rt_id: u16, network_id: *const c_char) -> bool {
    let id = if network_id.is_null() {
        ""
    } else {
        unsafe { CStr::from_ptr(network_id) }.to_str().unwrap_or("")
    };
    leaf::network_changed(rt_id, id)
}

/// Pauses the kiri bridge the config asks for (`[Kiri] bridge = true`): it
/// unlinks from the registrars and stops serving until resumed. When to
/// pause (e.g. off Wi-Fi or off charge) is the app's decision.
///
/// @param rt_id The ID of the leaf instance.
///
/// @return Returns true if the leaf instance runs (also when its config has
///         no bridge: the pause then holds for a bridge a reload adds), false
///         otherwise, and always false without the `kiri` feature.
#[no_mangle]
pub extern "C" fn leaf_kiri_bridge_pause(rt_id: u16) -> bool {
    set_kiri_bridge_paused(rt_id, true)
}

/// Resumes the kiri bridge paused by `leaf_kiri_bridge_pause`.
///
/// @param rt_id The ID of the leaf instance.
///
/// @return Returns true if the leaf instance runs, false otherwise, and
///         always false without the `kiri` feature.
#[no_mangle]
pub extern "C" fn leaf_kiri_bridge_resume(rt_id: u16) -> bool {
    set_kiri_bridge_paused(rt_id, false)
}

/// Whether a kiri bridge runs (configured, started and not paused).
///
/// @param rt_id The ID of the leaf instance.
///
/// @return Returns true while the leaf instance runs a kiri bridge; always
///         false without the `kiri` feature.
#[no_mangle]
pub extern "C" fn leaf_kiri_bridge_running(rt_id: u16) -> bool {
    kiri_bridge_running(rt_id)
}

/// `leaf_kiri_set_user_prefs`: the user has not chosen (the server's
/// default: the conf's `[Kiri] bridge`; for `connect`: on).
pub const LEAF_KIRI_PREF_DEFAULT: i32 = 0;
/// `leaf_kiri_set_user_prefs`: the user turned it on.
pub const LEAF_KIRI_PREF_ON: i32 = 1;
/// `leaf_kiri_set_user_prefs`: the user turned it off.
pub const LEAF_KIRI_PREF_OFF: i32 = 2;

/// `leaf_kiri_bridge_state`: the bridge is wanted (running, or starting; a
/// failed start is in the log).
pub const LEAF_KIRI_BRIDGE_ON: i32 = 0;
/// `leaf_kiri_bridge_state`: off, the user turned it off.
pub const LEAF_KIRI_BRIDGE_OFF_BY_USER: i32 = 1;
/// `leaf_kiri_bridge_state`: off, the user has not chosen and the conf's
/// `[Kiri] bridge` is false or unset (the server's default).
pub const LEAF_KIRI_BRIDGE_OFF_BY_SERVER_DEFAULT: i32 = 2;
/// `leaf_kiri_bridge_state`: off, forced by the conf's `bridge-override =
/// off` whatever the user chose (show the switch greyed out).
pub const LEAF_KIRI_BRIDGE_FORCED_OFF_BY_SERVER: i32 = 3;
/// `leaf_kiri_bridge_state`: wanted, but paused by the app
/// (`leaf_kiri_bridge_pause`).
pub const LEAF_KIRI_BRIDGE_PAUSED: i32 = 4;
/// `leaf_kiri_bridge_state`: wanted, but the conf has no `[Kiri]` ROOT key
/// and config to run it with.
pub const LEAF_KIRI_BRIDGE_NOT_CONFIGURED: i32 = 5;
/// `leaf_kiri_bridge_state`: leaf is built without the bridge.
pub const LEAF_KIRI_BRIDGE_NOT_BUILT: i32 = 6;
/// `leaf_kiri_bridge_state`: no leaf instance with this ID runs.
pub const LEAF_KIRI_BRIDGE_NO_RUNTIME: i32 = 7;
/// `leaf_kiri_bridge_state`: wanted and running, but the bridge reaches no
/// egress server: it is not offered to clients until a route works again
/// (it unlinked from the registrars; it links again by itself).
pub const LEAF_KIRI_BRIDGE_UPSTREAM_DOWN: i32 = 8;

/// The user's kiri switches (the app's "connect to the kiri network" and
/// "be a bridge"). Callable before `leaf_run*` (kept for `rt_id` and read
/// when the instance starts: a bridge turned off never starts) and while it
/// runs (takes effect at once, no reload).
///
/// @param rt_id The ID of the leaf instance.
/// @param connect LEAF_KIRI_PREF_OFF: every `kiri` outbound is disabled: its
///                client stops (no session, config or directory fetch,
///                telemetry), its connections close, a `standby` group skips
///                it, and connections routed to it go to its `fallback=TAG`
///                outbound or fail at once without one. LEAF_KIRI_PREF_ON or
///                LEAF_KIRI_PREF_DEFAULT: on (started lazily).
/// @param bridge LEAF_KIRI_PREF_DEFAULT: the conf's `[Kiri] bridge` (the
///               server's default); LEAF_KIRI_PREF_ON / _OFF: the user's
///               choice. The conf's `bridge-override = off` and
///               `leaf_kiri_bridge_pause` still stop it
///               (`leaf_kiri_bridge_state` tells why).
///
/// @return Returns true if the leaf instance runs (applied now), false if
///         it does not (kept for its start), and false for an unknown value
///         (nothing changed) or without the `kiri` feature.
#[no_mangle]
pub extern "C" fn leaf_kiri_set_user_prefs(rt_id: u16, connect: i32, bridge: i32) -> bool {
    let pref = |v: i32| match v {
        LEAF_KIRI_PREF_DEFAULT => Some(None),
        LEAF_KIRI_PREF_ON => Some(Some(true)),
        LEAF_KIRI_PREF_OFF => Some(Some(false)),
        _ => None,
    };
    let (Some(connect), Some(bridge)) = (pref(connect), pref(bridge)) else {
        return false;
    };
    set_kiri_user_prefs(rt_id, connect != Some(false), bridge)
}

/// The user's egress choice (kiri design §19.46 "Egress choice"): one of
/// the signed config's egresses by id (`leaf_kiri_status`'s `egresses`
/// lists them, lowest estimated round trip first), used now and kept; NULL
/// or "" for automatic (the lowest round trip, moved to while no connection
/// is open). Before the leaf instance starts or while it runs; kept for
/// `rt_id` across restarts, on the device only (store it in the app to keep
/// it across app launches).
///
/// @param rt_id The ID of the leaf instance.
/// @param egress The egress id (UTF-8, NUL-terminated), or NULL / "".
/// @return Returns true if the leaf instance runs (applied now), false if
///         it does not (kept for its start) or without the `kiri` feature.
#[no_mangle]
pub extern "C" fn leaf_kiri_set_egress(rt_id: u16, egress: *const c_char) -> bool {
    let egress = if egress.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(egress) }.to_str().ok().map(str::to_string).filter(|e| !e.is_empty())
    };
    set_kiri_egress(rt_id, egress)
}

/// Whether the kiri bridge is wanted, and why not, for the app's switch.
///
/// @param rt_id The ID of the leaf instance.
///
/// @return One of LEAF_KIRI_BRIDGE_*: LEAF_KIRI_BRIDGE_ON, _OFF_BY_USER,
///         _OFF_BY_SERVER_DEFAULT, _FORCED_OFF_BY_SERVER, _PAUSED,
///         _NOT_CONFIGURED, _NOT_BUILT (always without the `kiri` feature),
///         _NO_RUNTIME.
#[no_mangle]
pub extern "C" fn leaf_kiri_bridge_state(rt_id: u16) -> i32 {
    kiri_bridge_state(rt_id)
}

/// Turns the kiri bridge's client activity lines on or off (`kiri bridge:
/// client offer …`, `client connected …`, `circuit opened …`, `traffic: …`
/// in leaf's log). Off by default: they are per-session records with their
/// times (kiri §19.41, S1), a diagnostic for testing a bridge, not for
/// normal use. Kept for `rt_id` like the user's switches: callable before
/// `leaf_run*` and while it runs (at once).
///
/// @param rt_id The ID of the leaf instance.
/// @param on True to log client activity.
///
/// @return Returns true if the leaf instance runs, false otherwise (kept
///         for its start), and always false without the `kiri` feature.
#[no_mangle]
pub extern "C" fn leaf_kiri_bridge_activity_log(rt_id: u16, on: bool) -> bool {
    set_kiri_bridge_activity_log(rt_id, on)
}

/// The kiri state of a leaf instance as JSON (UTF-8) for the app's UI:
/// every `kiri` outbound with its client's session and paths — transport,
/// the bridge's address as this device sees it, ICE candidate types, the
/// bridge's id, round trip to the bridge (`hop_rtt_ms`: TCP kernel srtt,
/// QUIC srtt, ICE consent checks) and to the egress (`e2e_rtt_ms`: kiri's
/// session PING/PONG), rates and bytes, age — and the bridge's state
/// (LEAF_KIRI_BRIDGE_*) and counts. Local only: it holds bridge addresses,
/// never a destination; do not log or send it. Costs no traffic. Blocks
/// for at most about 2 s; poll it (~1 s) from a thread of the app, not
/// from a leaf callback.
///
/// Schema (version 1), absent values `null`:
/// {"version":1,"connect":bool,
///  "outbounds":[{"tag":str,"state":"disabled"|"not-started"|"starting"|
///    "failed"|"idle-stopped"|"stopped"|"idle"|"connecting"|"up",
///    "error":str|null,"egress":str|null,"nat":str|null,
///    "mode":"bridged"|"direct"|null,"sessions":int,
///    "traffic":null|{"up":int,"down":int,"extra_up":int,"extra_down":int},
///    "paths":[{"session":int,"transport":str,"via_bridge":bool,
///      "peer":"IP:port"|null,"ice_local":str|null,"ice_remote":str|null,
///      "bridge_id":str|null,"detail":str|null,"hop_rtt_ms":num|null,
///      "e2e_rtt_ms":num|null,"e2e_rtt_min_ms":num|null,
///      "rate_up":num,"rate_down":num,"bytes_up":int,"bytes_down":int,
///      "age_s":num,"state":"probation"|"up"|"retiring"}]}],
///  "bridge":{"state":int,"running":bool,"stats":null|{"circuits":int,
///    "opened":int,"refused_full":int,"forwarded":int,
///    "upstream_failures":int,"upstream_down":bool,"upstream_connections":int,
///    "offers":int,"answered":int,"refused":int,
///    "connected":int,"failed":int}}}
/// Rates are payload bytes per second over the last 2 s (up: towards the
/// egress), bytes payload bytes so far. "traffic": payload bytes since the
/// client started (first sends and receipts) and what multipath added:
/// records sent again on another path and copies (extra_up), duplicates
/// received (extra_down); framing and keepalives not counted.
///
/// @param rt_id The ID of the leaf instance.
/// @param buf Where the JSON goes, NUL-terminated, if it fits (may be NULL
///            when len is 0).
/// @param len Size of buf in bytes.
///
/// @return The JSON's length in bytes (without the NUL). It was written
///         only if this is less than len; otherwise call again with a
///         buffer of at least the returned length + 1 (buf[0] is set to
///         NUL if len > 0). Without the `kiri` feature: a JSON with no
///         outbounds and bridge state LEAF_KIRI_BRIDGE_NOT_BUILT.
#[no_mangle]
pub unsafe extern "C" fn leaf_kiri_status(rt_id: u16, buf: *mut c_char, len: usize) -> i32 {
    let json = kiri_status(rt_id);
    let n = json.len();
    if !buf.is_null() && len > 0 {
        // SAFETY: the caller gives `len` writable bytes at `buf`.
        let out = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, len) };
        if n < len {
            out[..n].copy_from_slice(json.as_bytes());
            out[n] = 0;
        } else {
            out[0] = 0;
        }
    }
    n.min(i32::MAX as usize) as i32
}

#[cfg(feature = "kiri")]
use leaf::{
    kiri_bridge_running, kiri_status, set_kiri_bridge_activity_log, set_kiri_bridge_paused,
    set_kiri_egress, set_kiri_user_prefs,
};

#[cfg(not(feature = "kiri"))]
fn set_kiri_egress(_rt_id: u16, _egress: Option<String>) -> bool {
    false
}

#[cfg(not(feature = "kiri"))]
fn kiri_status(_rt_id: u16) -> String {
    format!(
        "{{\"version\":1,\"connect\":false,\"outbounds\":[],\"bridge\":{{\"state\":{},\"running\":false,\"stats\":null}}}}",
        LEAF_KIRI_BRIDGE_NOT_BUILT
    )
}

#[cfg(not(feature = "kiri"))]
fn set_kiri_bridge_activity_log(_rt_id: u16, _on: bool) -> bool {
    false
}

#[cfg(feature = "kiri")]
fn kiri_bridge_state(rt_id: u16) -> i32 {
    leaf::kiri_bridge_state(rt_id) as i32
}

#[cfg(not(feature = "kiri"))]
fn set_kiri_user_prefs(_rt_id: u16, _connect: bool, _bridge: Option<bool>) -> bool {
    false
}

#[cfg(not(feature = "kiri"))]
fn kiri_bridge_state(_rt_id: u16) -> i32 {
    LEAF_KIRI_BRIDGE_NOT_BUILT
}

#[cfg(not(feature = "kiri"))]
fn set_kiri_bridge_paused(_rt_id: u16, _paused: bool) -> bool {
    false
}

#[cfg(not(feature = "kiri"))]
fn kiri_bridge_running(_rt_id: u16) -> bool {
    false
}

/// Tests the configuration.
///
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @return Returns ERR_OK on success, i.e no syntax error.
#[no_mangle]
pub unsafe extern "C" fn leaf_test_config(config_path: *const c_char) -> i32 {
    if let Ok(config_path) = unsafe { CStr::from_ptr(config_path).to_str() } {
        if let Err(e) = leaf::test_config(config_path) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

/// Tests all outbounds connectivity and latency.
///
/// @param config The content of the config file.
/// @param concurrency The maximum number of concurrent tests.
/// @param timeout_sec The timeout in seconds for each test.
/// @param context User-provided context pointer to be passed back to the callback.
/// @param callback The callback function to receive results.
///                 Arguments: tag (string), tcp_latency (ms, -1 if failed), udp_latency (ms, -1 if failed), context.
/// @return Returns ERR_OK on success.
#[no_mangle]
pub unsafe extern "C" fn leaf_test_outbounds(
    config: *const c_char,
    concurrency: u32,
    timeout_sec: u32,
    context: *mut std::ffi::c_void,
    callback: extern "C" fn(*const c_char, i32, i32, *mut std::ffi::c_void),
) -> i32 {
    if let Ok(config_str) = unsafe { CStr::from_ptr(config).to_str() } {
        // Send context safely to the other thread?
        // raw pointers are not Send.
        // But we are blocking on rt.block_on, so we are staying in this function?
        // No, rt.block_on blocks the current thread until the future completes.
        // The callback is called from within the future.
        // Since we block, the context pointer is valid for the duration.
        // However, the future is executed on the runtime.
        // We need to wrap the pointer in a Send wrapper if the runtime is multi-threaded.
        // But here we create a new Runtime `Runtime::new()`, which is multi-threaded by default?
        // Or we can use `current_thread` runtime.
        // leaf::util::test_outbounds is async.

        // Let's use a wrapper struct to make the pointer Send/Sync since we know we are waiting for it.
        struct SendPtr(*mut std::ffi::c_void);
        unsafe impl Send for SendPtr {}
        unsafe impl Sync for SendPtr {}
        let ctx = SendPtr(context);

        let config = match leaf::config::from_string(config_str) {
            Ok(c) => c,
            Err(e) => return to_errno(leaf::Error::Config(anyhow::anyhow!(e))),
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            use futures::StreamExt;
            let timeout = if timeout_sec > 0 {
                Some(std::time::Duration::from_secs(timeout_sec as u64))
            } else {
                None
            };
            if let Ok(mut stream) =
                leaf::util::stream_outbounds_tests(&config, timeout, concurrency as usize).await
            {
                while let Some((tag, (tcp_res, udp_res))) = stream.next().await {
                    let tag_cstring = std::ffi::CString::new(tag.clone()).unwrap();
                    let tcp_latency = match tcp_res {
                        Ok(d) => d.as_millis() as i32,
                        Err(e) => {
                            println!("TCP test failed for {}: {:?}", tag, e);
                            -1
                        }
                    };
                    let udp_latency = match udp_res {
                        Ok(d) => d.as_millis() as i32,
                        Err(e) => {
                            println!("UDP test failed for {}: {:?}", tag, e);
                            -1
                        }
                    };
                    callback(tag_cstring.as_ptr(), tcp_latency, udp_latency, ctx.0);
                }
            } else {
                println!("Failed to start stream_outbounds_tests");
            }
        });
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

/// Runs a health check for an outbound.
///
/// This performs an active health check by sending a PING to healthcheck.leaf
/// and waiting for a PONG response through the specified outbound, testing both
/// TCP and UDP protocols.
///
/// @param rt_id The ID of the leaf instance.
/// @param outbound_tag The tag of the outbound to test.
/// @param timeout_ms Timeout in milliseconds (0 for default 4 seconds).
/// @return Returns ERR_OK if either TCP or UDP health check succeeds, error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn leaf_health_check(
    rt_id: u16,
    outbound_tag: *const c_char,
    timeout_ms: u64,
) -> i32 {
    use std::time::Duration;

    let outbound_tag = if let Ok(tag) = unsafe { CStr::from_ptr(outbound_tag).to_str() } {
        tag.to_string()
    } else {
        return ERR_CONFIG_PATH;
    };

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    let result = if let Some(m) = manager {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let timeout = if timeout_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(timeout_ms))
        };
        rt.block_on(async move { m.health_check_outbound(&outbound_tag, timeout).await })
    } else {
        Err(leaf::Error::RuntimeManager)
    };

    match result {
        Ok((tcp_res, udp_res)) => {
            if tcp_res.is_ok() || udp_res.is_ok() {
                ERR_OK
            } else {
                ERR_IO
            }
        }
        Err(e) => to_errno(e),
    }
}

/// Gets the last active time for an outbound.
///
/// This returns the timestamp of the last successful connection through the outbound.
///
/// @param rt_id The ID of the leaf instance.
/// @param outbound_tag The tag of the outbound.
/// @param timestamp_s Pointer to store the timestamp in seconds since epoch.
/// @return Returns ERR_OK on success, ERR_NO_DATA if no active time found, error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn leaf_get_last_active(
    rt_id: u16,
    outbound_tag: *const c_char,
    timestamp_s: *mut u32,
) -> i32 {
    let outbound_tag = if let Ok(tag) = unsafe { CStr::from_ptr(outbound_tag).to_str() } {
        tag.to_string()
    } else {
        return ERR_CONFIG_PATH;
    };

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    let result = if let Some(m) = manager {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move { m.get_outbound_last_peer_active(&outbound_tag).await })
    } else {
        return to_errno(leaf::Error::RuntimeManager);
    };

    match result {
        Ok(Some(ts)) => {
            unsafe { *timestamp_s = ts };
            ERR_OK
        }
        Ok(None) => ERR_NO_DATA,
        Err(e) => to_errno(e),
    }
}

/// Gets seconds since last active time for an outbound.
///
/// This returns the number of seconds elapsed since the last successful
/// connection through the specified outbound.
///
/// @param rt_id The ID of the leaf instance.
/// @param outbound_tag The tag of the outbound.
/// @param since_s Pointer to store the seconds since last active.
/// @return Returns ERR_OK on success, ERR_NO_DATA if no active time found, error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn leaf_get_since_last_active(
    rt_id: u16,
    outbound_tag: *const c_char,
    since_s: *mut u32,
) -> i32 {
    let outbound_tag = if let Ok(tag) = unsafe { CStr::from_ptr(outbound_tag).to_str() } {
        tag.to_string()
    } else {
        return ERR_CONFIG_PATH;
    };

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    let result = if let Some(m) = manager {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move { m.get_outbound_last_peer_active(&outbound_tag).await })
    } else {
        return to_errno(leaf::Error::RuntimeManager);
    };

    match result {
        Ok(Some(ts)) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            let since = now.saturating_sub(ts);
            unsafe { *since_s = since };
            ERR_OK
        }
        Ok(None) => ERR_NO_DATA,
        Err(e) => to_errno(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::time::Duration;

    /// `leaf_kiri_status` writes the JSON only into a buffer it fits in
    /// (NUL-terminated) and always returns its length.
    #[test]
    fn kiri_status_fills_a_buffer_it_fits_in() {
        let n = unsafe { leaf_kiri_status(999, std::ptr::null_mut(), 0) };
        assert!(n > 20, "{n}");
        let mut small = vec![b'x' as c_char; n as usize];
        assert_eq!(
            unsafe { leaf_kiri_status(999, small.as_mut_ptr(), small.len()) },
            n
        );
        assert_eq!(small[0], 0, "too small: left empty");
        let mut buf = vec![b'x' as c_char; n as usize + 1];
        assert_eq!(
            unsafe { leaf_kiri_status(999, buf.as_mut_ptr(), buf.len()) },
            n
        );
        let json = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(json.len(), n as usize);
        assert!(
            json.starts_with("{\"version\":1,") && json.contains("\"outbounds\":[]"),
            "{json}"
        );
    }

    /// The kiri bridge controls reach the runtime the C API started; the
    /// bridge itself (pause unlinks, resume relinks) is tested end to end in
    /// kiri's `leaf-e2e/tests/bridge.rs` through the same leaf functions.
    #[test]
    fn kiri_bridge_controls_follow_the_runtime() {
        const ID: u16 = 4711;
        assert!(!leaf_kiri_bridge_pause(ID), "no runtime yet");
        assert!(!leaf_kiri_bridge_running(ID));
        assert!(
            !leaf_kiri_bridge_activity_log(ID, true),
            "kept: no runtime yet"
        );
        #[cfg(feature = "kiri")]
        assert!(leaf::proxy::kiri::prefs::Prefs::of(ID).bridge_activity_log());

        let conf =
            CString::new("[General]\nloglevel = error\n\n[Proxy]\nDirect = direct\n").unwrap();
        let t =
            std::thread::spawn(move || unsafe { leaf_run_with_config_string(ID, conf.as_ptr()) });
        for _ in 0..200 {
            if leaf::is_running(ID) {
                break;
            }
            assert!(!t.is_finished(), "leaf exited at start");
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(leaf::is_running(ID), "leaf did not start");

        assert_eq!(leaf_kiri_bridge_pause(ID), cfg!(feature = "kiri"));
        assert_eq!(leaf_kiri_bridge_resume(ID), cfg!(feature = "kiri"));
        assert!(!leaf_kiri_bridge_running(ID), "no bridge in this config");
        assert_eq!(
            leaf_kiri_bridge_activity_log(ID, false),
            cfg!(feature = "kiri")
        );

        assert!(leaf_shutdown(ID));
        assert_eq!(t.join().unwrap(), ERR_OK);
        assert!(!leaf_kiri_bridge_resume(ID), "no runtime after shutdown");
    }

    /// The user's switches: kept before the start (false: no runtime yet),
    /// applied while running (true), bad values refused; the bridge state
    /// says why the bridge is off.
    #[test]
    fn kiri_user_prefs_and_bridge_state() {
        const ID: u16 = 4712;
        let kiri = cfg!(feature = "kiri");
        assert!(
            !leaf_kiri_set_user_prefs(ID, LEAF_KIRI_PREF_ON, 7),
            "bad value"
        );
        assert!(!leaf_kiri_set_user_prefs(
            ID,
            LEAF_KIRI_PREF_ON,
            LEAF_KIRI_PREF_OFF
        ));
        let want = |running: i32| {
            if kiri {
                running
            } else {
                LEAF_KIRI_BRIDGE_NOT_BUILT
            }
        };
        assert_eq!(
            leaf_kiri_bridge_state(ID),
            want(LEAF_KIRI_BRIDGE_NO_RUNTIME)
        );
        #[cfg(feature = "kiri")]
        assert_eq!(leaf::kiri_user_prefs(ID), (true, Some(false)), "kept");

        let conf = CString::new(
            "[General]
loglevel = error

[Proxy]
Direct = direct
",
        )
        .unwrap();
        let t =
            std::thread::spawn(move || unsafe { leaf_run_with_config_string(ID, conf.as_ptr()) });
        for _ in 0..200 {
            if leaf::is_running(ID) {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(
            leaf_kiri_bridge_state(ID),
            want(LEAF_KIRI_BRIDGE_OFF_BY_USER)
        );
        assert_eq!(
            leaf_kiri_set_user_prefs(ID, LEAF_KIRI_PREF_OFF, LEAF_KIRI_PREF_DEFAULT),
            kiri
        );
        assert_eq!(
            leaf_kiri_bridge_state(ID),
            want(LEAF_KIRI_BRIDGE_OFF_BY_SERVER_DEFAULT)
        );
        assert_eq!(
            leaf_kiri_set_user_prefs(ID, LEAF_KIRI_PREF_ON, LEAF_KIRI_PREF_ON),
            kiri
        );
        // On, but this conf has no [Kiri] section to run it with.
        assert_eq!(
            leaf_kiri_bridge_state(ID),
            want(LEAF_KIRI_BRIDGE_NOT_CONFIGURED)
        );
        assert!(!leaf_kiri_bridge_running(ID));
        assert!(leaf_shutdown(ID));
        assert_eq!(t.join().unwrap(), ERR_OK);
    }
}
