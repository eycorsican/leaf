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
/// At least one plugin the config names by url could not be downloaded.
pub const ERR_PLUGIN_FETCH: i32 = 10;
/// The caller cancelled the operation.
pub const ERR_CANCELLED: i32 = 11;
/// This build does not include what the call needs.
pub const ERR_UNSUPPORTED: i32 = 12;

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
        leaf::Error::PluginFetch(..) => ERR_PLUGIN_FETCH,
        leaf::Error::Cancelled => ERR_CANCELLED,
    }
}

#[cfg(feature = "plugin-socks5-c")]
extern "C" {
    // `socks5.c` compiled by build.rs with LEAF_PLUGIN_STATIC_NAME=socks5_c.
    fn leaf_plugin_socks5_c_get_descriptor() -> *const leaf::app::outbound::plugin::PluginDescriptor;
}

/// Registers the plugins this library was built with -- the `plugin-*`
/// features -- as builtins, once. Every entry point that reads a config calls
/// it, so an app never has to.
fn register_compiled_in_plugins() {
    #[cfg(feature = "plugin")]
    {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            #[allow(unused_variables)]
            let register =
                |name: &str, get_descriptor: leaf::app::outbound::plugin::PluginDescriptorFn| {
                    // Safety: each of these is a plugin linked into this library,
                    // whose descriptor function is the one it exports when built
                    // as a library of its own.
                    if let Err(e) = unsafe {
                        leaf::app::outbound::plugin::register_builtin_plugin(name, get_descriptor)
                    } {
                        eprintln!("leaf: registering builtin plugin [{}] failed: {}", name, e);
                    }
                };
            #[cfg(feature = "plugin-socks5-c")]
            register("socks5-c", leaf_plugin_socks5_c_get_descriptor);
        });
    }
}

/// Registers a plugin linked into the app as a builtin, under the name a
/// config's `builtin=` refers to.
///
/// For plugins the app links itself; the ones this library was built with
/// (its `plugin-*` features) are registered already. Call it before
/// `leaf_run_*`. Registering the same function under the same name again is
/// allowed; a different function under a name already taken is not.
///
/// @param name Letters, digits, '-', '_' and '.'.
/// @param get_descriptor The plugin's descriptor function: its
///                       `leaf_plugin_get_descriptor`, or, for a C plugin
///                       built with LEAF_PLUGIN_STATIC_NAME=x,
///                       `leaf_plugin_x_get_descriptor`. It is trusted as a
///                       loaded plugin library is; the descriptor it returns
///                       is validated when an outbound first uses it.
/// @return ERR_OK; ERR_CONFIG for a bad name, a NULL function, or a name
///         registered to a different function; ERR_UNSUPPORTED for a build
///         without plugin support.
#[no_mangle]
#[allow(unused_variables)]
pub unsafe extern "C" fn leaf_register_plugin(
    name: *const c_char,
    get_descriptor: Option<unsafe extern "C" fn() -> *const std::ffi::c_void>,
) -> i32 {
    #[cfg(not(feature = "plugin"))]
    {
        ERR_UNSUPPORTED
    }
    #[cfg(feature = "plugin")]
    {
        let (Some(get_descriptor), false) = (get_descriptor, name.is_null()) else {
            return ERR_CONFIG;
        };
        let Ok(name) = (unsafe { CStr::from_ptr(name).to_str() }) else {
            return ERR_CONFIG;
        };
        register_compiled_in_plugins();
        // Safety: the same function type with the descriptor pointer spelled
        // `void *` for the C header's sake; the pointee is only read through
        // the host's validation.
        let get_descriptor: leaf::app::outbound::plugin::PluginDescriptorFn =
            unsafe { std::mem::transmute(get_descriptor) };
        match unsafe { leaf::app::outbound::plugin::register_builtin_plugin(name, get_descriptor) }
        {
            Ok(()) => ERR_OK,
            Err(_) => ERR_CONFIG,
        }
    }
}

/// The plugin is not in the cache and will be downloaded.
pub const LEAF_FETCH_QUEUED: i32 = 0;
/// The plugin is already in the cache. Terminal.
pub const LEAF_FETCH_CACHED: i32 = 1;
/// The server answered; `total` is known from here on if the server said.
pub const LEAF_FETCH_STARTED: i32 = 2;
/// Bytes arrived, or a download is still waiting for them; may come before
/// STARTED while the connection is being made.
pub const LEAF_FETCH_PROGRESS: i32 = 3;
/// Downloaded, and the sha256 matched. Terminal.
pub const LEAF_FETCH_DONE: i32 = 4;
/// Could not be fetched; `error` says why. Terminal.
pub const LEAF_FETCH_FAILED: i32 = 5;

/// One event of a `leaf_prefetch_plugins` call.
///
/// Fields may be added at the end in later versions; `size` is
/// `sizeof(LeafFetchEvent)` as this library knows it, so a caller built against
/// an older header can tell which fields are there.
#[repr(C)]
pub struct LeafFetchEvent {
    pub size: u32,
    /// One of the `LEAF_FETCH_*` values.
    pub event: i32,
    /// `0 .. count - 1`, stable for the whole call.
    pub index: u32,
    /// How many distinct plugins the call covers.
    pub count: u32,
    /// The name the config gave the plugin. Valid only during the callback.
    pub plugin: *const c_char,
    pub downloaded: i64,
    /// -1 while unknown.
    pub total: i64,
    /// Summed over the plugins being downloaded; cached ones do not count.
    pub all_downloaded: i64,
    /// -1 while any download's size is unknown.
    pub all_total: i64,
    /// Set only for `LEAF_FETCH_FAILED`. Valid only during the callback.
    pub error: *const c_char,
}

/// Returns false to cancel the whole call.
pub type LeafFetchCallback =
    extern "C" fn(event: *const LeafFetchEvent, context: *mut std::ffi::c_void) -> bool;

/// Downloads the plugins a config names by url and the cache does not yet
/// hold, without starting anything. A later `leaf_run_*` with the same config
/// then finds them in the cache and starts at once.
///
/// The cache directory comes from the `PLUGIN_CACHE_DIR` environment variable,
/// read when this is called. It must be a directory only this app can write
/// to; there is no default.
///
/// Blocks until every plugin is in the cache, has failed, or the callback
/// cancelled. Each plugin first gets a QUEUED or CACHED event, all of them
/// before any download starts; each downloaded one then gets STARTED, some
/// PROGRESS, and exactly one DONE or FAILED. A download that has not finished
/// is reported with PROGRESS about once a second even when nothing has
/// arrived -- including before STARTED, while it is still connecting -- so
/// that the callback can cancel it. After a cancel there are no further events.
///
/// The callback runs on the thread that called this function, never
/// concurrently, and never after it returns.
///
/// @param config The content of the config file.
/// @param timeout_sec Limit for the whole call; 0 for the default of 30 seconds,
///                    or `PLUGIN_FETCH_TIMEOUT` when that is set.
/// @param context Passed back to the callback.
/// @param callback May be NULL.
/// @return ERR_OK when every plugin is in the cache; ERR_PLUGIN_FETCH when at
///         least one could not be fetched, the rest having been; ERR_CANCELLED;
///         ERR_CONFIG for a config that cannot be fetched from as it is, or a
///         missing cache directory; ERR_UNSUPPORTED for a build without
///         plugin downloads.
#[no_mangle]
#[allow(unused_variables)]
pub unsafe extern "C" fn leaf_prefetch_plugins(
    config: *const c_char,
    timeout_sec: u32,
    context: *mut std::ffi::c_void,
    callback: Option<LeafFetchCallback>,
) -> i32 {
    register_compiled_in_plugins();
    #[cfg(not(feature = "plugin-fetch"))]
    {
        ERR_UNSUPPORTED
    }
    #[cfg(feature = "plugin-fetch")]
    {
        use leaf::app::outbound::plugin_fetch::{self, FetchEventKind, FetchOptions};
        use std::ffi::CString;

        let Ok(config) = (unsafe { CStr::from_ptr(config).to_str() }) else {
            return ERR_CONFIG;
        };
        let config = match leaf::config::from_string(config) {
            Ok(config) => config,
            Err(e) => return to_errno(leaf::Error::Config(e)),
        };
        let mut options = match FetchOptions::from_env() {
            Ok(options) => options,
            // Only an error when there is something to download.
            Err(e) => match plugin_fetch::has_url_plugins(&config) {
                Ok(false) => return ERR_OK,
                Ok(true) => return to_errno(leaf::Error::Config(e)),
                Err(e) => return to_errno(leaf::Error::Config(e)),
            },
        };
        if timeout_sec > 0 {
            options.timeout = Some(std::time::Duration::from_secs(timeout_sec as u64));
        }

        let mut on_event = |event: &plugin_fetch::FetchEvent<'_>| -> bool {
            let Some(callback) = callback else {
                return true;
            };
            // Interior NULs cannot come from a conf name or from an error this
            // library wrote, but a C string cannot carry one either way.
            let plugin = CString::new(event.plugin.replace('\0', "")).unwrap_or_default();
            let error = event
                .error
                .map(|e| CString::new(e.replace('\0', "")).unwrap_or_default());
            let raw = LeafFetchEvent {
                size: std::mem::size_of::<LeafFetchEvent>() as u32,
                event: match event.kind {
                    FetchEventKind::Queued => LEAF_FETCH_QUEUED,
                    FetchEventKind::Cached => LEAF_FETCH_CACHED,
                    FetchEventKind::Started => LEAF_FETCH_STARTED,
                    FetchEventKind::Progress => LEAF_FETCH_PROGRESS,
                    FetchEventKind::Done => LEAF_FETCH_DONE,
                    FetchEventKind::Failed => LEAF_FETCH_FAILED,
                },
                index: event.index as u32,
                count: event.count as u32,
                plugin: plugin.as_ptr(),
                downloaded: event.downloaded as i64,
                total: event.total.map_or(-1, |t| t as i64),
                all_downloaded: event.all_downloaded as i64,
                all_total: event.all_total.map_or(-1, |t| t as i64),
                error: error.as_ref().map_or(std::ptr::null(), |e| e.as_ptr()),
            };
            callback(&raw, context)
        };
        match plugin_fetch::prefetch(&config, &options, &mut on_event) {
            Ok(()) => ERR_OK,
            Err(e) => to_errno(e.into()),
        }
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
    register_compiled_in_plugins();
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
    register_compiled_in_plugins();
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
    register_compiled_in_plugins();
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

/// Tests the configuration.
///
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @return Returns ERR_OK on success, i.e no syntax error.
#[no_mangle]
pub unsafe extern "C" fn leaf_test_config(config_path: *const c_char) -> i32 {
    register_compiled_in_plugins();
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
    register_compiled_in_plugins();
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

/// The C side of `leaf_prefetch_plugins`: what reaches a callback, which codes
/// come back, and on which thread. What a download does is the fetch module's
/// business and is tested there and end to end; this is about the translation.
#[cfg(all(test, feature = "plugin-fetch"))]
mod prefetch_tests {
    use super::*;
    use sha2::Digest;
    use std::ffi::{c_void, CString};

    #[derive(Debug, Clone, PartialEq)]
    struct Seen {
        size: u32,
        event: i32,
        index: u32,
        count: u32,
        plugin: String,
        downloaded: i64,
        total: i64,
        all_downloaded: i64,
        all_total: i64,
        error: Option<String>,
    }

    #[derive(Default)]
    struct Recorder {
        seen: Vec<Seen>,
        threads: Vec<std::thread::ThreadId>,
        /// Answer `false` to the first event of this kind.
        cancel_on: Option<i32>,
    }

    extern "C" fn record(event: *const LeafFetchEvent, context: *mut c_void) -> bool {
        let recorder = unsafe { &mut *(context as *mut Recorder) };
        let event = unsafe { &*event };
        let text = |p: *const c_char| unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
        recorder.seen.push(Seen {
            size: event.size,
            event: event.event,
            index: event.index,
            count: event.count,
            plugin: text(event.plugin),
            downloaded: event.downloaded,
            total: event.total,
            all_downloaded: event.all_downloaded,
            all_total: event.all_total,
            error: (!event.error.is_null()).then(|| text(event.error)),
        });
        recorder.threads.push(std::thread::current().id());
        recorder.cancel_on != Some(event.event)
    }

    fn prefetch(config: &str, recorder: &mut Recorder) -> i32 {
        let config = CString::new(config).unwrap();
        unsafe {
            leaf_prefetch_plugins(
                config.as_ptr(),
                5,
                recorder as *mut Recorder as *mut c_void,
                Some(record),
            )
        }
    }

    fn conf(plugins: &str) -> String {
        format!("[Plugin]\n{}\n[Proxy]\nP = plugin, plugin=p\n", plugins)
    }

    /// One test, because the cache directory comes from the environment, which
    /// every test in the process shares.
    #[test]
    fn translates_events_codes_and_threads() {
        let dir = std::env::temp_dir().join(format!("leaf-ffi-prefetch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Without a cache directory: fine when there is nothing to download,
        // a config error when there is.
        std::env::remove_var("PLUGIN_CACHE_DIR");
        let mut recorder = Recorder::default();
        assert_eq!(prefetch(&conf("p = path=./p.dll"), &mut recorder), ERR_OK);
        let sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        // A closed port on loopback: refused at once, never anything else.
        let refused = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let unreachable = conf(&format!(
            "p = url=https://127.0.0.1:{}/p.dll, sha256={}, size=1234",
            refused, sha
        ));
        assert_eq!(prefetch(&unreachable, &mut recorder), ERR_CONFIG);
        assert!(recorder.seen.is_empty());

        std::env::set_var("PLUGIN_CACHE_DIR", &dir);

        // A config it will not download from is a config error, with no event.
        let http = conf(&format!("p = url=http://127.0.0.1/p.dll, sha256={}", sha));
        assert_eq!(prefetch(&http, &mut recorder), ERR_CONFIG);
        assert!(recorder.seen.is_empty());

        // Everything cached: one CACHED event, and ERR_OK.
        let body = b"cached plugin";
        let cached_sha = hex_of(&sha2::Sha256::digest(body));
        std::fs::create_dir_all(dir.join(&cached_sha)).unwrap();
        std::fs::write(dir.join(&cached_sha).join("c.dll"), body).unwrap();
        let cached = conf(&format!(
            "p = url=https://127.0.0.1:{}/c.dll, sha256={}",
            refused, cached_sha
        ));
        let mut recorder = Recorder::default();
        assert_eq!(prefetch(&cached, &mut recorder), ERR_OK);
        assert_eq!(
            recorder.seen,
            vec![Seen {
                size: std::mem::size_of::<LeafFetchEvent>() as u32,
                event: LEAF_FETCH_CACHED,
                index: 0,
                count: 1,
                plugin: "p".to_string(),
                downloaded: 0,
                total: -1,
                all_downloaded: 0,
                all_total: 0,
                error: None,
            }]
        );

        // A download that fails: QUEUED with the declared size, then FAILED
        // with a reason, ERR_PLUGIN_FETCH, all on this thread. Windows takes a
        // couple of seconds to give up on a refused port, and the heartbeat
        // reports the wait as PROGRESS; that is left out here.
        let mut recorder = Recorder::default();
        assert_eq!(prefetch(&unreachable, &mut recorder), ERR_PLUGIN_FETCH);
        let kinds: Vec<i32> = recorder
            .seen
            .iter()
            .map(|s| s.event)
            .filter(|&e| e != LEAF_FETCH_PROGRESS)
            .collect();
        assert_eq!(
            kinds,
            vec![LEAF_FETCH_QUEUED, LEAF_FETCH_FAILED],
            "{:?}",
            recorder.seen
        );
        assert_eq!(recorder.seen[0].total, 1234);
        assert_eq!(recorder.seen[0].all_total, 1234);
        assert!(recorder.seen[0].error.is_none());
        let reason = recorder.seen.last().unwrap().error.as_deref().unwrap();
        assert!(reason.contains("connecting to 127.0.0.1"), "{}", reason);
        let me = std::thread::current().id();
        assert!(recorder.threads.iter().all(|t| *t == me));

        // A callback that answers false: ERR_CANCELLED, and no further events.
        let mut recorder = Recorder {
            cancel_on: Some(LEAF_FETCH_QUEUED),
            ..Default::default()
        };
        assert_eq!(prefetch(&unreachable, &mut recorder), ERR_CANCELLED);
        assert_eq!(recorder.seen.len(), 1);

        // A NULL callback is allowed.
        let config = CString::new(unreachable).unwrap();
        let code = unsafe { leaf_prefetch_plugins(config.as_ptr(), 5, std::ptr::null_mut(), None) };
        assert_eq!(code, ERR_PLUGIN_FETCH);

        std::env::remove_var("PLUGIN_CACHE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Plugins linked into the library: that each one this build includes is
/// registered, and that its descriptor -- reached through the static link
/// rather than a library -- passes the host's validation and makes handlers.
#[cfg(all(test, feature = "plugin"))]
mod builtin_tests {
    use super::*;
    use leaf::app::outbound::plugin::{
        builtin_plugin_names, is_builtin_plugin, ExternalHandlers, PluginOutboundConfig,
    };
    use std::ffi::{c_void, CString};

    unsafe extern "C" fn no_descriptor() -> *const c_void {
        std::ptr::null()
    }

    unsafe extern "C" fn another_no_descriptor() -> *const c_void {
        // Different from the one above, so that the two cannot be folded into
        // one function and compare equal.
        std::ptr::dangling::<c_void>()
    }

    fn register(name: &str, f: Option<unsafe extern "C" fn() -> *const c_void>) -> i32 {
        let name = CString::new(name).unwrap();
        unsafe { leaf_register_plugin(name.as_ptr(), f) }
    }

    #[test]
    fn leaf_register_plugin_codes() {
        assert_eq!(register("app-plugin", Some(no_descriptor)), ERR_OK);
        assert_eq!(register("app-plugin", Some(no_descriptor)), ERR_OK);
        assert_eq!(
            register("app-plugin", Some(another_no_descriptor)),
            ERR_CONFIG
        );
        assert_eq!(register("not a name", Some(no_descriptor)), ERR_CONFIG);
        assert_eq!(register("app-null", None), ERR_CONFIG);
        assert_eq!(
            unsafe { leaf_register_plugin(std::ptr::null(), Some(no_descriptor)) },
            ERR_CONFIG
        );
        assert!(is_builtin_plugin("app-plugin"));
    }

    fn endpoint() -> PluginOutboundConfig {
        PluginOutboundConfig {
            host: Some("127.0.0.1".to_string()),
            port: Some(1080),
            ..Default::default()
        }
    }

    fn loads(name: &str, config: PluginOutboundConfig, stream: bool, datagram: bool) {
        register_compiled_in_plugins();
        assert!(
            is_builtin_plugin(name),
            "[{}] is not registered; registered: {:?}",
            name,
            builtin_plugin_names()
        );
        let mut handlers = ExternalHandlers::new();
        unsafe { handlers.new_builtin_handler(name, "tag", config) }
            .unwrap_or_else(|e| panic!("builtin [{}] did not load: {}", name, e));
        assert_eq!(
            handlers.get_stream_handler("tag").is_some(),
            stream,
            "{}",
            name
        );
        assert_eq!(
            handlers.get_datagram_handler("tag").is_some(),
            datagram,
            "{}",
            name
        );
    }

    #[cfg(feature = "plugin-socks5-c")]
    #[test]
    fn socks5_c_is_built_in() {
        loads("socks5-c", endpoint(), true, false);
    }
}
