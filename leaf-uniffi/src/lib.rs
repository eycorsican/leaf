uniffi::setup_scaffolding!();

#[derive(uniffi::Enum)]
pub enum ErrEnum {
    ErrOk = 0,
    ErrConfigPath = 1,
    ErrConfig = 2,
    ErrIo = 3,
    ErrWatcher = 4,
    ErrAsyncChannelSend = 5,
    ErrSyncChannelRecv = 6,
    ErrRuntimeManager = 7,
    ErrNoConfigFile = 8,
}

fn to_errno(e: leaf::Error) -> ErrEnum {
    match e {
        leaf::Error::Config(..) => ErrEnum::ErrConfig,
        leaf::Error::NoConfigFile => ErrEnum::ErrNoConfigFile,
        leaf::Error::Io(..) => ErrEnum::ErrIo,
        #[cfg(feature = "auto-reload")]
        leaf::Error::Watcher(..) => ErrEnum::ErrWatcher,
        leaf::Error::AsyncChannelSend(..) => ErrEnum::ErrAsyncChannelSend,
        leaf::Error::SyncChannelRecv(..) => ErrEnum::ErrSyncChannelRecv,
        leaf::Error::RuntimeManager => ErrEnum::ErrRuntimeManager,
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
#[uniffi::export]
pub fn leaf_run_with_options(
    rt_id: u16,
    config_path: String,
    auto_reload: bool, // requires this parameter anyway
    multi_thread: bool,
    auto_threads: bool,
    threads: i32,
    stack_size: i32,
) -> ErrEnum {
    if let Err(e) = leaf::util::run_with_options(
        rt_id,
        config_path,
        #[cfg(feature = "auto-reload")]
        auto_reload,
        multi_thread,
        auto_threads,
        threads as usize,
        stack_size as usize,
    ) {
        return to_errno(e);
    }
    ErrEnum::ErrOk
}

/// Starts leaf with a single-threaded runtime, on a successful start this function
/// blocks the current thread.
///
/// @param rt_id A unique ID to associate this leaf instance, this is required when
///              calling subsequent FFI functions, e.g. reload, shutdown.
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @return ERR_OK on finish running, any other errors means a startup failure.
#[uniffi::export]
pub fn leaf_run(rt_id: u16, config_path: String) -> ErrEnum {
    let opts = leaf::StartOptions {
        config: leaf::Config::File(config_path.to_string()),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: leaf::RuntimeOption::SingleThread,
    };
    if let Err(e) = leaf::start(rt_id, opts) {
        return to_errno(e);
    }
    ErrEnum::ErrOk
}

#[uniffi::export]
pub fn leaf_run_with_config_string(rt_id: u16, config: String) -> ErrEnum {
    let opts = leaf::StartOptions {
        config: leaf::Config::Str(config.to_string()),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: leaf::RuntimeOption::SingleThread,
    };
    if let Err(e) = leaf::start(rt_id, opts) {
        return to_errno(e);
    }
    ErrEnum::ErrOk
}

/// Reloads DNS servers, outbounds and routing rules from the config file.
///
/// @param rt_id The ID of the leaf instance to reload.
///
/// @return Returns ERR_OK on success.
#[uniffi::export]
pub fn leaf_reload(rt_id: u16) -> ErrEnum {
    if let Err(e) = leaf::reload(rt_id) {
        return to_errno(e);
    }
    ErrEnum::ErrOk
}

/// Shuts down leaf.
///
/// @param rt_id The ID of the leaf instance to reload.
///
/// @return Returns true on success, false otherwise.
#[uniffi::export]
pub fn leaf_shutdown(rt_id: u16) -> bool {
    leaf::shutdown(rt_id)
}

/// Tests the configuration.
///
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @return Returns ERR_OK on success, i.e no syntax error.
#[uniffi::export]
pub fn leaf_test_config(config_path: String) -> ErrEnum {
    if let Err(e) = leaf::test_config(config_path.as_str()) {
        return to_errno(e);
    }
    ErrEnum::ErrOk
}
