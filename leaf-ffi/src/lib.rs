use std::{ffi::CStr, os::raw::c_char};

use leaf::config;

#[cfg(any(target_os = "ios", target_os = "android"))]
pub mod bindings;

#[cfg(any(target_os = "ios", target_os = "android"))]
mod logger;

// This function is only available on iOS 13.0+, useful for debugging
// memory issues on iOS.
// use ios::os_proc_available_memory;

fn run(rt: &tokio::runtime::Runtime, config: leaf::config::Config) {
    let loglevel = if let Some(log) = config.log.as_ref() {
        match log.level {
            config::Log_Level::TRACE => log::LevelFilter::Trace,
            config::Log_Level::DEBUG => log::LevelFilter::Debug,
            config::Log_Level::INFO => log::LevelFilter::Info,
            config::Log_Level::WARN => log::LevelFilter::Warn,
            config::Log_Level::ERROR => log::LevelFilter::Error,
        }
    } else {
        log::LevelFilter::Info
    };
    let mut logger = leaf::common::log::setup_logger(loglevel);
    if let Some(log) = config.log.as_ref() {
        match log.output {
            config::Log_Output::CONSOLE => {
                #[cfg(any(target_os = "ios", target_os = "android"))]
                {
                    let console_output =
                        fern::Output::writer(Box::new(logger::ConsoleWriter::default()), "\n");
                    logger = logger.chain(console_output);
                }
                #[cfg(not(any(target_os = "ios", target_os = "android")))]
                {
                    logger = logger.chain(fern::Output::stdout("\n"));
                }
            }
            config::Log_Output::FILE => {
                let f = fern::log_file(&log.output_file).expect("open log file failed");
                let file_output = fern::Output::file(f, "\n");
                logger = logger.chain(file_output);
            }
        }
    }
    leaf::common::log::apply_logger(logger);

    let runners = match leaf::util::create_runners(config) {
        Ok(v) => v,
        Err(e) => {
            log::error!("create runners fialed: {}", e);
            return;
        }
    };

    rt.block_on(futures::future::join_all(runners));
}

// TODO Return meaningful error codes.
#[cfg(not(target_os = "android"))]
#[no_mangle]
pub extern "C" fn run_leaf(config_path: *const c_char) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    if let Ok(config) = unsafe { CStr::from_ptr(config_path).to_str() }
        .map_err(Into::into)
        .and_then(leaf::config::from_file)
    {
        run(&rt, config);
    } else {
        log::error!("invalid config path or config file");
        return;
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn run_leaf(config_path: *const c_char, protect_path: *const c_char) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    if let Ok(protect_path) = unsafe { CStr::from_ptr(protect_path).to_str() } {
        rt.block_on(leaf::proxy::set_socket_protect_path(
            protect_path.to_string(),
        ));
    }
    if let Ok(config) = unsafe { CStr::from_ptr(config_path).to_str() }
        .map_err(Into::into)
        .and_then(leaf::config::from_file)
    {
        run(&rt, config);
    } else {
        log::error!("invalid config path or config file");
        return;
    }
}
