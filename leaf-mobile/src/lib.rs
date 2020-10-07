use std::{ffi::CStr, os::raw::c_char, time};

use bytes::BytesMut;
use log::*;

use leaf::config;

pub mod ios;

mod logger;
use logger::ConsoleWriter;

use ios::os_proc_available_memory;

#[no_mangle]
pub extern "C" fn run_leaf(path: *const c_char) {
    if let Ok(path) = unsafe { CStr::from_ptr(path).to_str() } {
        let config = leaf::config::from_file(path).expect("read config failed");

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
        let console_output = fern::Output::writer(Box::new(ConsoleWriter(BytesMut::new())), "\n");
        logger = logger.chain(console_output);
        if let Some(log) = config.log.as_ref() {
            match log.output {
                config::Log_Output::CONSOLE => {
                    // console output already applied
                }
                config::Log_Output::FILE => {
                    let f = fern::log_file(&log.output_file).expect("open log file failed");
                    let file_output = fern::Output::file(f, "\n");
                    logger = logger.chain(file_output);
                }
            }
        }
        leaf::common::log::apply_logger(logger);

        let mut rt = tokio::runtime::Builder::new()
            .basic_scheduler()
            .enable_all()
            .build()
            .unwrap();

        let runners = match leaf::util::create_runners(config) {
            Ok(v) => v,
            Err(e) => {
                error!("create runners fialed: {}", e);
                return;
            }
        };

        let monit_mem = Box::pin(async {
            loop {
                let n = unsafe { os_proc_available_memory() };
                debug!("{} bytes memory available", n);
                tokio::time::delay_for(time::Duration::from_secs(1)).await;
            }
        });

        rt.block_on(async move {
            tokio::select! {
                _ = futures::future::join_all(runners) => (),
                _ = monit_mem  => (),
            }
        });
    } else {
        error!("invalid config path");
        return;
    }
}
