use std::process::exit;

// #[cfg(not(target_env = "msvc"))]
// use jemallocator::Jemalloc;
//
// #[cfg(not(target_env = "msvc"))]
// #[global_allocator]
// static GLOBAL: Jemalloc = Jemalloc;

use clap::{App, Arg};
use log::*;

use leaf::config;

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

fn main() {
    let matches = App::new("leaf")
        .version(VERSION.unwrap())
        .about("A lightweight and fast proxy utility.")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .about("The configuration file.")
                .takes_value(true)
                .default_value("config.conf"),
        )
        .get_matches();

    let path = matches.value_of("config").unwrap();

    let config = match leaf::config::from_file(path) {
        Ok(v) => v,
        Err(err) => {
            println!("create config failed: {}", err);
            exit(1);
        }
    };

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
    let console_output = fern::Output::stdout("\n");
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

    rt.block_on(async move {
        tokio::select! {
            _ = futures::future::join_all(runners) => (),
            _ = tokio::signal::ctrl_c() => {
                warn!("ctrl-c received, exit");
            },
        }
    });
}
