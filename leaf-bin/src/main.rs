use std::process::exit;

use clap::{App, Arg};

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
const COMMIT_HASH: Option<&'static str> = option_env!("CFG_COMMIT_HASH");
const COMMIT_DATE: Option<&'static str> = option_env!("CFG_COMMIT_DATE");

fn get_version_string() -> String {
    match (VERSION, COMMIT_HASH, COMMIT_DATE) {
        (Some(ver), None, None) => ver.to_string(),
        (Some(ver), Some(hash), Some(date)) => format!("{} ({} - {})", ver, hash, date),
        _ => "unknown".to_string(),
    }
}

#[cfg(debug_assertions)]
fn default_thread_stack_size() -> usize {
    2 * 1024 * 1024
}

#[cfg(not(debug_assertions))]
fn default_thread_stack_size() -> usize {
    128 * 1024
}

fn main() {
    let matches = App::new("leaf")
        .version(get_version_string().as_str())
        .about("A lightweight and fast proxy utility.")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .about("The configuration file")
                .takes_value(true)
                .default_value("config.conf"),
        )
        .arg(
            Arg::new("threads")
                .long("threads")
                .value_name("N")
                .about("Sets the number of runtime threads.")
                .takes_value(true)
                .default_value("auto"),
        )
        .arg(
            Arg::new("thread-stack-size")
                .long("thread-stack-size")
                .value_name("BYTES")
                .about("Sets the stack size of runtime threads.")
                .takes_value(true)
                .default_value(&default_thread_stack_size().to_string()),
        )
        .arg(
            Arg::new("test-outbound")
                .short('t')
                .long("test-outbound")
                .value_name("TAG")
                .about("Tests the availability of a specified outbound")
                .takes_value(true),
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

    let rt = {
        let threads = matches.value_of("threads").unwrap();
        let stack_size = matches
            .value_of("thread-stack-size")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        if threads == "auto" {
            tokio::runtime::Builder::new_multi_thread()
                .thread_stack_size(stack_size)
                .enable_all()
                .build()
                .unwrap()
        } else if let Ok(n) = threads.parse::<usize>() {
            if n > 1 {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(n)
                    .thread_stack_size(stack_size)
                    .enable_all()
                    .build()
                    .unwrap()
            } else {
                tokio::runtime::Builder::new_current_thread()
                    .thread_stack_size(stack_size)
                    .enable_all()
                    .build()
                    .unwrap()
            }
        } else {
            println!("invalid number of threads");
            exit(1);
        }
    };

    if let Some(tag) = matches.value_of("test-outbound") {
        rt.block_on(leaf::util::test_outbound(&tag, &config));
        exit(1);
    }

    let runners = match leaf::util::prepare(config) {
        Ok(v) => v,
        Err(e) => {
            println!("prepare failed: {}", e);
            exit(1);
        }
    };

    rt.block_on(async move {
        tokio::select! {
            _ = futures::future::join_all(runners) => (),
            _ = tokio::signal::ctrl_c() => {
                println!("ctrl-c received, exit");
            },
        }
    });
}
