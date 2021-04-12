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
    let mut app = App::new("leaf");

    #[cfg(feature = "auto-reload")]
    {
        app = app.arg(
            Arg::new("auto-reload")
                .long("auto-reload")
                .about("Enables auto reloading when config file changes.")
                .takes_value(false),
        );
    }

    app = app.arg(
        Arg::new("config")
            .short('c')
            .long("config")
            .value_name("FILE")
            .about("The configuration file")
            .takes_value(true)
            .default_value("config.conf"),
    );

    let matches = app
        .version(get_version_string().as_str())
        .about("A lightweight and fast proxy utility.")
        .arg(
            Arg::new("single-thread")
                .long("single-thread")
                .about("Runs in a single thread.")
                .takes_value(false),
        )
        .arg(
            Arg::new("threads")
                .long("threads")
                .value_name("N")
                .about("Sets the number of runtime worker threads.")
                .takes_value(true)
                .default_value("auto"),
        )
        .arg(
            Arg::new("thread-stack-size")
                .long("thread-stack-size")
                .value_name("BYTES")
                .about("Sets the stack size of runtime worker threads.")
                .takes_value(true)
                .default_value(&default_thread_stack_size().to_string()),
        )
        .arg(
            Arg::new("test")
                .short('T')
                .long("test")
                .about("Tests the configuration and exit.")
                .takes_value(false),
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

    let config_path = matches.value_of("config").unwrap();

    if matches.is_present("test") {
        if let Err(e) = leaf::test_config(&config_path) {
            println!("{}", e);
            exit(1);
        } else {
            println!("ok");
            exit(0);
        }
    }

    if let Some(tag) = matches.value_of("test-outbound") {
        let config = leaf::config::from_file(&config_path).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(leaf::util::test_outbound(&tag, &config));
        exit(0);
    }

    #[cfg(feature = "auto-reload")]
    let auto_reload = matches.is_present("auto-reload");

    let threads = matches.value_of("threads").unwrap();
    let thread_stack_size = matches
        .value_of("thread-stack-size")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let multi_thread = !matches.is_present("single-thread");
    let auto_threads = threads.parse::<usize>().map(|_| false).unwrap_or(true);
    let threads = threads.parse::<usize>().unwrap_or(1);

    if let Err(e) = leaf::util::run_with_options(
        0,
        config_path.to_string(),
        #[cfg(feature = "auto-reload")]
        auto_reload,
        multi_thread,
        auto_threads,
        threads,
        thread_stack_size,
    ) {
        println!("start leaf failed: {}", e);
        exit(1);
    }
}
