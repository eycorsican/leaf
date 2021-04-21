use std::process::exit;

use argh::FromArgs;

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

#[derive(FromArgs)]
/// A lightweight and fast proxy utility
struct Args {
    /// the configuration file
    #[argh(option, short = 'c', default = "String::from(\"config.conf\")")]
    config: String,

    /// enables auto reloading when config file changes
    #[cfg(feature = "auto-reload")]
    #[argh(switch)]
    auto_reload: bool,

    /// runs in a single thread
    #[argh(switch)]
    single_thread: bool,

    /// sets the stack size of runtime worker threads
    #[argh(option, default = "default_thread_stack_size()")]
    thread_stack_size: usize,

    /// tests the configuration and exit
    #[argh(switch, short = 'T')]
    test: bool,

    /// tests the connectivity of the specified outbound
    #[argh(option, short = 't')]
    test_outbound: Option<String>,

    /// prints version
    #[argh(switch, short = 'V')]
    version: bool,
}

fn main() {
    let args: Args = argh::from_env();

    if args.version {
        println!("{}", get_version_string());
        exit(0);
    }

    if args.test {
        if let Err(e) = leaf::test_config(&args.config) {
            println!("{}", e);
            exit(1);
        } else {
            println!("ok");
            exit(0);
        }
    }

    if let Some(tag) = args.test_outbound {
        let config = leaf::config::from_file(&args.config).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(leaf::util::test_outbound(&tag, &config));
        exit(0);
    }

    if let Err(e) = leaf::util::run_with_options(
        0,
        args.config,
        #[cfg(feature = "auto-reload")]
        args.auto_reload,
        !args.single_thread,
        true,
        0, // auto_threads is true, this value no longer matters
        args.thread_stack_size,
    ) {
        println!("start leaf failed: {}", e);
        exit(1);
    }
}
