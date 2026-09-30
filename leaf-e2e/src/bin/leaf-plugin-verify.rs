//! A hands-on tool for checking plugin downloads and builtin plugins by hand.
//!
//! `docs/plugin-verification.md` walks through it step by step. It exists
//! because leaf, by design, trusts only the public CAs for a plugin download
//! -- neither a config nor the C API can add one -- so a local https server
//! with a certificate of its own cannot be tried against `leaf` itself. This
//! tool can trust such a server, because it links leaf as a library and hands
//! the CA to the same code a client runs. It is a development tool and is
//! never shipped in a client.
//!
//! ```text
//! leaf-plugin-verify serve    host plugin files over local https, with faults on request
//! leaf-plugin-verify render   fill a plugin's url, sha256 and size into a conf template
//! leaf-plugin-verify prefetch download what a conf names, printing the events an app sees
//! leaf-plugin-verify run      start leaf from a conf, optionally with builtins and a local CA
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use argh::FromArgs;
use leaf::app::outbound::plugin::{self as host, PluginDescriptorFn};
use leaf::app::outbound::plugin_fetch::{self, FetchError, FetchOptions};
use leaf_e2e::plugin_server::{Gate, PluginServer, Route};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};

/// Exit codes, the same numbers the C API returns.
const EXIT_CONFIG: i32 = 2;
const EXIT_FETCH_FAILED: i32 = 10;
const EXIT_CANCELLED: i32 = 11;

#[derive(FromArgs)]
/// Check plugin downloads and builtin plugins by hand.
struct Args {
    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Serve(Serve),
    Render(Render),
    Prefetch(Prefetch),
    Run(Run),
}

#[derive(FromArgs)]
/// Serve the plugin libraries in a directory over https on 127.0.0.1, with a
/// certificate from a CA made for this run.
#[argh(subcommand, name = "serve")]
struct Serve {
    /// the files to serve, each at /<file name>
    #[argh(positional)]
    files: Vec<PathBuf>,
    /// the port to listen on
    #[argh(option, default = "8443")]
    port: u16,
    /// where to write the CA certificate, as PEM, for `--ca` elsewhere
    #[argh(option, default = "PathBuf::from(\"plugin-ca.pem\")")]
    ca_out: PathBuf,
    /// how to misbehave: ok, slow (visible progress), corrupt (wrong bytes),
    /// stall (half, then nothing), missing (404)
    #[argh(option, default = "String::from(\"ok\")")]
    mode: String,
}

#[derive(FromArgs)]
/// Write a conf from a template, replacing each {{name}} with
/// `url=<base>/<file name>, sha256=<digest>, size=<bytes>` for that file.
#[argh(subcommand, name = "render")]
struct Render {
    /// the template to read
    #[argh(positional)]
    template: PathBuf,
    /// the conf to write
    #[argh(positional)]
    out: PathBuf,
    /// name=path of a plugin file; repeat for more
    #[argh(option)]
    file: Vec<String>,
    /// the url the files are served under
    #[argh(option, default = "String::from(\"https://127.0.0.1:8443\")")]
    base_url: String,
}

#[derive(FromArgs)]
/// Download what a conf names by url into a cache, printing every event the C
/// API's callback would receive. Exits 0, 10 (some failed), 11 (cancelled) or
/// 2 (config), as leaf_prefetch_plugins returns.
#[argh(subcommand, name = "prefetch")]
struct Prefetch {
    /// the conf file
    #[argh(option, short = 'c')]
    config: PathBuf,
    /// the cache directory
    #[argh(option)]
    cache_dir: PathBuf,
    /// a CA certificate (PEM) to trust besides the public ones
    #[argh(option)]
    ca: Option<PathBuf>,
    /// limit for the whole prefetch, in seconds
    #[argh(option, default = "30")]
    timeout: u64,
    /// how many downloads at once
    #[argh(option, default = "4")]
    concurrency: usize,
    /// cancel, as an app's callback would, once this many bytes have arrived
    #[argh(option)]
    cancel_after: Option<u64>,
}

#[derive(FromArgs)]
/// Start leaf from a conf, as a client would, and run until interrupted.
#[argh(subcommand, name = "run")]
struct Run {
    /// the conf file
    #[argh(option, short = 'c')]
    config: PathBuf,
    /// the cache directory for plugins named by url
    #[argh(option)]
    cache_dir: Option<PathBuf>,
    /// a CA certificate (PEM) to trust besides the public ones
    #[argh(option)]
    ca: Option<PathBuf>,
    /// name=path: register the plugin library at path as the builtin name,
    /// standing in for a plugin linked into a mobile app; repeat for more
    #[argh(option)]
    builtin: Vec<String>,
}

fn main() {
    let args: Args = argh::from_env();
    let outcome = match args.command {
        Command::Serve(serve) => runtime().and_then(|rt| rt.block_on(run_serve(serve))),
        Command::Render(render) => run_render(render),
        Command::Prefetch(prefetch) => run_prefetch(prefetch),
        Command::Run(run) => run_leaf(run),
    };
    match outcome {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {:#}", err);
            std::process::exit(1);
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building a runtime")
}

fn sha256_of(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("[{}] has no file name", path.display()))
}

fn mib(bytes: u64) -> String {
    format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
}

// ---------------------------------------------------------------------------

async fn run_serve(args: Serve) -> Result<i32> {
    if args.files.is_empty() {
        bail!("name at least one file to serve");
    }
    let server = PluginServer::start_on(args.port).await?;
    server.verbose();
    std::fs::write(&args.ca_out, server.ca_pem())
        .with_context(|| format!("writing {}", args.ca_out.display()))?;

    println!(
        "serving on https://127.0.0.1:{} (mode: {})",
        args.port, args.mode
    );
    println!("CA certificate: {}", args.ca_out.display());
    println!();
    for path in &args.files {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let name = file_name(path)?;
        let route_path = format!("/{}", name);
        println!("  {}", server.url(&route_path));
        println!("    sha256={}, size={}", sha256_of(&bytes), bytes.len());
        let route = match args.mode.as_str() {
            "ok" => Route::ok(bytes),
            // 16 KiB every 50 ms: about 320 KiB/s, slow enough to watch and to
            // cancel part-way.
            "slow" => Route::ok(bytes).pace(Duration::from_millis(50)),
            "corrupt" => {
                let mut bytes = bytes;
                if let Some(last) = bytes.last_mut() {
                    *last ^= 0xff;
                }
                Route::ok(bytes)
            }
            "stall" => {
                let half = bytes.len() / 2;
                // Never opened: half the file, and then nothing.
                Route::ok(bytes).gate(Gate::after(half))
            }
            "missing" => Route::status(404),
            other => bail!(
                "unknown mode [{}]; use ok, slow, corrupt, stall or missing",
                other
            ),
        };
        server.route(&route_path, route);
    }
    println!();
    println!("requests (Ctrl-C to stop):");
    tokio::signal::ctrl_c().await?;
    Ok(0)
}

// ---------------------------------------------------------------------------

fn run_render(args: Render) -> Result<i32> {
    let mut text = std::fs::read_to_string(&args.template)
        .with_context(|| format!("reading {}", args.template.display()))?;
    for spec in &args.file {
        let (name, path) = spec
            .split_once('=')
            .ok_or_else(|| anyhow!("--file [{}] is not name=path", spec))?;
        let path = Path::new(path);
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let value = format!(
            "url={}/{}, sha256={}, size={}",
            args.base_url.trim_end_matches('/'),
            file_name(path)?,
            sha256_of(&bytes),
            bytes.len()
        );
        let placeholder = format!("{{{{{}}}}}", name);
        if !text.contains(&placeholder) {
            bail!("the template has no {}", placeholder);
        }
        text = text.replace(&placeholder, &value);
    }
    if let Some(start) = text.find("{{") {
        let rest = &text[start..];
        let end = rest.find("}}").map_or(rest.len(), |end| end + 2);
        bail!("{} is left in the template; give it a --file", &rest[..end]);
    }
    std::fs::write(&args.out, text).with_context(|| format!("writing {}", args.out.display()))?;
    println!("wrote {}", args.out.display());
    Ok(0)
}

// ---------------------------------------------------------------------------

fn read_ca(path: &Path) -> Result<CertificateDer<'static>> {
    CertificateDer::from_pem_file(path)
        .map_err(|e| anyhow!("reading the CA certificate {}: {}", path.display(), e))
}

fn read_conf(path: &Path) -> Result<leaf::config::internal::Config> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    leaf::config::from_string(&text)
        .map_err(|e| anyhow!("{} is not a valid config: {:#}", path.display(), e))
}

fn run_prefetch(args: Prefetch) -> Result<i32> {
    let config = match read_conf(&args.config) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {:#}", err);
            return Ok(EXIT_CONFIG);
        }
    };
    let mut options = FetchOptions::new(&args.cache_dir);
    options.timeout = Some(Duration::from_secs(args.timeout));
    options.max_concurrent = args.concurrency;
    if let Some(ca) = &args.ca {
        options.extra_roots = vec![read_ca(ca)?];
    }

    let started = std::time::Instant::now();
    let caller = std::thread::current().id();
    let mut on_event = |event: &plugin_fetch::FetchEvent<'_>| -> bool {
        let total = event.total.map_or("?".to_string(), mib);
        let all_total = event.all_total.map_or("?".to_string(), mib);
        let kind = format!("{:?}", event.kind).to_uppercase();
        print!(
            "{:>7.3}s  [{}/{}] {:<12} {:<9} {} / {}   all {} / {}",
            started.elapsed().as_secs_f64(),
            event.index + 1,
            event.count,
            event.plugin,
            kind,
            mib(event.downloaded),
            total,
            mib(event.all_downloaded),
            all_total
        );
        if let Some(error) = event.error {
            print!("\n           error: {}", error);
        }
        if std::thread::current().id() != caller {
            print!("   (!! not on the calling thread)");
        }
        println!();
        match args.cancel_after {
            Some(limit) if event.all_downloaded >= limit && !event.kind.is_terminal() => {
                println!(
                    "           -> cancelling: {} bytes have arrived",
                    event.all_downloaded
                );
                false
            }
            _ => true,
        }
    };
    let result = plugin_fetch::prefetch(&config, &options, &mut on_event);

    println!();
    let code = match &result {
        Ok(()) => {
            println!("result: ok -- every plugin is in the cache");
            0
        }
        Err(FetchError::Failed(failures)) => {
            println!(
                "result: {} plugin(s) failed (exit {})",
                failures.len(),
                EXIT_FETCH_FAILED
            );
            EXIT_FETCH_FAILED
        }
        Err(FetchError::Cancelled) => {
            println!("result: cancelled (exit {})", EXIT_CANCELLED);
            EXIT_CANCELLED
        }
        Err(FetchError::Config(err)) => {
            println!("result: config error (exit {}): {:#}", EXIT_CONFIG, err);
            EXIT_CONFIG
        }
    };
    print_cache(&args.cache_dir);
    Ok(code)
}

/// Every file in the cache, so a reader can see that a failure left nothing
/// behind and a success left exactly the file it should.
fn print_cache(dir: &Path) {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    println!("cache {}:", dir.display());
    if files.is_empty() {
        println!("  (empty)");
    }
    for file in files {
        let size = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
        let shown = file.strip_prefix(dir).unwrap_or(&file);
        println!("  {}  ({} bytes)", shown.display(), size);
    }
}

// ---------------------------------------------------------------------------

/// Registers the plugin library at `path` as the builtin `name`: its
/// descriptor function is exactly what a linked-in plugin hands the host.
fn register_builtin(spec: &str) -> Result<()> {
    let (name, path) = spec
        .split_once('=')
        .ok_or_else(|| anyhow!("--builtin [{}] is not name=path", spec))?;
    // Safety: the operator named this library as a plugin to run, which is the
    // same trust as configuring it as an outbound; the symbol has the type
    // the ABI gives it.
    unsafe {
        let library =
            libloading::Library::new(path).with_context(|| format!("opening {}", path))?;
        let get_descriptor: PluginDescriptorFn = *library
            .get::<PluginDescriptorFn>(b"leaf_plugin_get_descriptor\0")
            .with_context(|| format!("{} exports no leaf_plugin_get_descriptor", path))?;
        std::mem::forget(library);
        host::register_builtin_plugin(name, get_descriptor)?;
    }
    println!("registered builtin [{}] from {}", name, path);
    Ok(())
}

fn run_leaf(args: Run) -> Result<i32> {
    for spec in &args.builtin {
        register_builtin(spec)?;
    }
    match &args.cache_dir {
        Some(dir) => {
            let mut options = FetchOptions::new(dir);
            if let Some(ca) = &args.ca {
                options.extra_roots = vec![read_ca(ca)?];
            }
            plugin_fetch::set_default_options(Some(options));
        }
        None => {
            if args.ca.is_some() {
                bail!("--ca only matters with --cache-dir");
            }
        }
    }
    let config = args
        .config
        .to_str()
        .ok_or_else(|| anyhow!("the config path is not UTF-8"))?
        .to_string();
    println!("starting leaf from {} (Ctrl-C to stop)", config);
    let opts = leaf::StartOptions {
        config: leaf::Config::File(config),
        auto_reload: false,
        runtime_opt: leaf::RuntimeOption::MultiThreadAuto(2 * 1024 * 1024),
    };
    if let Err(err) = leaf::start(0, opts) {
        eprintln!("leaf failed to start: {}", err);
        return Ok(1);
    }
    Ok(0)
}
