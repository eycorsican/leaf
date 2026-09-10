//! Scheduling and isolation.
//!
//! Every case runs in its own process. That is not incidental: this suite
//! deliberately loads plugins that misbehave, so a case may crash the process
//! it runs in, and it selects a plugin's load-time behaviour through the
//! environment, which cannot be changed once a library is mapped. Isolation
//! turns both of those from "the run is lost" into "one case failed", and lets
//! a hung case be killed and reported rather than hanging the suite.
//!
//! The same binary plays both roles. Without `LEAF_E2E_CASE` it is the runner;
//! with it, it is a single case.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use libtest_mimic::{Arguments, Completion, Failed, Trial};

use crate::fixtures::{Fixture, FixtureSet};
use crate::paths;
use crate::scenario::{Scenario, Tag};

/// Set by the runner on a child to say which case it should run.
pub const ENV_CASE: &str = "LEAF_E2E_CASE";
/// Turns "skipped because a fixture is missing" into a failure. CI sets it.
pub const ENV_STRICT: &str = "LEAF_E2E_STRICT";
/// Runs cases directly instead of in child processes, for debugging.
pub const ENV_IN_PROCESS: &str = "LEAF_E2E_IN_PROCESS";
/// Multiplies every case deadline. A sanitizer lane or a loaded CI machine runs
/// several times slower than a developer's laptop, and the alternative -- per
/// case timeouts padded for the worst machine -- would let a real hang sit for
/// minutes everywhere else.
pub const ENV_TIMEOUT_SCALE: &str = "LEAF_E2E_TIMEOUT_SCALE";

/// How much of a failed case's log to inline in the failure message. The whole
/// log is on disk either way.
const LOG_TAIL_BYTES: usize = 8 * 1024;

/// Hands each case child process a port band of its own; see `net`.
static NEXT_PORT_BAND: AtomicU32 = AtomicU32::new(0);

/// Entry point for the `e2e` test target.
pub fn main() -> ! {
    match std::env::var(ENV_CASE) {
        Ok(case) => run_single_case(&case),
        Err(_) => run_suite(),
    }
}

/// Harness options, parsed out of argv before libtest-mimic sees it.
#[derive(Clone)]
struct Options {
    strict: bool,
    in_process: bool,
    timeout_scale: f64,
    include_tags: Vec<Tag>,
    exclude_tags: Vec<Tag>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            strict: false,
            in_process: false,
            timeout_scale: 1.0,
            include_tags: Vec::new(),
            exclude_tags: Vec::new(),
        }
    }
}

impl Options {
    /// Splits our own flags out of argv, leaving the rest for libtest-mimic.
    fn split(argv: Vec<String>) -> Result<(Options, Vec<OsString>)> {
        let mut opts = Options {
            strict: env_flag(ENV_STRICT),
            in_process: env_flag(ENV_IN_PROCESS),
            timeout_scale: env_scale(ENV_TIMEOUT_SCALE)?,
            ..Options::default()
        };
        let mut rest = Vec::new();
        let mut args = argv.into_iter();
        if let Some(program) = args.next() {
            rest.push(OsString::from(program));
        }
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--strict" => opts.strict = true,
                "--in-process" => opts.in_process = true,
                "--timeout-scale" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow!("--timeout-scale needs a number"))?;
                    opts.timeout_scale = parse_scale(&value)?;
                }
                "--tag" | "--no-tag" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow!("{} needs a tag name", arg))?;
                    let tag =
                        Tag::parse(&value).ok_or_else(|| anyhow!("unknown tag [{}]", value))?;
                    if arg == "--tag" {
                        opts.include_tags.push(tag);
                    } else {
                        opts.exclude_tags.push(tag);
                    }
                }
                _ => rest.push(OsString::from(arg)),
            }
        }
        Ok((opts, rest))
    }

    fn selects(&self, scenario: &Scenario) -> bool {
        if self.exclude_tags.iter().any(|tag| scenario.has_tag(*tag)) {
            return false;
        }
        if self.include_tags.is_empty() {
            return true;
        }
        self.include_tags.iter().any(|tag| scenario.has_tag(*tag))
    }
}

/// The deadline multiplier this run was given.
///
/// A case inherits it through the environment, so work inside one -- a stall
/// deadline in the load generator, say -- can be as generous as the runner is
/// being with the case as a whole.
pub fn timeout_scale() -> f64 {
    env_scale(ENV_TIMEOUT_SCALE).unwrap_or(1.0)
}

fn env_scale(key: &str) -> Result<f64> {
    match std::env::var(key) {
        Ok(value) => parse_scale(&value),
        Err(_) => Ok(1.0),
    }
}

fn parse_scale(value: &str) -> Result<f64> {
    let scale: f64 = value
        .parse()
        .map_err(|_| anyhow!("[{}] is not a number", value))?;
    if !scale.is_finite() || scale <= 0.0 {
        return Err(anyhow!("a timeout scale must be a positive number"));
    }
    Ok(scale)
}

fn env_flag(key: &str) -> bool {
    matches!(
        std::env::var(key).as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn run_suite() -> ! {
    let (opts, passthrough) = match Options::split(std::env::args().collect()) {
        Ok(split) => split,
        Err(err) => {
            eprintln!("leaf-e2e: {:#}", err);
            std::process::exit(2);
        }
    };
    let args = Arguments::from_iter(passthrough);

    // Checked once, here, rather than left to surface as every case in the run
    // reporting a fixture it could not build. Everything the harness builds and
    // everything it looks for hangs off this one directory, so if cargo has
    // moved it again, that is the thing to say. `--list` builds nothing and
    // stays usable either way, which is what someone diagnosing this needs.
    if !args.list {
        if let Err(err) = paths::profile_dir() {
            eprintln!("leaf-e2e: {:#}", err);
            std::process::exit(2);
        }
    }

    let selected: Vec<Scenario> = crate::scenarios::all()
        .into_iter()
        .filter(|scenario| opts.selects(scenario))
        .collect();

    // Only build what is actually going to run: filtering down to one case
    // should not compile every plugin in the workspace. `--list` builds nothing.
    let wanted: BTreeSet<Fixture> = if args.list {
        BTreeSet::new()
    } else {
        selected
            .iter()
            .filter(|scenario| !args.is_filtered_out(&placeholder_trial(scenario)))
            .flat_map(|scenario| scenario.needs.iter().copied())
            .collect()
    };
    if !wanted.is_empty() {
        eprintln!(
            "leaf-e2e: preparing fixtures: {}",
            wanted
                .iter()
                .map(|fixture| fixture.id())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let fixtures = FixtureSet::build(&wanted);
    let fixture_env = Arc::new(fixtures.env());
    if opts.in_process {
        // Cases normally receive these on their child process. Running in this
        // one, they have to be applied here -- once, before any case starts, so
        // that concurrent cases do not race to set them.
        for (key, value) in fixture_env.iter() {
            std::env::set_var(key, value);
        }
    }

    let trials = selected
        .into_iter()
        .map(|scenario| {
            let unmet = fixtures.unmet(&scenario.needs);
            trial_for(scenario, unmet, Arc::clone(&fixture_env), opts.clone())
        })
        .collect();

    libtest_mimic::run(&args, trials).exit();
}

/// A stand-in used only to ask libtest-mimic whether a case survives filtering.
fn placeholder_trial(scenario: &Scenario) -> Trial {
    Trial::test(scenario.id.clone(), || Ok(())).with_kind(scenario.kind)
}

fn trial_for(
    scenario: Scenario,
    unmet: Option<String>,
    fixture_env: Arc<Vec<(String, String)>>,
    opts: Options,
) -> Trial {
    let kind = scenario.kind;
    let name = scenario.id.clone();
    Trial::ignorable_test(name, move || {
        if let Some(reason) = unmet {
            return if opts.strict {
                Err(Failed::from(format!("{} (--strict)", reason)))
            } else {
                Ok(Completion::ignored_with(reason))
            };
        }
        let outcome = if opts.in_process {
            run_here(&scenario)
        } else {
            let timeout = scenario.timeout.mul_f64(opts.timeout_scale);
            run_in_child(&scenario, &fixture_env, timeout)
        };

        match (outcome, &scenario.known_defect) {
            (Ok(()), None) => Ok(Completion::Completed),
            (Err(err), None) => Err(Failed::from(format!("{:#}", err))),
            // The defect is still there. Say so and move on.
            (Err(_), Some(defect)) => Ok(Completion::ignored_with(format!(
                "known defect: {}",
                defect
            ))),
            // It passed. Either the defect is fixed or the case stopped
            // reaching it; both mean the marker is now a lie.
            (Ok(()), Some(defect)) => Err(Failed::from(format!(
                "this case is marked as hitting a known defect but passed. \
                 Remove the `known_defect` marker if it is fixed, or work out \
                 why the case no longer reaches it.\nMarked defect: {}",
                defect
            ))),
        }
    })
    .with_kind(kind)
}

/// Spawns one case as a child process and reports what became of it.
fn run_in_child(
    scenario: &Scenario,
    fixture_env: &[(String, String)],
    timeout: Duration,
) -> Result<()> {
    let dir = paths::artifacts_dir()?.join(paths::artifact_slug(&scenario.id));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating the artifact directory {}", dir.display()))?;
    let stdout_path = dir.join("stdout.log");
    let stderr_path = dir.join("stderr.log");

    let exe = std::env::current_exe().context("locating the harness executable")?;
    // A band of ports this case has to itself. Cases run concurrently and each
    // reserves listeners for its nodes, and a port the operating system hands
    // out is not held between being chosen and being bound -- so without this
    // two cases can be given the same one, and the one that loses the bind
    // spends the rest of its run talking to the other one's node. Handing out
    // bands in order means no two cases running at the same time share one.
    let band = NEXT_PORT_BAND.fetch_add(1, Ordering::Relaxed) % crate::net::BAND_COUNT;

    let mut command = Command::new(exe);
    command
        .env(ENV_CASE, &scenario.id)
        .env(crate::logs::ENV_LOG_FILE, &stdout_path)
        .env(crate::net::ENV_PORT_BAND, band.to_string())
        .env("RUST_BACKTRACE", "1")
        .env_remove(ENV_IN_PROCESS)
        .stdin(Stdio::null())
        .stdout(Stdio::from(File::create(&stdout_path)?))
        .stderr(Stdio::from(File::create(&stderr_path)?));
    for (key, value) in fixture_env {
        command.env(key, value);
    }
    // Scenario environment last, so a case can override a default.
    for (key, value) in &scenario.env {
        command.env(key, value);
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("spawning the child for case [{}]", scenario.id))?;

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(anyhow!(
                    "timed out after {:?}\n{}",
                    timeout,
                    evidence(&stdout_path, &stderr_path)
                ));
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };

    if status.success() {
        return Ok(());
    }
    Err(anyhow!(
        "case exited with {}\n{}",
        describe_status(&status),
        evidence(&stdout_path, &stderr_path)
    ))
}

/// Runs a case in this process. Loses crash isolation, and a case's own
/// environment becomes process-wide, so this is opt-in, meant for running a
/// single case under a debugger, and belongs with `--test-threads 1`.
fn run_here(scenario: &Scenario) -> Result<()> {
    for (key, value) in &scenario.env {
        std::env::set_var(key, value);
    }
    runtime()?.block_on((scenario.run)())
}

fn run_single_case(id: &str) -> ! {
    let Some(scenario) = crate::scenarios::all()
        .into_iter()
        .find(|scenario| scenario.id == id)
    else {
        eprintln!("leaf-e2e: no such case [{}]", id);
        std::process::exit(2);
    };
    let outcome = runtime().and_then(|rt| rt.block_on((scenario.run)()));
    match outcome {
        Ok(()) => std::process::exit(0),
        Err(err) => {
            eprintln!("leaf-e2e: case [{}] failed: {:#}", id, err);
            std::process::exit(1);
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    // Multi-threaded because plugins that embed their own runtime call back in
    // from threads the executor does not own, and because a node runs its own
    // runtime on a blocking thread of this one.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .context("building the case runtime")
}

fn describe_status(status: &std::process::ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return format!("signal {} (the case crashed or was killed)", signal);
        }
    }
    match status.code() {
        Some(code) => format!("exit code {}", code),
        None => "an unknown status".to_string(),
    }
}

/// The tail of a failed case's captured output, plus where the whole thing is.
fn evidence(stdout_path: &PathBuf, stderr_path: &PathBuf) -> String {
    let mut out = String::new();
    for (label, path) in [("stdout", stdout_path), ("stderr", stderr_path)] {
        let tail = tail_of(path).unwrap_or_else(|err| format!("<unreadable: {}>", err));
        if !tail.trim().is_empty() {
            out.push_str(&format!("--- {} (tail) ---\n{}\n", label, tail.trim_end()));
        }
    }
    out.push_str(&format!(
        "--- full logs ---\n{}\n",
        stdout_path.parent().unwrap_or(stdout_path).display()
    ));
    out
}

fn tail_of(path: &PathBuf) -> Result<String> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len > LOG_TAIL_BYTES as u64 {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::End(-(LOG_TAIL_BYTES as i64)))?;
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}
