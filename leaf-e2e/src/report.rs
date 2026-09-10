//! Numbers a case produced, left next to its logs.
//!
//! The suite asserts ratios, because an absolute number from a shared runner
//! says more about the runner than about the code. That is the right thing to
//! *fail* on and the wrong thing to throw away: a ratio that stayed inside its
//! budget while both sides halved is a regression nobody sees. So every meter
//! also writes what it measured into the case's artifact directory, which CI
//! already uploads.
//!
//! Nothing reads these files back. They are evidence, not a fixture, and a
//! failure to write one never fails a case.

use std::collections::HashSet;
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::paths;
use crate::runner::ENV_CASE;

/// Appends `entry` to a JSON array in the current case's artifact directory.
///
/// A no-op when there is no case directory to write to, which is how
/// `--in-process` runs behave: they share one process and have nowhere
/// per-case to put this.
pub fn append(file_name: &str, entry: Value) {
    if let Err(err) = try_append(file_name, entry) {
        // Evidence, not an assertion: a case that measured something correctly
        // does not become a failure because the disk did not want it.
        eprintln!("leaf-e2e: could not record {}: {:#}", file_name, err);
    }
}

/// The case this process is running, when it is running one.
pub fn case() -> Option<String> {
    std::env::var(ENV_CASE).ok()
}

fn try_append(file_name: &str, entry: Value) -> Result<()> {
    let Some(case) = case() else {
        return Ok(());
    };
    let dir = paths::artifacts_dir()?.join(paths::artifact_slug(&case));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating the artifact directory {}", dir.display()))?;
    let path = dir.join(file_name);

    // The artifact directory outlives a run, so the first write from this
    // process replaces what the previous run left rather than appending to it.
    // A file that mixed today's numbers with last week's would be worse than
    // no file at all.
    let mut entries = if first_write(&path) {
        Vec::new()
    } else {
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<Vec<Value>>(&bytes).unwrap_or_default(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        }
    };
    entries.push(entry);

    let body = serde_json::to_vec_pretty(&entries).context("encoding the record")?;
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))
}

/// Whether this process has yet to write to `path`.
fn first_write(path: &std::path::Path) -> bool {
    static WRITTEN: Mutex<Option<HashSet<std::path::PathBuf>>> = Mutex::new(None);
    let mut written = WRITTEN.lock().expect("the record set is never poisoned");
    written
        .get_or_insert_with(HashSet::new)
        .insert(path.to_path_buf())
}
