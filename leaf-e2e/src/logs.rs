//! Reading what the node under test logged.
//!
//! Some of what the host does is only visible in its log: the text a plugin
//! returned from `get_last_error`, the specific rule a misbehaving engine
//! broke. A client sees a closed connection either way, so without this a
//! hostile case could only assert that something went wrong, not that the right
//! thing did.
//!
//! The runner already redirects each case's output to a file and hands the case
//! its path, so this reads that file rather than intercepting anything.

use std::time::Duration;

use anyhow::{bail, Context, Result};

/// The path the runner redirected this case's stdout to.
pub const ENV_LOG_FILE: &str = "LEAF_E2E_LOG_FILE";

/// The directory the runner set aside for this case's artifacts, when there is
/// one. Anything a case writes for a human to look at afterwards belongs here.
pub fn artifact_dir() -> Option<std::path::PathBuf> {
    let path = std::env::var(ENV_LOG_FILE).ok()?;
    std::path::Path::new(&path)
        .parent()
        .map(|dir| dir.to_path_buf())
}

/// Strips ANSI escape sequences from a log line.
///
/// The node's log is styled, and not only where it is obvious: a tracing field
/// renders as `name` `=` `value` with the name and the separator wrapped in
/// their own escapes, so the literal text `count=2` never appears in it even
/// though that is exactly what the line says. A case asserting on a message
/// gets away with this because messages are not styled; one asserting on a
/// field does not, and would fail or pass depending on whether colour happened
/// to be on. Matching against the stripped line makes both kinds mean what
/// they look like.
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // A control sequence: `ESC [` then parameter bytes, then one final
        // byte in `@`..=`~` that ends it. Anything else after ESC is a two
        // character sequence, whose second character is consumed here.
        match chars.next() {
            Some('[') => {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            Some(_) | None => {}
        }
    }
    out
}

/// Waits for a line containing `needle` and returns it, with any styling
/// removed.
///
/// Polls rather than tails: the log is written by this same process, and a case
/// is looking for something a node is about to say, not for a stream.
pub async fn wait_for(needle: &str, within: Duration) -> Result<String> {
    let path = std::env::var(ENV_LOG_FILE).map_err(|_| {
        anyhow::anyhow!(
            "no captured log for this case; log assertions need the runner's \
             child process, so they do not work under --in-process"
        )
    })?;

    let deadline = tokio::time::Instant::now() + within;
    loop {
        let captured = std::fs::read_to_string(&path)
            .with_context(|| format!("reading the captured log at {}", path))?;
        if let Some(line) = captured
            .lines()
            .map(strip_ansi)
            .find(|line| line.contains(needle))
        {
            return Ok(line);
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "nothing in the log mentioned [{}] within {:?}",
                needle,
                within
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
