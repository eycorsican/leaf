//! Where things live.
//!
//! Everything is derived, never configured: the workspace root comes from this
//! crate's manifest at compile time, and the target directory comes from where
//! cargo placed this very binary. That keeps the harness working under a custom
//! `CARGO_TARGET_DIR`, a custom profile, or a `cargo test` run from any cwd.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

/// The workspace root. `leaf-e2e` sits exactly one level below it.
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("leaf-e2e lives one level below the workspace root")
        .to_path_buf()
}

/// Set to use a profile directory instead of deriving one.
pub const ENV_PROFILE_DIR: &str = "LEAF_E2E_PROFILE_DIR";

/// `<target>/<profile>`, e.g. `target/debug`.
///
/// Nothing tells a test binary at run time which profile built it, so this is
/// derived from where cargo put the binary -- and cargo has more than one place
/// to put it. The classic layout is `<profile>/deps/<exe>`; a newer cargo keeps
/// intermediates, this binary among them, under
/// `<profile>/build/<package>/<hash>/out/<exe>`. Both leave the profile
/// directory immediately above a directory cargo names itself, so this looks
/// for that name instead of counting levels upward. Counting is what turned a
/// layout change into `cargo build --profile <build hash>`, and every fixture
/// in the run failing to build for a reason that named neither cargo nor the
/// layout.
///
/// [`ENV_PROFILE_DIR`] overrides it, for a layout that is neither.
pub fn profile_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(ENV_PROFILE_DIR) {
        return Ok(PathBuf::from(dir));
    }
    let exe = std::env::current_exe()?;
    let dir = derive_profile_dir(&exe).ok_or_else(|| {
        anyhow!(
            "cannot tell which profile directory [{}] was built into; \
             set {} to the `target/<profile>` directory cargo used",
            exe.display(),
            ENV_PROFILE_DIR
        )
    })?;
    if !dir.is_dir() {
        return Err(anyhow!(
            "derived the profile directory [{}] from [{}], and it does not exist; \
             set {} to the `target/<profile>` directory cargo used",
            dir.display(),
            exe.display(),
            ENV_PROFILE_DIR
        ));
    }
    Ok(dir)
}

/// The profile directory an executable at `exe` was placed under, by the name
/// of the directory cargo puts between the two.
///
/// The nearest such directory wins, so a workspace that itself lives under a
/// path component called `build` or `deps` is not mistaken for the layout.
/// Pure, so that a layout can be checked without cargo producing one.
pub fn derive_profile_dir(exe: &Path) -> Option<PathBuf> {
    exe.ancestors()
        .skip(1)
        .find(|dir| {
            dir.file_name()
                .is_some_and(|name| name == "deps" || name == "build")
        })
        .and_then(Path::parent)
        .map(Path::to_path_buf)
}

/// The target triple to build fixtures for, when cargo nested the profile under
/// one.
///
/// Cargo lays out `target/<profile>` by default and `target/<triple>/<profile>`
/// when it was given an explicit `--target`, as a sanitizer or cross lane is.
/// A fixture built without matching that would land where the harness does not
/// look, so the layout is recognised by comparing the directory above the
/// profile against the triple this crate was compiled for.
pub fn target_triple() -> Result<Option<String>> {
    let triple = env!("LEAF_E2E_TARGET");
    let profile = profile_dir()?;
    let nested = profile
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == triple);
    Ok(nested.then(|| triple.to_string()))
}

/// The directory name cargo used for the current profile, e.g. `debug`.
pub fn profile_dir_name() -> Result<String> {
    let dir = profile_dir()?;
    dir.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("unnamed target directory {}", dir.display()))
}

/// The `--profile` argument that reproduces the current profile.
///
/// The `debug` *directory* is produced by the `dev` *profile*; every other
/// profile names its own directory.
pub fn cargo_profile_arg() -> Result<String> {
    Ok(match profile_dir_name()?.as_str() {
        "debug" => "dev".to_string(),
        other => other.to_string(),
    })
}

/// Per-case logs and recordings, kept next to the build output so that
/// `cargo clean` disposes of them.
pub fn artifacts_dir() -> Result<PathBuf> {
    Ok(profile_dir()?.join("e2e-artifacts"))
}

/// Turns a scenario id into a single path segment.
pub fn artifact_slug(scenario_id: &str) -> String {
    scenario_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}
