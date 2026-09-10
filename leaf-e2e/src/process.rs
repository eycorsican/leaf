//! Driving a real `leaf` process.
//!
//! Almost every case runs leaf in-process, which is faster and makes its log
//! easy to read. A few things only exist outside it: whether the shipped binary
//! starts from a config file on disk, and whether the process actually exits
//! once a plugin has pulled a language runtime of its own into it. The ABI
//! warns about the second -- a Go `c-shared` build leaves a thread that has
//! called into it unable to exit cleanly -- and no in-process test can observe
//! it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use crate::fixtures::Fixture;
use crate::logs;
use crate::net;
use crate::node::Node;

/// How long the binary may take to start listening.
const START_TIMEOUT: Duration = Duration::from_secs(20);

pub struct CliNode {
    name: String,
    child: Child,
    socks: SocketAddr,
    stopped: bool,
}

impl CliNode {
    /// Writes the node's config next to the case's other artifacts and starts
    /// the shipped binary on it.
    pub async fn start(name: &str, node: &Node) -> Result<Self> {
        let socks = node.socks_addr()?;
        let directory = logs::artifact_dir().unwrap_or_else(std::env::temp_dir);
        std::fs::create_dir_all(&directory)?;
        let config_path: PathBuf = directory.join(format!("{}.json", name));
        std::fs::write(&config_path, node.config_string())
            .with_context(|| format!("writing {}", config_path.display()))?;

        let child = Command::new(Fixture::LeafCli.path()?)
            .arg("-c")
            .arg(&config_path)
            // Inherited, so the process's log lands in the case's captured
            // output like everything else.
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdin(Stdio::null())
            .spawn()
            .context("starting the leaf binary")?;

        let mut node = Self {
            name: name.to_string(),
            child,
            socks,
            stopped: false,
        };
        if let Err(err) = net::wait_tcp_ready(socks, START_TIMEOUT).await {
            let _ = node.child.kill();
            return Err(anyhow!("[{}] never started listening: {}", node.name, err));
        }
        Ok(node)
    }

    pub fn socks_addr(&self) -> SocketAddr {
        self.socks
    }

    /// Asks the process to shut down the way an operator would, and requires it
    /// to actually go.
    pub async fn interrupt_and_wait(mut self, within: Duration) -> Result<()> {
        self.stopped = true;
        interrupt(self.child.id())?;

        let deadline = Instant::now() + within;
        loop {
            match self.child.try_wait()? {
                Some(status) if status.success() => return Ok(()),
                Some(status) => bail!("[{}] exited with {}", self.name, status),
                None if Instant::now() >= deadline => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    bail!(
                        "[{}] did not exit within {:?} of being interrupted",
                        self.name,
                        within
                    );
                }
                None => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    }
}

impl Drop for CliNode {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Sends the interrupt leaf listens for.
///
/// `Child::kill` would be a `SIGKILL`, which proves nothing about whether the
/// process can shut itself down.
#[cfg(unix)]
fn interrupt(pid: u32) -> Result<()> {
    let status = Command::new("kill")
        .arg("-INT")
        .arg(pid.to_string())
        .status()
        .context("interrupting the leaf process")?;
    if !status.success() {
        bail!("kill -INT {} failed with {}", pid, status);
    }
    Ok(())
}

#[cfg(not(unix))]
fn interrupt(_pid: u32) -> Result<()> {
    bail!("interrupting a process is only implemented for unix")
}

/// Runs `leaf -T` over a config file, which parses it and exits.
/// Runs `--verify-plugin` on a library and hands back whether it was accepted
/// and everything the binary said about it.
///
/// Both halves matter: a rejection is as much of a result as a report, and the
/// text is the whole point of the option.
pub fn verify_plugin(path: &std::path::Path, sha256: Option<&str>) -> Result<(bool, String)> {
    let mut command = Command::new(Fixture::LeafCli.path()?);
    command.arg("--verify-plugin").arg(path);
    if let Some(sha256) = sha256 {
        command.arg("--verify-plugin-sha256").arg(sha256);
    }
    let output = command.output().context("running the leaf binary")?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), text))
}

pub fn test_config(path: &std::path::Path) -> Result<()> {
    let output = Command::new(Fixture::LeafCli.path()?)
        .arg("-T")
        .arg("-c")
        .arg(path)
        .output()
        .context("running the leaf binary")?;
    if !output.status.success() {
        bail!(
            "{} was rejected: {}{}",
            path.display(),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}
