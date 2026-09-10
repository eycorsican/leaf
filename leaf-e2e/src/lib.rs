//! End-to-end tests for leaf's plugin host.
//!
//! The suite drives whole leaf instances -- a client node, usually a server
//! node, and an origin server -- and observes them from the outside over
//! SOCKS5, so a case covers the same path a deployment does: config parsing,
//! plugin loading, routing, the dispatcher, and the C ABI data plane.
//!
//! Three properties shape the design:
//!
//! * **A case owns a process.** Plugins are loaded into the host and some cases
//!   deliberately load ones that misbehave, so a case must be able to crash,
//!   hang or set load-time environment without affecting its neighbours.
//! * **Nothing is hard-coded.** Ports come from the operating system and paths
//!   are derived, so cases run concurrently and the suite works under any
//!   target directory or profile.
//! * **Missing tools are visible.** A case whose plugin could not be built is
//!   reported as ignored with a reason, never as passed; `--strict` turns that
//!   into a failure so CI cannot go green on an empty run.
//!
//! See `README.md` for how to run it.

pub mod alloc;
pub mod behaviours;
pub mod client;
pub mod conformance;
pub mod differential;
pub mod fixtures;
pub mod flow;
pub mod framing;
pub mod load;
pub mod logs;
pub mod meters;
pub mod net;
pub mod node;
pub mod paths;
pub mod process;
pub mod report;
pub mod runner;
pub mod scenario;
pub mod scenarios;
pub mod servers;
pub mod tls;
