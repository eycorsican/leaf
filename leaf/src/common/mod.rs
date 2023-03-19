pub mod crypto;
pub mod io;
pub mod net;
pub mod resolver;
pub mod sniff;

#[cfg(target_os = "macos")]
pub mod cmd_macos;
#[cfg(target_os = "macos")]
pub use cmd_macos as cmd;

#[cfg(target_os = "linux")]
pub mod cmd_linux;
#[cfg(target_os = "linux")]
pub use cmd_linux as cmd;

#[cfg(target_os = "windows")]
pub mod cmd_windows;
#[cfg(target_os = "windows")]
pub use cmd_windows as cmd;