use std::path::Path;

use anyhow::anyhow;
use anyhow::Result;

pub mod external_rule;
pub mod geosite;
pub mod internal;

#[cfg(feature = "json")]
pub mod json;

#[cfg(feature = "conf")]
pub mod conf;

pub use internal::*;

pub fn from_file(path: &str) -> Result<internal::Config> {
    if let Some(ext) = Path::new(path).extension() {
        match ext.to_str() {
            Some(ext) => match ext {
                #[cfg(feature = "json")]
                "json" => return json::from_file(path),
                #[cfg(feature = "conf")]
                "conf" => return conf::from_file(path),
                _ => (),
            },
            None => (),
        }
    }
    return Err(anyhow!("config files use extension .json or .conf"));
}
