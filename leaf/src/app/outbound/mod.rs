use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

pub mod manager;
pub mod selector;
pub mod selector_cache;

#[cfg(feature = "plugin")]
pub mod plugin;

pub type Selectors = HashMap<String, Arc<RwLock<selector::OutboundSelector>>>;
