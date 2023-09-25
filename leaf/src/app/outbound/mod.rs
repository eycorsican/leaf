#[cfg(feature = "outbound-select")]
use std::{collections::HashMap, sync::Arc};

#[cfg(feature = "outbound-select")]
use tokio::sync::RwLock;

pub mod manager;

#[cfg(feature = "outbound-select")]
pub mod selector;
#[cfg(feature = "outbound-select")]
pub mod selector_cache;

#[cfg(feature = "plugin")]
pub mod plugin;

#[cfg(feature = "outbound-select")]
pub type Selectors = HashMap<String, Arc<RwLock<selector::OutboundSelector>>>;
