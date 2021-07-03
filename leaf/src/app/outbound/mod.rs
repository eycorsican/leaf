use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

pub mod manager;
pub mod plugin;
pub mod selector;
pub mod selector_cache;

pub type Selectors = HashMap<String, Arc<RwLock<selector::OutboundSelector>>>;
