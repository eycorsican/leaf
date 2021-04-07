use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

pub mod manager;
pub mod selector;

pub type Selectors = HashMap<String, Arc<RwLock<selector::OutboundSelector>>>;
