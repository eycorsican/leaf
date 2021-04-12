use std::collections::HashMap;
use std::sync::Arc;

use crate::proxy::OutboundHandler;
use anyhow::{anyhow, Result};

/// OutboundSelector typically associates to a `select` outbound.
pub struct OutboundSelector {
    handlers: HashMap<String, Arc<dyn OutboundHandler>>,
    selected: Option<String>,
}

impl OutboundSelector {
    pub fn new(handlers: HashMap<String, Arc<dyn OutboundHandler>>) -> Self {
        Self {
            handlers,
            selected: None,
        }
    }

    pub fn get_selected(&self) -> Option<Arc<dyn OutboundHandler>> {
        if let Some(tag) = self.selected.as_ref() {
            if let Some(h) = self.handlers.get(tag) {
                return Some(h.clone());
            }
        }
        None
    }

    pub fn get_selected_tag(&self) -> Option<String> {
        if let Some(tag) = self.selected.as_ref() {
            return Some(tag.to_owned());
        }
        None
    }

    pub fn set_selected(&mut self, tag: &str) -> Result<()> {
        if self.handlers.contains_key(tag) {
            self.selected.replace(tag.to_string());
            Ok(())
        } else {
            Err(anyhow!("handler not exists"))
        }
    }
}
