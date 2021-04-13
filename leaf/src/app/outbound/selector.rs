use std::collections::HashMap;
use std::sync::Arc;

use protobuf::Message;

use crate::proxy::OutboundHandler;
use anyhow::{anyhow, Result};

pub fn get_selected_from_cache(id: &str) -> Result<Option<String>> {
    let proj_dirs = if let Some(d) = directories::ProjectDirs::from("com", "github", "leaf") {
        d
    } else {
        return Err(anyhow!("no home directory"));
    };
    let cache_loc = proj_dirs.cache_dir();
    let cache_file = cache_loc.join("selector.cache");
    let content = std::fs::read(&cache_file)?;
    let cache = super::selector_cache::SelectorCache::parse_from_bytes(&content)?;
    Ok(cache.items.get(id).map(Clone::clone))
}

pub fn persist_selected_to_cache(id: String, selected: String) -> Result<()> {
    let proj_dirs = if let Some(d) = directories::ProjectDirs::from("com", "github", "leaf") {
        d
    } else {
        return Err(anyhow!("no home directory"));
    };
    let cache_loc = proj_dirs.cache_dir();
    if !cache_loc.exists() {
        std::fs::create_dir_all(&cache_loc)?;
    }
    let cache_file = cache_loc.join("selector.cache");
    let mut cache = if cache_file.exists() {
        let content = std::fs::read(&cache_file)?;
        super::selector_cache::SelectorCache::parse_from_bytes(&content)?
    } else {
        super::selector_cache::SelectorCache::new()
    };
    cache.items.insert(id.clone(), selected.clone());
    let content = cache.write_to_bytes()?;
    std::fs::write(&cache_file, content)?;
    Ok(())
}

/// OutboundSelector typically associates to a `select` outbound.
pub struct OutboundSelector {
    id: String,
    handlers: HashMap<String, Arc<dyn OutboundHandler>>,
    selected: Option<String>,
}

impl OutboundSelector {
    pub fn new(id: String, handlers: HashMap<String, Arc<dyn OutboundHandler>>) -> Self {
        Self {
            id,
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
            if let Err(e) = persist_selected_to_cache(self.id.clone(), tag.to_string()) {
                log::warn!("persist selector state failed: {}", e);
            }
            Ok(())
        } else {
            Err(anyhow!("handler not exists"))
        }
    }
}
