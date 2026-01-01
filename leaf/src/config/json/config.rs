use std::path::Path;

use anyhow::{anyhow, Result};

use crate::config::{common, internal};

pub use crate::config::common::{
    AMuxInboundSettings, AMuxOutboundSettings, CatInboundSettings, ChainInboundSettings,
    ChainOutboundSettings, Config, Dns, FailOverOutboundSettings, HcInboundSettings, Inbound,
    InboundSettings, Log, NfInboundSettings, ObfsOutboundSettings, Outbound, OutboundSettings,
    PluginOutboundSettings, QuicInboundSettings, QuicOutboundSettings, RedirectOutboundSettings,
    Rule, SelectOutboundSettings, ShadowsocksInboundSettings,
    ShadowsocksOutboundSettings, SocksOutboundSettings, StaticOutboundSettings, TlsInboundSettings,
    TlsOutboundSettings, TrojanInboundSettings, TrojanOutboundSettings, TryAllOutboundSettings,
    TunInboundSettings, VMessOutboundSettings, WebSocketInboundSettings, WebSocketOutboundSettings,
};

pub fn to_internal(config: Config) -> Result<internal::Config> {
    common::to_internal(config)
}

pub fn json_from_string(config: &str) -> Result<common::Config> {
    serde_json::from_str(config).map_err(|e| anyhow!("deserialize json config failed: {}", e))
}

pub fn from_string(s: &str) -> Result<internal::Config> {
    let config = json_from_string(s)?;
    common::to_internal(config)
}

pub fn from_file<P>(path: P) -> Result<internal::Config>
where
    P: AsRef<Path>,
{
    let config = std::fs::read_to_string(path)?;
    let config = json_from_string(&config)?;
    common::to_internal(config)
}
