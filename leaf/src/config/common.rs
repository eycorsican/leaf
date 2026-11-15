use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Result};
use protobuf::Message;
use serde::de::Deserializer;
use serde_derive::{Deserialize, Serialize};

use crate::config::{compat, external_rule, internal};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Dns {
    pub servers: Option<Vec<String>>,
    pub hosts: Option<HashMap<String, Vec<String>>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Log {
    pub level: Option<String>,
    pub output: Option<String>,
    pub format: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CatInboundSettings {
    pub network: Option<String>,
    pub address: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NfInboundSettings {
    #[serde(rename = "driverName", alias = "driver_name")]
    pub driver_name: String,
    pub nfapi: Option<String>,
    #[serde(rename = "fakeDnsExclude", alias = "fake_dns_exclude")]
    pub fake_dns_exclude: Option<Vec<String>>,
    #[serde(rename = "fakeDnsInclude", alias = "fake_dns_include")]
    pub fake_dns_include: Option<Vec<String>>,
    pub tun2socks: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct SocksInboundSettings {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksInboundSettings {
    pub method: Option<String>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrojanInboundSettings {
    pub passwords: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct WebSocketInboundSettings {
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HcInboundSettings {
    pub path: String,
    #[serde(default)]
    pub request: Option<String>,
    pub response: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct AMuxInboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuicInboundSettings {
    pub certificate: Option<String>,
    #[serde(rename = "certificateKey", alias = "certificate_key")]
    pub certificate_key: Option<String>,
    #[serde(rename = "rawCertificate", alias = "raw_certificate")]
    pub raw_certificate: Option<Vec<String>>,
    #[serde(rename = "rawCertificateKey", alias = "raw_certificate_key")]
    pub raw_certificate_key: Option<Vec<String>>,
    pub alpn: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsInboundSettings {
    pub certificate: Option<String>,
    #[serde(rename = "certificateKey", alias = "certificate_key")]
    pub certificate_key: Option<String>,
    #[serde(rename = "rawCertificate", alias = "raw_certificate")]
    pub raw_certificate: Option<Vec<String>>,
    #[serde(rename = "rawCertificateKey", alias = "raw_certificate_key")]
    pub raw_certificate_key: Option<Vec<String>>,
    #[serde(rename = "echConfig", alias = "ech_config")]
    pub ech_config: Option<String>,
    #[serde(rename = "echKey", alias = "ech_key")]
    pub ech_key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ChainInboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct MptpInboundSettings {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TunInboundSettings {
    pub auto: Option<bool>,
    pub fd: Option<i32>,
    pub name: Option<String>,
    pub address: Option<String>,
    pub gateway: Option<String>,
    pub netmask: Option<String>,
    pub mtu: Option<i32>,
    #[serde(rename = "fakeDnsExclude", alias = "fake_dns_exclude")]
    pub fake_dns_exclude: Option<Vec<String>>,
    #[serde(rename = "fakeDnsInclude", alias = "fake_dns_include")]
    pub fake_dns_include: Option<Vec<String>>,
    pub tun2socks: Option<String>,
    pub wintun: Option<String>,
    #[serde(rename = "dnsServers", alias = "dns_servers")]
    pub dns_servers: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RedirectOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SocksOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShadowsocksOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub method: Option<String>,
    pub password: Option<String>,
    pub prefix: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ObfsOutboundSettings {
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrojanOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VMessOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub uuid: Option<String>,
    pub security: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VlessOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub uuid: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RealityOutboundSettings {
    #[serde(rename = "serverName", alias = "server_name")]
    pub server_name: Option<String>,
    #[serde(rename = "publicKey", alias = "public_key")]
    pub public_key: Option<String>,
    #[serde(rename = "shortId", alias = "short_id")]
    pub short_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TryAllOutboundSettings {
    pub actors: Option<Vec<String>>,
    #[serde(rename = "delayBase", alias = "delay_base")]
    pub delay_base: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StaticOutboundSettings {
    pub actors: Option<Vec<String>>,
    pub method: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsOutboundSettings {
    #[serde(rename = "serverName", alias = "server_name")]
    pub server_name: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub certificate: Option<String>,
    #[serde(rename = "certificateKey", alias = "certificate_key")]
    pub certificate_key: Option<String>,
    #[serde(rename = "rawCertificate", alias = "raw_certificate")]
    pub raw_certificate: Option<Vec<String>>,
    #[serde(rename = "rawCertificateKey", alias = "raw_certificate_key")]
    pub raw_certificate_key: Option<Vec<String>>,
    pub insecure: Option<bool>,
    #[serde(rename = "ech")]
    pub ech: Option<bool>,
    #[serde(rename = "echDisableDnsLookup", alias = "ech_disable_dns_lookup")]
    pub ech_disable_dns_lookup: Option<bool>,
    #[serde(rename = "echConfigList", alias = "ech_config_list")]
    pub ech_config_list: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebSocketOutboundSettings {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AMuxOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub actors: Option<Vec<String>>,
    #[serde(rename = "maxAccepts", alias = "max_accepts")]
    pub max_accepts: Option<u32>,
    pub concurrency: Option<u32>,
    pub max_recv_bytes: Option<u64>,
    pub max_lifetime: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuicOutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    #[serde(rename = "serverName", alias = "server_name")]
    pub server_name: Option<String>,
    pub certificate: Option<String>,
    #[serde(rename = "certificateKey", alias = "certificate_key")]
    pub certificate_key: Option<String>,
    #[serde(rename = "rawCertificate", alias = "raw_certificate")]
    pub raw_certificate: Option<Vec<String>>,
    #[serde(rename = "rawCertificateKey", alias = "raw_certificate_key")]
    pub raw_certificate_key: Option<Vec<String>>,
    pub alpn: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ChainOutboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MptpOutboundSettings {
    pub actors: Option<Vec<String>>,
    pub address: Option<String>,
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FailOverOutboundSettings {
    pub actors: Option<Vec<String>>,
    #[serde(rename = "failTimeout", alias = "fail_timeout")]
    pub fail_timeout: Option<u32>,
    #[serde(rename = "healthCheck", alias = "health_check")]
    pub health_check: Option<bool>,
    #[serde(rename = "healthCheckTimeout", alias = "health_check_timeout")]
    pub health_check_timeout: Option<u32>,
    #[serde(rename = "healthCheckDelay", alias = "health_check_delay")]
    pub health_check_delay: Option<u32>,
    #[serde(rename = "healthCheckActive", alias = "health_check_active")]
    pub health_check_active: Option<u32>,
    #[serde(rename = "healthCheckPrefers", alias = "health_check_prefers")]
    pub health_check_prefers: Option<Vec<String>>,
    #[serde(rename = "checkInterval", alias = "check_interval")]
    pub check_interval: Option<u32>,
    #[serde(rename = "healthCheckOnStart", alias = "health_check_on_start")]
    pub health_check_on_start: Option<bool>,
    #[serde(rename = "healthCheckWait", alias = "health_check_wait")]
    pub health_check_wait: Option<bool>,
    #[serde(rename = "healthCheckAttempts", alias = "health_check_attempts")]
    pub health_check_attempts: Option<u32>,
    #[serde(
        rename = "healthCheckSuccessPercentage",
        alias = "health_check_success_percentage"
    )]
    pub health_check_success_percentage: Option<u32>,
    pub failover: Option<bool>,
    #[serde(rename = "fallbackCache", alias = "fallback_cache")]
    pub fallback_cache: Option<bool>,
    #[serde(rename = "cacheSize", alias = "cache_size")]
    pub cache_size: Option<u32>,
    #[serde(rename = "cacheTimeout", alias = "cache_timeout")]
    pub cache_timeout: Option<u32>,
}

/// The `standby` group (conf: `NAME = standby, A, B, stagger=2.5, ...`).
/// Lenient (see [`compat`]): unknown keys ignored, bad tunables defaulted.
#[derive(Serialize, Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StandbyOutboundSettings {
    pub actors: Option<Vec<String>>,
    /// Seconds before the next actor starts in parallel (default 2.5).
    pub stagger: Option<f64>,
    /// Overall connect budget in seconds (default 10).
    pub timeout: Option<f64>,
    /// Consecutive failures that mark an actor down (default 3).
    pub down_after: Option<u32>,
    /// Retry backoff of a down actor in seconds (default 60 to 1800).
    pub retry_min: Option<u32>,
    pub retry_max: Option<u32>,
    /// Pre-warm the last actor when the others fail often (default false).
    pub prewarm: Option<bool>,
    /// Seconds from the first write to the first response byte (default 5).
    pub response_timeout: Option<f64>,
    /// Seconds within which an answered connection that dies counts as a
    /// failure (default 30).
    pub early_death: Option<f64>,
    /// Flap damping half-life in seconds (default 900).
    pub half_life: Option<f64>,
    /// Seconds of good service that end probation and relax the penalty
    /// (default 600).
    pub stable: Option<f64>,
    /// Seconds between discovery attempts (default 0.4).
    pub discover_stagger: Option<f64>,
    /// Attempts in flight at once (default 3).
    pub max_parallel: Option<u32>,
    /// Shuffle the actors before the last, once per device (default false).
    pub shuffle: Option<bool>,
    /// Directory of the state file (default: CACHE_LOCATION, KIRI_STATE_DIR,
    /// ASSET_LOCATION).
    pub state_dir: Option<String>,
    /// In a retry race, a retry connecting this many milliseconds after the
    /// current actor still wins (default 100).
    pub retry_grace: Option<u32>,
    /// An actor on probation gets 1 in this many new connections (default 4).
    pub probation_share: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SelectOutboundSettings {
    pub actors: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PluginOutboundSettings {
    pub path: Option<String>,
    pub args: Option<String>,
}

/// Development and lab settings of kiri (outbound and bridge).
#[derive(Serialize, Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KiriDevSettings {
    /// Transports to enable instead of the signed config's (e.g. `tcp-dev`).
    pub transports: Option<Vec<String>>,
    /// Local UDP bind addresses for WebRTC.
    pub udp_bind: Option<Vec<String>>,
    /// Announce every host candidate, loopback and private included.
    pub webrtc_all_host_candidates: Option<bool>,
    /// Extra fallback config URLs.
    pub config_fallback_urls: Option<Vec<String>>,
}

/// The `kiri` top-level object (conf: the `[Kiri]` section): settings the
/// kiri outbounds inherit, and the bridge service.
#[derive(Serialize, Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KiriSettings {
    /// ROOT public keys (64 hex characters each).
    pub root_pubkeys: Option<Vec<String>>,
    /// The signed runtime config, base64.
    pub config: Option<String>,
    pub state_dir: Option<String>,
    /// Run a kiri WebRTC bridge (volunteer) alongside leaf: the server's
    /// default, used while the user has not chosen (leaf
    /// `set_kiri_user_prefs`).
    pub bridge: Option<bool>,
    /// `"off"`: the bridge is off whatever the user chose (the server's
    /// emergency stop). Only `off` is accepted; anything else is noted and
    /// ignored.
    pub bridge_override: Option<String>,
    /// Whole-bridge rate limit in KiB/s (0 or none: unlimited).
    pub bridge_max_kbps: Option<u64>,
    /// Circuits at once (default 64).
    pub bridge_max_circuits: Option<u32>,
    /// Per-circuit rate limit in KiB/s (default 2048).
    pub bridge_circuit_kbps: Option<u64>,
    /// The bridge also offers kiri's `quic-ice/1` (QUIC on the ICE-punched
    /// socket) next to WebRTC (default true).
    pub bridge_quic_ice: Option<bool>,
    /// Accept a TLS egress by the SPKI pin of the signed config alone (kiri
    /// `--tls-pin-only`): needed for a self-signed egress, as in the pilot.
    pub tls_pin_only: Option<bool>,
    /// Who resolves kiri's host names (STUN servers, URLs): `"kiri"`
    /// (default: kiri's own resolver, DoH then plain DNS to resolvers by IP,
    /// never through leaf's tun / fake DNS) or `"system"`.
    pub resolver: Option<String>,
    /// Seconds without a stream or flow after which an outbound's client
    /// stops (0 or none: never); outbounds inherit it.
    pub idle_stop: Option<u32>,
    /// kiri streams are used before the egress connected them (default
    /// true; kiri §19.37); false waits for it, as before (A/B).
    pub optimistic_open: Option<bool>,
    pub dev: Option<KiriDevSettings>,
}

/// Settings of a `kiri` outbound; what is left out comes from [`KiriSettings`].
#[derive(Serialize, Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KiriOutboundSettings {
    pub root_pubkeys: Option<Vec<String>>,
    pub config: Option<String>,
    /// Bootstrap links (`kiri://boot/...`).
    pub bootstrap: Option<Vec<String>>,
    pub state_dir: Option<String>,
    /// Simultaneous paths per session (default 2).
    pub paths: Option<u32>,
    /// The signed config's egress to use first.
    pub egress_id: Option<String>,
    /// As [`KiriSettings::tls_pin_only`].
    pub tls_pin_only: Option<bool>,
    /// As [`KiriSettings::idle_stop`].
    pub idle_stop: Option<u32>,
    /// As [`KiriSettings::optimistic_open`].
    pub optimistic_open: Option<bool>,
    /// The outbound connections go to while the user turned kiri off (leaf
    /// `set_kiri_user_prefs`); without one they are refused.
    pub fallback: Option<String>,
    pub dev: Option<KiriDevSettings>,
}

/// JSON `dev.tlsPinOnly` (until 2026-11-12) is the top-level `tlsPinOnly`.
const KIRI_JSON_RETIRED: compat::RetiredKeys =
    &[("dev.tlsPinOnly", compat::Retired::Renamed("tlsPinOnly"))];

impl<'de> serde::Deserialize<'de> for KiriDevSettings {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut f = compat::Fields::new(d, "kiri dev", &[])?;
        let s = Self {
            transports: f.opt("transports"),
            udp_bind: f.opt("udpBind"),
            webrtc_all_host_candidates: f.opt("webrtcAllHostCandidates"),
            config_fallback_urls: f.opt("configFallbackUrls"),
        };
        f.finish();
        Ok(s)
    }
}

impl<'de> serde::Deserialize<'de> for KiriSettings {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut f = compat::Fields::new(d, "kiri", KIRI_JSON_RETIRED)?;
        let s = Self {
            root_pubkeys: f.need("rootPubkeys")?,
            config: f.need("config")?,
            state_dir: f.opt("stateDir"),
            bridge: f.opt("bridge"),
            bridge_override: f.opt("bridgeOverride"),
            bridge_max_kbps: f.opt("bridgeMaxKbps"),
            bridge_max_circuits: f.opt("bridgeMaxCircuits"),
            bridge_circuit_kbps: f.opt("bridgeCircuitKbps"),
            bridge_quic_ice: f.opt("bridgeQuicIce"),
            tls_pin_only: f.opt("tlsPinOnly"),
            resolver: f.opt("resolver"),
            idle_stop: f.opt("idleStop"),
            optimistic_open: f.opt("optimisticOpen"),
            dev: f.opt("dev"),
        };
        f.finish();
        Ok(s)
    }
}

impl<'de> serde::Deserialize<'de> for KiriOutboundSettings {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut f = compat::Fields::new(d, "kiri outbound", KIRI_JSON_RETIRED)?;
        let s = Self {
            root_pubkeys: f.need("rootPubkeys")?,
            config: f.need("config")?,
            bootstrap: f.need("bootstrap")?,
            state_dir: f.opt("stateDir"),
            paths: f.opt("paths"),
            egress_id: f.opt("egressId"),
            tls_pin_only: f.opt("tlsPinOnly"),
            idle_stop: f.opt("idleStop"),
            optimistic_open: f.opt("optimisticOpen"),
            fallback: f.opt("fallback"),
            dev: f.opt("dev"),
        };
        f.finish();
        Ok(s)
    }
}

impl<'de> serde::Deserialize<'de> for StandbyOutboundSettings {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut f = compat::Fields::new(d, "standby", &[])?;
        let s = Self {
            actors: f.need("actors")?,
            stagger: f.opt("stagger"),
            timeout: f.opt("timeout"),
            down_after: f.opt("downAfter"),
            retry_min: f.opt("retryMin"),
            retry_max: f.opt("retryMax"),
            prewarm: f.opt("prewarm"),
            response_timeout: f.opt("responseTimeout"),
            early_death: f.opt("earlyDeath"),
            half_life: f.opt("halfLife"),
            stable: f.opt("stable"),
            discover_stagger: f.opt("discoverStagger"),
            max_parallel: f.opt("maxParallel"),
            shuffle: f.opt("shuffle"),
            state_dir: f.opt("stateDir"),
            retry_grace: f.opt("retryGrace"),
            probation_share: f.opt("probationShare"),
        };
        f.finish();
        Ok(s)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Inbound {
    pub tag: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    #[serde(flatten)]
    pub settings: InboundSettings,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum InboundSettings {
    Cat {
        #[serde(default)]
        settings: Option<CatInboundSettings>,
    },
    Nf {
        #[serde(default)]
        settings: Option<NfInboundSettings>,
    },
    Shadowsocks {
        #[serde(default)]
        settings: Option<ShadowsocksInboundSettings>,
    },
    Trojan {
        #[serde(default)]
        settings: Option<TrojanInboundSettings>,
    },
    #[serde(rename = "websocket", alias = "ws")]
    WebSocket {
        #[serde(default)]
        settings: Option<WebSocketInboundSettings>,
    },
    Hc {
        #[serde(default)]
        settings: Option<HcInboundSettings>,
    },
    AMux {
        #[serde(default)]
        settings: Option<AMuxInboundSettings>,
    },
    Quic {
        #[serde(default)]
        settings: Option<QuicInboundSettings>,
    },
    Tls {
        #[serde(default)]
        settings: Option<TlsInboundSettings>,
    },
    Chain {
        #[serde(default)]
        settings: Option<ChainInboundSettings>,
    },
    Mptp {
        #[serde(default)]
        settings: Option<MptpInboundSettings>,
    },
    Tun {
        #[serde(default)]
        settings: Option<TunInboundSettings>,
    },
    Socks {
        #[serde(default)]
        settings: Option<SocksInboundSettings>,
    },
    Http,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Outbound {
    pub tag: Option<String>,
    #[serde(flatten)]
    pub settings: OutboundSettings,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum OutboundSettings {
    Redirect {
        #[serde(default)]
        settings: Option<RedirectOutboundSettings>,
    },
    Socks {
        #[serde(default)]
        settings: Option<SocksOutboundSettings>,
    },
    Shadowsocks {
        #[serde(default)]
        settings: Option<ShadowsocksOutboundSettings>,
    },
    Obfs {
        #[serde(default)]
        settings: Option<ObfsOutboundSettings>,
    },
    Trojan {
        #[serde(default)]
        settings: Option<TrojanOutboundSettings>,
    },
    VMess {
        #[serde(default)]
        settings: Option<VMessOutboundSettings>,
    },
    Vless {
        #[serde(default)]
        settings: Option<VlessOutboundSettings>,
    },
    Reality {
        #[serde(default)]
        settings: Option<RealityOutboundSettings>,
    },
    TryAll {
        #[serde(default)]
        settings: Option<TryAllOutboundSettings>,
    },
    Static {
        #[serde(default)]
        settings: Option<StaticOutboundSettings>,
    },
    Tls {
        #[serde(default)]
        settings: Option<TlsOutboundSettings>,
    },
    #[serde(rename = "websocket", alias = "ws")]
    WebSocket {
        #[serde(default)]
        settings: Option<WebSocketOutboundSettings>,
    },
    AMux {
        #[serde(default)]
        settings: Option<AMuxOutboundSettings>,
    },
    Quic {
        #[serde(default)]
        settings: Option<QuicOutboundSettings>,
    },
    Chain {
        #[serde(default)]
        settings: Option<ChainOutboundSettings>,
    },
    Mptp {
        #[serde(default)]
        settings: Option<MptpOutboundSettings>,
    },
    FailOver {
        #[serde(default)]
        settings: Option<FailOverOutboundSettings>,
    },
    Standby {
        #[serde(default)]
        settings: Option<StandbyOutboundSettings>,
    },
    Select {
        #[serde(default)]
        settings: Option<SelectOutboundSettings>,
    },
    Plugin {
        #[serde(default)]
        settings: Option<PluginOutboundSettings>,
    },
    Kiri {
        #[serde(default)]
        settings: Option<KiriOutboundSettings>,
    },
    Direct,
    Drop,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Rule {
    #[serde(rename = "type")]
    pub type_field: Option<String>,
    pub ip: Option<Vec<String>>,
    pub domain: Option<Vec<String>>,
    #[serde(rename = "domainKeyword", alias = "domain_keyword")]
    pub domain_keyword: Option<Vec<String>>,
    #[serde(rename = "domainSuffix", alias = "domain_suffix")]
    pub domain_suffix: Option<Vec<String>>,
    pub geoip: Option<Vec<String>>,
    pub external: Option<Vec<String>>,
    #[serde(rename = "portRange", alias = "port_range")]
    pub port_range: Option<Vec<String>>,
    pub network: Option<Vec<String>>,
    #[serde(rename = "inboundTag", alias = "inbound_tag")]
    pub inbound_tag: Option<Vec<String>>,
    #[serde(rename = "processName", alias = "process_name")]
    pub process_name: Option<Vec<String>>,
    pub target: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Router {
    pub rules: Option<Vec<Rule>>,
    #[serde(rename = "domainResolve", alias = "domain_resolve")]
    pub domain_resolve: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Config {
    pub log: Option<Log>,
    pub env: Option<HashMap<String, String>>,
    pub inbounds: Option<Vec<Inbound>>,
    pub outbounds: Option<Vec<Outbound>>,
    pub router: Option<Router>,
    pub dns: Option<Dns>,
    pub kiri: Option<KiriSettings>,
}

/// Seconds (fractions allowed) as whole milliseconds, 1 ms to a day.
fn standby_ms(ctx: &str, key: &str, v: Option<f64>, default: f64) -> u32 {
    let v = match v {
        Some(v) if !v.is_finite() => {
            compat::bad(ctx, key, &v.to_string(), &format!("{default}"));
            default
        }
        v => compat::clamp(ctx, key, v, default, 0.001, 86400.0),
    };
    ((v * 1000.0).round() as u32).max(1)
}

/// The internal settings of the `standby` group `tag`: unset or bad
/// tunables take their defaults, out-of-range ones are clamped (noted, see
/// [`compat`]); only a group without actors fails.
fn standby_settings(tag: &str, s: Option<&StandbyOutboundSettings>) -> Result<Vec<u8>> {
    let ctx = &format!("standby [{tag}]");
    let empty = StandbyOutboundSettings::default();
    let s = s.unwrap_or(&empty);
    let mut out = internal::StandbyOutboundSettings::new();
    out.actors = s.actors.clone().unwrap_or_default();
    if out.actors.is_empty() {
        return Err(anyhow!("standby [{tag}]: needs at least one actor"));
    }
    out.stagger_ms = standby_ms(ctx, "stagger", s.stagger, 2.5);
    out.timeout_ms = standby_ms(ctx, "timeout", s.timeout, 10.0);
    out.down_after = compat::clamp(ctx, "down-after", s.down_after, 3, 1, 1000);
    out.retry_min = compat::clamp(ctx, "retry", s.retry_min, 60, 1, u32::MAX);
    let max = s.retry_max.unwrap_or(1800.max(out.retry_min));
    out.retry_max = compat::clamp(ctx, "retry", Some(max), max, out.retry_min, u32::MAX);
    out.prewarm = s.prewarm.unwrap_or(false);
    out.response_timeout_ms = standby_ms(ctx, "response-timeout", s.response_timeout, 5.0);
    out.early_death_ms = standby_ms(ctx, "early-death", s.early_death, 30.0);
    out.half_life_ms = standby_ms(ctx, "half-life", s.half_life, 900.0);
    out.stable_ms = standby_ms(ctx, "stable", s.stable, 600.0);
    out.discover_stagger_ms = standby_ms(ctx, "discover-stagger", s.discover_stagger, 0.4);
    out.max_parallel = compat::clamp(ctx, "max-parallel", s.max_parallel, 3, 1, 64);
    out.shuffle = s.shuffle.unwrap_or(false);
    out.state_dir = s.state_dir.clone().unwrap_or_default();
    out.retry_grace_ms = compat::clamp(ctx, "retry-grace", s.retry_grace, 100, 0, 10_000);
    out.probation_share = compat::clamp(ctx, "probation-share", s.probation_share, 4, 1, 1000);
    Ok(out.write_to_bytes().unwrap())
}

fn is_inline_certificate(certificate: &str) -> bool {
    certificate.contains("-----BEGIN")
}

/// Resolves a certificate or a private key, either of which may be given
/// inline or as a path.
///
/// The two halves of a keypair are configured the same way and have to be read
/// the same way. They were not: a certificate was recognised inline and a key
/// never was, so an inline key became a path under the asset directory made of
/// PEM, and what the operator saw was "no private keys found" about a key that
/// was right there in the configuration.
fn resolve_certificate(value: &str) -> String {
    if is_inline_certificate(value) {
        return value.to_string();
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return path.to_string_lossy().to_string();
    }
    Path::new(&*crate::option::ASSET_LOCATION)
        .join(path)
        .to_string_lossy()
        .to_string()
}

fn validate_non_empty_str(value: &str, field_name: &str, protocol: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "invalid [{}] settings: {} cannot be empty",
            protocol,
            field_name
        ));
    }
    Ok(())
}

pub fn to_internal(mut config: Config) -> Result<internal::Config> {
    let mut log = internal::Log::new();
    if let Some(ext_log) = &config.log {
        if let Some(ext_level) = &ext_log.level {
            match ext_level.to_lowercase().as_str() {
                "trace" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::TRACE),
                "debug" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::DEBUG),
                "info" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::INFO),
                "warn" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::WARN),
                "error" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::ERROR),
                "none" => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::NONE),
                _ => log.level = protobuf::EnumOrUnknown::new(internal::log::Level::WARN),
            }
        }

        if let Some(ext_output) = &ext_log.output {
            match ext_output.as_str() {
                "console" => {
                    log.output = protobuf::EnumOrUnknown::new(internal::log::Output::CONSOLE)
                }
                _ => {
                    log.output = protobuf::EnumOrUnknown::new(internal::log::Output::FILE);
                    log.output_file = ext_output.clone();
                }
            }
        }

        if let Some(ext_format) = &ext_log.format {
            match ext_format.to_lowercase().as_str() {
                "compact" => {
                    log.format = protobuf::EnumOrUnknown::new(internal::log::Format::COMPACT)
                }
                _ => log.format = protobuf::EnumOrUnknown::new(internal::log::Format::FULL),
            }
        }
    }

    let mut inbounds = Vec::new();
    if let Some(ext_inbounds) = &config.inbounds {
        for ext_inbound in ext_inbounds {
            let mut inbound = internal::Inbound::new();
            if let Some(ext_tag) = &ext_inbound.tag {
                inbound.tag = ext_tag.clone();
            }
            if let Some(ext_address) = &ext_inbound.address {
                inbound.address = ext_address.to_owned();
            } else {
                inbound.address = "127.0.0.1".to_string();
            }
            if let Some(ext_port) = ext_inbound.port {
                inbound.port = ext_port as u32;
            }

            match &ext_inbound.settings {
                #[cfg(any(
                    target_os = "ios",
                    target_os = "android",
                    target_os = "macos",
                    target_os = "linux",
                    target_os = "windows"
                ))]
                InboundSettings::Tun {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "tun".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::TunInboundSettings::new();
                        let mut fake_dns_exclude = Vec::new();
                        if let Some(ext_excludes) = &ext_settings.fake_dns_exclude {
                            for ext_exclude in ext_excludes {
                                fake_dns_exclude.push(ext_exclude.clone());
                            }
                        }
                        if !fake_dns_exclude.is_empty() {
                            settings.fake_dns_exclude = fake_dns_exclude;
                        }

                        let mut fake_dns_include = Vec::new();
                        if let Some(ext_includes) = &ext_settings.fake_dns_include {
                            for ext_include in ext_includes {
                                fake_dns_include.push(ext_include.clone());
                            }
                        }
                        if !fake_dns_include.is_empty() {
                            settings.fake_dns_include = fake_dns_include;
                        }

                        let fd = ext_settings.fd.unwrap_or(-1);
                        if fd >= 0 {
                            settings.fd = fd;
                        } else {
                            settings.fd = -1; // disable fd option
                            if let Some(ext_name) = &ext_settings.name {
                                settings.name = ext_name.clone();
                            }
                            if let Some(ext_address) = &ext_settings.address {
                                settings.address = ext_address.clone();
                            }
                            if let Some(ext_gateway) = &ext_settings.gateway {
                                settings.gateway = ext_gateway.clone();
                            }
                            if let Some(ext_netmask) = &ext_settings.netmask {
                                settings.netmask = ext_netmask.clone();
                            }
                            if let Some(ext_auto) = ext_settings.auto {
                                settings.auto = ext_auto;
                            }
                            if let Some(ext_mtu) = ext_settings.mtu {
                                settings.mtu = ext_mtu;
                            } else {
                                settings.mtu = 1500;
                            }
                        }
                        if let Some(ext_tun2socks) = &ext_settings.tun2socks {
                            settings.tun2socks = ext_tun2socks.clone();
                        }
                        if let Some(ext_wintun) = &ext_settings.wintun {
                            settings.wintun = Some(ext_wintun.clone());
                        }
                        if let Some(ext_dns_servers) = &ext_settings.dns_servers {
                            for ext_dns_server in ext_dns_servers {
                                settings.dns_servers.push(ext_dns_server.clone());
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                #[cfg(not(any(
                    target_os = "ios",
                    target_os = "android",
                    target_os = "macos",
                    target_os = "linux",
                    target_os = "windows"
                )))]
                InboundSettings::Tun { .. } => {
                    return Err(anyhow::anyhow!(
                        "tun inbound is not supported on this platform"
                    ));
                }
                InboundSettings::Cat {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "cat".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::CatInboundSettings::new();
                        settings.network =
                            ext_settings.network.clone().unwrap_or("tcp".to_string());
                        settings.address = ext_settings.address.clone();
                        settings.port = ext_settings.port as u32;
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Nf {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "nf".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::NfInboundSettings::new();
                        let mut fake_dns_exclude = Vec::new();
                        if let Some(ext_excludes) = &ext_settings.fake_dns_exclude {
                            for ext_exclude in ext_excludes {
                                fake_dns_exclude.push(ext_exclude.clone());
                            }
                        }
                        if !fake_dns_exclude.is_empty() {
                            settings.fake_dns_exclude = fake_dns_exclude;
                        }

                        let mut fake_dns_include = Vec::new();
                        if let Some(ext_includes) = &ext_settings.fake_dns_include {
                            for ext_include in ext_includes {
                                fake_dns_include.push(ext_include.clone());
                            }
                        }
                        if !fake_dns_include.is_empty() {
                            settings.fake_dns_include = fake_dns_include;
                        }

                        settings.driver_name = ext_settings.driver_name.clone();
                        settings.nfapi = ext_settings
                            .nfapi
                            .clone()
                            .unwrap_or("nfapi.dll".to_string());
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Hc {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "hc".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::HcInboundSettings::new();
                        settings.path = ext_settings.path.clone();
                        settings.request = ext_settings.request.clone().unwrap_or_default();
                        settings.response = ext_settings.response.clone();
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Socks {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "socks".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::SocksInboundSettings::new();
                        if let Some(ext_username) = &ext_settings.username {
                            settings.username = ext_username.clone();
                        }
                        if let Some(ext_password) = &ext_settings.password {
                            settings.password = ext_password.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Http => {
                    inbound.protocol = "http".to_string();
                    inbounds.push(inbound);
                }
                InboundSettings::Shadowsocks {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "shadowsocks".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ShadowsocksInboundSettings::new();
                        if let Some(ext_method) = &ext_settings.method {
                            settings.method = ext_method.clone();
                        } else {
                            settings.method = "chacha20-ietf-poly1305".to_string();
                        }
                        if let Some(ext_password) = &ext_settings.password {
                            settings.password = ext_password.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Trojan {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "trojan".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::TrojanInboundSettings::new();
                        if let Some(ext_passwords) = &ext_settings.passwords {
                            for ext_pass in ext_passwords {
                                settings.passwords.push(ext_pass.clone());
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::WebSocket {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "ws".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::WebSocketInboundSettings::new();
                        match &ext_settings.path {
                            Some(ext_path) if !ext_path.is_empty() => {
                                settings.path = ext_path.clone();
                            }
                            _ => {
                                settings.path = "/".to_string();
                            }
                        };
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::AMux {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "amux".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::AMuxInboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Quic {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "quic".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::QuicInboundSettings::new();
                        if let Some(ext_raw_certificate) = &ext_settings.raw_certificate {
                            settings.certificate = ext_raw_certificate.join("\n");
                        } else if let Some(ext_certificate) = &ext_settings.certificate {
                            settings.certificate = resolve_certificate(ext_certificate);
                        }
                        if let Some(ext_raw_certificate_key) = &ext_settings.raw_certificate_key {
                            settings.certificate_key = ext_raw_certificate_key.join("\n");
                        } else if let Some(ext_certificate_key) = &ext_settings.certificate_key {
                            settings.certificate_key = resolve_certificate(ext_certificate_key);
                        }
                        if let Some(ext_alpns) = &ext_settings.alpn {
                            for ext_alpn in ext_alpns {
                                settings.alpn.push(ext_alpn.clone());
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Tls {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "tls".to_string();
                    if let Some(ext_settings) = ext_settings {
                        if ext_settings.ech_config.is_some() || ext_settings.ech_key.is_some() {
                            match (&ext_settings.ech_config, &ext_settings.ech_key) {
                                (Some(ech_config), Some(ech_key)) => {
                                    validate_non_empty_str(ech_config, "echConfig", "tls inbound")?;
                                    validate_non_empty_str(ech_key, "echKey", "tls inbound")?;
                                    return Err(anyhow::anyhow!(
                                        "invalid [tls inbound] settings: inbound ECH is not supported yet; remove echConfig and echKey"
                                    ));
                                }
                                _ => {
                                    return Err(anyhow::anyhow!(
                                        "invalid [tls inbound] settings: echConfig and echKey must be set together"
                                    ))
                                }
                            }
                        }
                        let mut settings = internal::TlsInboundSettings::new();
                        if let Some(ext_raw_certificate) = &ext_settings.raw_certificate {
                            settings.certificate = ext_raw_certificate.join("\n");
                        } else if let Some(ext_certificate) = &ext_settings.certificate {
                            settings.certificate = resolve_certificate(ext_certificate);
                        }
                        if let Some(ext_raw_certificate_key) = &ext_settings.raw_certificate_key {
                            settings.certificate_key = ext_raw_certificate_key.join("\n");
                        } else if let Some(ext_certificate_key) = &ext_settings.certificate_key {
                            settings.certificate_key = resolve_certificate(ext_certificate_key);
                        }
                        if let Some(ext_ech_config) = &ext_settings.ech_config {
                            settings.ech_config = ext_ech_config.clone();
                        }
                        if let Some(ext_ech_key) = &ext_settings.ech_key {
                            settings.ech_key = ext_ech_key.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Chain {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "chain".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ChainInboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
                InboundSettings::Mptp {
                    settings: ext_settings,
                } => {
                    inbound.protocol = "mptp".to_string();
                    if let Some(_ext_settings) = ext_settings {
                        let settings = internal::MptpInboundSettings::new();
                        let settings = settings.write_to_bytes().unwrap();
                        inbound.settings = settings;
                    }
                    inbounds.push(inbound);
                }
            }
        }
    }

    if let Some(ext_outbounds) = &config.outbounds {
        super::kiri::check_fallbacks(ext_outbounds)?;
    }
    let mut outbounds = Vec::new();
    if let Some(ext_outbounds) = &config.outbounds {
        for ext_outbound in ext_outbounds {
            let mut outbound = internal::Outbound::new();
            if let Some(ext_tag) = &ext_outbound.tag {
                outbound.tag = ext_tag.clone();
            }
            match &ext_outbound.settings {
                OutboundSettings::Kiri {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "kiri".to_string();
                    outbound.settings = super::kiri::outbound(
                        &outbound.tag,
                        ext_settings.as_ref(),
                        config.kiri.as_ref(),
                    )?;
                    outbounds.push(outbound);
                }
                OutboundSettings::Direct => {
                    outbound.protocol = "direct".to_string();
                    outbounds.push(outbound);
                }
                OutboundSettings::Drop => {
                    outbound.protocol = "drop".to_string();
                    outbounds.push(outbound);
                }
                OutboundSettings::Redirect {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "redirect".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::RedirectOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Socks {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "socks".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::SocksOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_username) = &ext_settings.username {
                            settings.username = ext_username.clone();
                        }
                        if let Some(ext_password) = &ext_settings.password {
                            settings.password = ext_password.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Shadowsocks {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "shadowsocks".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ShadowsocksOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_method) = &ext_settings.method {
                            settings.method = ext_method.clone();
                        } else {
                            settings.method = "chacha20-ietf-poly1305".to_string();
                        }
                        if let Some(ext_password) = &ext_settings.password {
                            settings.password = ext_password.clone();
                        }
                        if let Some(ext_prefix) = &ext_settings.prefix {
                            settings.prefix = Some(ext_prefix.clone());
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Obfs {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "obfs".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ObfsOutboundSettings::new();
                        if let Some(ext_method) = &ext_settings.method {
                            settings.method = ext_method.clone();
                        }
                        if let Some(ext_host) = &ext_settings.host {
                            settings.host = ext_host.clone();
                        }
                        if let Some(ext_path) = &ext_settings.path {
                            settings.path = ext_path.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Trojan {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "trojan".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::TrojanOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_password) = &ext_settings.password {
                            settings.password = ext_password.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::VMess {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "vmess".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::VMessOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_uuid) = &ext_settings.uuid {
                            settings.uuid = ext_uuid.clone();
                        }
                        if let Some(ext_security) = &ext_settings.security {
                            settings.security = ext_security.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Vless {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "vless".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::VlessOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_uuid) = &ext_settings.uuid {
                            settings.uuid = ext_uuid.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Reality {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "reality".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::RealityOutboundSettings::new();
                        if let Some(ext_server_name) = &ext_settings.server_name {
                            settings.server_name = ext_server_name.clone();
                        }
                        if let Some(ext_public_key) = &ext_settings.public_key {
                            settings.public_key = ext_public_key.clone();
                        }
                        if let Some(ext_short_id) = &ext_settings.short_id {
                            settings.short_id = ext_short_id.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Tls {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "tls".to_string();
                    if let Some(ext_settings) = ext_settings {
                        if let Some(ext_ech_config_list) = &ext_settings.ech_config_list {
                            validate_non_empty_str(
                                ext_ech_config_list,
                                "echConfigList",
                                "tls outbound",
                            )?;
                        }
                        let mut settings = internal::TlsOutboundSettings::new();
                        if let Some(ext_server_name) = &ext_settings.server_name {
                            settings.server_name = ext_server_name.clone();
                        }
                        if let Some(ext_alpn) = &ext_settings.alpn {
                            settings.alpn = ext_alpn.clone();
                        }
                        if let Some(ext_raw_certificate) = &ext_settings.raw_certificate {
                            settings.certificate = ext_raw_certificate.join("\n");
                        } else if let Some(ext_certificate) = &ext_settings.certificate {
                            settings.certificate = resolve_certificate(ext_certificate);
                        }
                        if let Some(ext_raw_certificate_key) = &ext_settings.raw_certificate_key {
                            settings.certificate_key = ext_raw_certificate_key.join("\n");
                        } else if let Some(ext_certificate_key) = &ext_settings.certificate_key {
                            settings.certificate_key = resolve_certificate(ext_certificate_key);
                        }
                        if let Some(ext_insecure) = ext_settings.insecure {
                            settings.insecure = ext_insecure;
                        }
                        if let Some(ext_ech) = ext_settings.ech {
                            settings.ech = ext_ech;
                        }
                        if let Some(ext_ech_disable_dns_lookup) =
                            ext_settings.ech_disable_dns_lookup
                        {
                            settings.ech_disable_dns_lookup = ext_ech_disable_dns_lookup;
                        }
                        if let Some(ext_ech_config_list) = &ext_settings.ech_config_list {
                            settings.ech_config_list = ext_ech_config_list.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::WebSocket {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "ws".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::WebSocketOutboundSettings::new();
                        if let Some(ext_path) = &ext_settings.path {
                            settings.path = ext_path.clone();
                        }
                        if let Some(ext_headers) = &ext_settings.headers {
                            settings.headers = ext_headers.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::TryAll {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "tryall".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::TryAllOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        if let Some(ext_delay_base) = ext_settings.delay_base {
                            settings.delay_base = ext_delay_base;
                        } else {
                            settings.delay_base = 0;
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Static {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "static".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::StaticOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        if let Some(ext_method) = &ext_settings.method {
                            settings.method = ext_method.clone();
                        } else {
                            settings.method = "random".to_string();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::FailOver {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "failover".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::FailOverOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            settings.actors.extend_from_slice(ext_actors);
                        }
                        settings.fail_timeout = ext_settings.fail_timeout.unwrap_or(4); // 4 secs
                        settings.health_check = ext_settings.health_check.unwrap_or(true);
                        settings.health_check_timeout =
                            ext_settings.health_check_timeout.unwrap_or(6); // 6 secs
                        settings.health_check_delay =
                            ext_settings.health_check_delay.unwrap_or(200); // 200ms
                        settings.health_check_active =
                            ext_settings.health_check_active.unwrap_or(15 * 60); // 15 mins
                        if let Some(ext_health_check_prefers) = &ext_settings.health_check_prefers {
                            settings
                                .health_check_prefers
                                .extend_from_slice(ext_health_check_prefers);
                        }
                        settings.health_check_on_start =
                            ext_settings.health_check_on_start.unwrap_or(false);
                        settings.health_check_wait =
                            ext_settings.health_check_wait.unwrap_or(false);
                        settings.health_check_attempts =
                            ext_settings.health_check_attempts.unwrap_or(1);
                        settings.health_check_success_percentage =
                            ext_settings.health_check_success_percentage.unwrap_or(50);
                        settings.check_interval = ext_settings.check_interval.unwrap_or(300); // 300 secs
                        settings.failover = ext_settings.failover.unwrap_or(true);
                        settings.fallback_cache = ext_settings.fallback_cache.unwrap_or(false);
                        settings.cache_size = ext_settings.cache_size.unwrap_or(256);
                        settings.cache_timeout = ext_settings.cache_timeout.unwrap_or(60); // 60 mins
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Standby {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "standby".to_string();
                    outbound.settings = standby_settings(&outbound.tag, ext_settings.as_ref())?;
                    outbounds.push(outbound);
                }
                OutboundSettings::AMux {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "amux".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::AMuxOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        settings.max_accepts = ext_settings.max_accepts.unwrap_or(8);
                        settings.concurrency = ext_settings.concurrency.unwrap_or(2);
                        settings.max_recv_bytes = ext_settings.max_recv_bytes.unwrap_or_default();
                        settings.max_lifetime = ext_settings.max_lifetime.unwrap_or_default();
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Quic {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "quic".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::QuicOutboundSettings::new();
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        if let Some(ext_server_name) = &ext_settings.server_name {
                            settings.server_name = ext_server_name.clone();
                        }
                        if let Some(ext_raw_certificate) = &ext_settings.raw_certificate {
                            settings.certificate = ext_raw_certificate.join("\n");
                        } else if let Some(ext_certificate) = &ext_settings.certificate {
                            settings.certificate = resolve_certificate(ext_certificate);
                        }
                        if let Some(ext_raw_certificate_key) = &ext_settings.raw_certificate_key {
                            settings.certificate_key = ext_raw_certificate_key.join("\n");
                        } else if let Some(ext_certificate_key) = &ext_settings.certificate_key {
                            settings.certificate_key = resolve_certificate(ext_certificate_key);
                        }
                        if let Some(ext_alpns) = &ext_settings.alpn {
                            settings.alpn = ext_alpns.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Chain {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "chain".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::ChainOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Mptp {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "mptp".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::MptpOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        if let Some(ext_address) = &ext_settings.address {
                            settings.address = ext_address.clone();
                        }
                        if let Some(ext_port) = ext_settings.port {
                            settings.port = ext_port as u32;
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Select {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "select".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::SelectOutboundSettings::new();
                        if let Some(ext_actors) = &ext_settings.actors {
                            for ext_actor in ext_actors {
                                settings.actors.push(ext_actor.clone());
                            }
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
                OutboundSettings::Plugin {
                    settings: ext_settings,
                } => {
                    outbound.protocol = "plugin".to_string();
                    if let Some(ext_settings) = ext_settings {
                        let mut settings = internal::PluginOutboundSettings::new();
                        if let Some(ext_path) = &ext_settings.path {
                            settings.path = ext_path.clone();
                        }
                        if let Some(ext_args) = &ext_settings.args {
                            settings.args = ext_args.clone();
                        }
                        let settings = settings.write_to_bytes().unwrap();
                        outbound.settings = settings;
                    }
                    outbounds.push(outbound);
                }
            }
        }
    }

    let mut router = protobuf::MessageField::none();
    if let Some(ext_router) = config.router.as_mut() {
        let mut int_router = internal::Router::new();
        let mut rules = Vec::new();
        if let Some(ext_rules) = ext_router.rules.as_mut() {
            for ext_rule in ext_rules.iter_mut() {
                let mut rule = internal::router::Rule::new();
                let target_tag = std::mem::take(&mut ext_rule.target);
                rule.target_tag = target_tag;

                // handle FINAL rule first
                if let Some(type_field) = &ext_rule.type_field {
                    if type_field == "FINAL" {
                        // reorder outbounds to make the FINAL one first
                        let mut idx = None;
                        for (i, v) in outbounds.iter().enumerate() {
                            if v.tag == rule.target_tag {
                                idx = Some(i);
                            }
                        }
                        if let Some(idx) = idx {
                            let final_ob = outbounds.remove(idx);
                            outbounds.insert(0, final_ob);
                        }
                        continue;
                    }
                }

                if let Some(ext_ips) = ext_rule.ip.as_mut() {
                    for ext_ip in ext_ips.drain(0..) {
                        rule.ip_cidrs.push(ext_ip);
                    }
                }
                if let Some(ext_domains) = ext_rule.domain.as_mut() {
                    for ext_domain in ext_domains.drain(0..) {
                        let mut domain = internal::router::rule::Domain::new();
                        domain.type_ = protobuf::EnumOrUnknown::new(
                            internal::router::rule::domain::Type::FULL,
                        );
                        domain.value = ext_domain;
                        rule.domains.push(domain);
                    }
                }
                if let Some(ext_domain_keywords) = ext_rule.domain_keyword.as_mut() {
                    for ext_domain_keyword in ext_domain_keywords.drain(0..) {
                        let mut domain = internal::router::rule::Domain::new();
                        domain.type_ = protobuf::EnumOrUnknown::new(
                            internal::router::rule::domain::Type::PLAIN,
                        );
                        domain.value = ext_domain_keyword;
                        rule.domains.push(domain);
                    }
                }
                if let Some(ext_domain_suffixes) = ext_rule.domain_suffix.as_mut() {
                    for ext_domain_suffix in ext_domain_suffixes.drain(0..) {
                        let mut domain = internal::router::rule::Domain::new();
                        domain.type_ = protobuf::EnumOrUnknown::new(
                            internal::router::rule::domain::Type::DOMAIN,
                        );
                        domain.value = ext_domain_suffix;
                        rule.domains.push(domain);
                    }
                }
                if let Some(ext_geoips) = ext_rule.geoip.as_mut() {
                    for ext_geoip in ext_geoips.drain(0..) {
                        let mut mmdb = internal::router::rule::Mmdb::new();
                        let asset_loc = Path::new(&*crate::option::ASSET_LOCATION);
                        mmdb.file = asset_loc.join("geo.mmdb").to_string_lossy().to_string();
                        mmdb.country_code = ext_geoip;
                        rule.mmdbs.push(mmdb)
                    }
                }
                if let Some(ext_externals) = ext_rule.external.as_mut() {
                    for ext_external in ext_externals.drain(0..) {
                        match external_rule::add_external_rule(&mut rule, &ext_external) {
                            Ok(_) => (),
                            Err(e) => {
                                println!("load external rule failed: {}", e);
                            }
                        }
                    }
                }
                if let Some(ext_port_ranges) = ext_rule.port_range.as_mut() {
                    for ext_port_range in ext_port_ranges.drain(0..) {
                        rule.port_ranges.push(ext_port_range);
                    }
                }
                if let Some(ext_networks) = ext_rule.network.as_mut() {
                    for ext_network in ext_networks.drain(0..) {
                        rule.networks.push(ext_network);
                    }
                }
                if let Some(ext_its) = ext_rule.inbound_tag.as_mut() {
                    for it in ext_its.drain(0..) {
                        rule.inbound_tags.push(it);
                    }
                }
                #[cfg(feature = "rule-process-name")]
                if let Some(ext_process_names) = ext_rule.process_name.as_mut() {
                    for process_name in ext_process_names.drain(0..) {
                        rule.process_names.push(process_name);
                    }
                }
                rules.push(rule);
            }
        }
        int_router.rules = rules;
        if let Some(ext_domain_resolve) = ext_router.domain_resolve {
            int_router.domain_resolve = ext_domain_resolve;
        }
        router = protobuf::MessageField::some(int_router);
    }

    let mut dns = internal::Dns::new();
    let mut servers = Vec::new();
    let mut hosts = HashMap::new();
    if let Some(ext_dns) = &config.dns {
        if let Some(ext_servers) = ext_dns.servers.as_ref() {
            for ext_server in ext_servers {
                servers.push(ext_server.to_owned());
            }
        }
        if let Some(ext_hosts) = ext_dns.hosts.as_ref() {
            for (name, static_ips) in ext_hosts.iter() {
                let mut ips = internal::dns::Ips::new();
                let mut ip_vals = Vec::new();
                for ip in static_ips {
                    ip_vals.push(ip.to_owned());
                }
                ips.values = ip_vals;
                hosts.insert(name.to_owned(), ips);
            }
        }
    }
    if servers.is_empty() {
        servers.push("1.1.1.1".to_string());
    }
    dns.servers = servers;
    if !hosts.is_empty() {
        dns.hosts = hosts;
    }

    let kiri_section = config.kiri.take();
    let mut config = internal::Config::new();
    config.log = protobuf::MessageField::some(log);
    config.inbounds = inbounds;
    config.outbounds = outbounds;
    config.router = router;
    config.dns = protobuf::MessageField::some(dns);
    if let Some(k) = super::kiri::section(kiri_section.as_ref())? {
        config.kiri = protobuf::MessageField::some(k);
    }
    config.notes = compat::take();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INLINE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGH\n-----END PRIVATE KEY-----\n";

    /// Both halves of a keypair are configured the same way and have to be
    /// read the same way. The key was not: it was always taken for a path, so
    /// an inline one became a filename made of PEM under the asset directory,
    /// and what the operator saw was "no private keys found" about a key that
    /// was right there in the configuration.
    #[test]
    fn an_inline_key_is_not_mistaken_for_a_path() {
        assert_eq!(resolve_certificate(INLINE_KEY), INLINE_KEY);
    }

    /// What counts as absolute is the platform's business, and the test has to
    /// ask the same question the code does. A leading slash is a whole path on
    /// Unix; on Windows it names the root of whichever drive is current, so
    /// `resolve_certificate` resolves it against the asset directory like any
    /// other relative path -- correctly, and to something no assertion written
    /// for Unix would recognise.
    #[test]
    fn an_absolute_path_is_left_alone() {
        let absolute = if cfg!(windows) {
            r"C:\leaf\cert.pem"
        } else {
            "/etc/leaf/cert.pem"
        };
        assert_eq!(resolve_certificate(absolute), absolute);
    }

    /// A relative path is still resolved against the asset directory, which is
    /// what makes `"certificate": "cert.pem"` work in a config file.
    #[test]
    fn a_relative_path_is_resolved_against_the_asset_directory() {
        let resolved = resolve_certificate("cert.pem");
        assert!(
            resolved.ends_with("cert.pem") && resolved != "cert.pem",
            "expected a path under the asset directory, got {}",
            resolved
        );
    }
}

/// The `standby` group from conf and JSON: defaults, every setting, and bad
/// values refused.
#[cfg(all(test, feature = "config-conf", feature = "config-json"))]
mod standby_tests {
    use protobuf::Message;

    use crate::config::internal::{Config, StandbyOutboundSettings};

    fn conf(group: &str) -> anyhow::Result<Config> {
        crate::config::conf::from_string(&format!(
            "[Proxy]\nA = direct\nB = direct\nC = drop\n\n[Proxy Group]\n{group}\n"
        ))
    }

    fn json(settings: &str) -> anyhow::Result<Config> {
        crate::config::json::from_string(&format!(
            r#"{{ "outbounds": [{{ "protocol": "direct", "tag": "A" }}, {{ "protocol": "direct", "tag": "B" }},
                {{ "protocol": "standby", "tag": "Auto", "settings": {{ {settings} }} }}] }}"#
        ))
    }

    fn standby(c: &Config) -> StandbyOutboundSettings {
        let o = c.outbounds.iter().find(|o| o.tag == "Auto").expect("Auto");
        assert_eq!(o.protocol, "standby");
        StandbyOutboundSettings::parse_from_bytes(&o.settings).unwrap()
    }

    #[test]
    fn conf_defaults_and_every_setting() {
        let s = standby(&conf("Auto = standby, A, B, C").unwrap());
        assert_eq!(s.actors, vec!["A", "B", "C"]);
        assert_eq!(
            (
                s.stagger_ms,
                s.timeout_ms,
                s.down_after,
                s.retry_min,
                s.retry_max,
                s.prewarm
            ),
            (2500, 10000, 3, 60, 1800, false)
        );
        let s = standby(
            &conf("Auto = standby, A, C, stagger=0.3, timeout=4, down-after=2, retry=1-4, prewarm=true")
                .unwrap(),
        );
        assert_eq!(s.actors, vec!["A", "C"]);
        assert_eq!(
            (
                s.stagger_ms,
                s.timeout_ms,
                s.down_after,
                s.retry_min,
                s.retry_max,
                s.prewarm
            ),
            (300, 4000, 2, 1, 4, true)
        );
        let s = standby(
            &conf("Auto = standby, A, B, response-timeout=1.5, early-death=2, half-life=60, stable=3, \
                   discover-stagger=0.1, max-parallel=2, shuffle=true, state-dir=/tmp/x")
            .unwrap(),
        );
        assert_eq!(
            (
                s.response_timeout_ms,
                s.early_death_ms,
                s.half_life_ms,
                s.stable_ms,
                s.discover_stagger_ms
            ),
            (1500, 2000, 60000, 3000, 100)
        );
        assert_eq!(
            (s.max_parallel, s.shuffle, s.state_dir.as_str()),
            (2, true, "/tmp/x")
        );
        let d = standby(&conf("Auto = standby, A").unwrap());
        assert_eq!(
            (
                d.response_timeout_ms,
                d.early_death_ms,
                d.half_life_ms,
                d.stable_ms,
                d.discover_stagger_ms
            ),
            (5000, 30000, 900000, 600000, 400)
        );
        assert_eq!(
            (d.max_parallel, d.shuffle, d.state_dir.as_str()),
            (3, false, "")
        );
        // One number: a fixed retry interval.
        let s = standby(&conf("Auto = standby, A, retry=30").unwrap());
        assert_eq!((s.retry_min, s.retry_max), (30, 30));
        // A minimum above the default maximum raises the maximum with it.
        let s = json(r#""actors": ["A"], "retryMin": 3600"#).unwrap();
        assert_eq!((standby(&s).retry_min, standby(&s).retry_max), (3600, 3600));
    }

    #[test]
    fn json_every_setting() {
        let s = standby(
            &json(r#""actors": ["A", "B"], "stagger": 0.5, "timeout": 3, "downAfter": 4, "retryMin": 2, "retryMax": 8, "prewarm": true, "responseTimeout": 1, "earlyDeath": 2, "halfLife": 3, "stable": 4, "discoverStagger": 0.2, "maxParallel": 5, "shuffle": true, "stateDir": "/s""#)
                .unwrap(),
        );
        assert_eq!(s.actors, vec!["A", "B"]);
        assert_eq!(
            (
                s.stagger_ms,
                s.timeout_ms,
                s.down_after,
                s.retry_min,
                s.retry_max,
                s.prewarm
            ),
            (500, 3000, 4, 2, 8, true)
        );
        assert_eq!(
            (
                s.response_timeout_ms,
                s.early_death_ms,
                s.half_life_ms,
                s.stable_ms,
                s.discover_stagger_ms,
                s.max_parallel
            ),
            (1000, 2000, 3000, 4000, 200, 5)
        );
        assert!(s.shuffle && s.state_dir == "/s");
    }

    fn note(c: &Config, key: &str) -> String {
        c.notes
            .iter()
            .find(|n| n.key == key)
            .unwrap_or_else(|| panic!("no note on {key}: {:?}", c.notes))
            .message
            .clone()
    }

    /// Bad values fall back to the default, out-of-range ones are clamped,
    /// unknown keys are ignored, each with a note; good settings next to
    /// them are kept. Before: each of these failed the load ("must be a
    /// number", "must be at least 1", "retry must be MIN-MAX", "unknown
    /// setting health-check", ...).
    #[test]
    fn conf_bad_values_default_clamp_and_unknown_keys_load() {
        let d = standby(&conf("Auto = standby, A").unwrap());
        for (line, key, want) in [
            ("stagger=fast", "stagger", "the default (want seconds)"),
            ("stagger=0", "stagger", "0 out of range, 0.001 used"),
            ("timeout=-1", "timeout", "-1 out of range, 0.001 used"),
            ("half-life=999999", "half-life", "out of range, 86400 used"),
            ("down-after=0", "down-after", "0 out of range, 1 used"),
            ("down-after=x", "down-after", "want a number"),
            ("retry=10-5", "retry", "5 out of range, 10 used"),
            ("retry=0-5", "retry", "0 out of range, 1 used"),
            ("retry=a-b", "retry", "want MIN-MAX seconds"),
            ("prewarm=yes", "prewarm", "true or false"),
            (
                "health-check=true",
                "health-check",
                "unknown setting, ignored",
            ),
            ("response-timeout=0", "response-timeout", "out of range"),
            ("max-parallel=0", "max-parallel", "0 out of range, 1 used"),
            ("shuffle=1", "shuffle", "true or false"),
            ("early-death=x", "early-death", "want seconds"),
            ("retry-grace=soon", "retry-grace", "want a number"),
            (
                "retry-grace=60000",
                "retry-grace",
                "60000 out of range, 10000 used",
            ),
            (
                "probation-share=0",
                "probation-share",
                "0 out of range, 1 used",
            ),
        ] {
            let c = conf(&format!("Auto = standby, A, B, {line}, stable=3"))
                .unwrap_or_else(|e| panic!("{line}: {e}"));
            let n = note(&c, &format!("standby [Auto] {key}"));
            assert!(n.contains(want), "{line}: {n}");
            assert_eq!(standby(&c).stable_ms, 3000, "{line}: good setting lost");
        }
        let s = |line: &str| standby(&conf(&format!("Auto = standby, A, {line}")).unwrap());
        assert_eq!(s("stagger=fast").stagger_ms, d.stagger_ms);
        assert_eq!(s("stagger=0").stagger_ms, 1);
        assert_eq!(s("down-after=0").down_after, 1);
        assert_eq!(s("down-after=x").down_after, 3);
        let r = s("retry=10-5");
        assert_eq!((r.retry_min, r.retry_max), (10, 10));
        let r = s("retry=a-b");
        assert_eq!((r.retry_min, r.retry_max), (60, 1800));
        assert_eq!(s("max-parallel=0").max_parallel, 1);
        assert_eq!(s("prewarm=yes").prewarm, false);
        assert_eq!(s("retry-grace=soon").retry_grace_ms, 100);
        assert_eq!(s("retry-grace=60000").retry_grace_ms, 10000);
        assert_eq!(s("probation-share=0").probation_share, 1);
        assert_eq!(s("health-check=true"), d, "an unknown key changes nothing");
    }

    /// `retry-grace` (ms, default 100) and `probation-share` (1 in N,
    /// default 4), conf and JSON.
    #[test]
    fn retry_grace_and_probation_share() {
        let d = standby(&conf("Auto = standby, A").unwrap());
        assert_eq!((d.retry_grace_ms, d.probation_share), (100, 4));
        let s = standby(&conf("Auto = standby, A, retry-grace=0, probation-share=10").unwrap());
        assert_eq!((s.retry_grace_ms, s.probation_share), (0, 10));
        let s =
            standby(&json(r#""actors": ["A"], "retryGrace": 250, "probationShare": 2"#).unwrap());
        assert_eq!((s.retry_grace_ms, s.probation_share), (250, 2));
    }

    /// JSON: only a group without actors (or with actors that are not a
    /// list) fails; unknown fields and bad values load with notes. Before:
    /// "unknown field" and each bad value failed the load.
    #[test]
    fn json_only_actors_are_essential() {
        for (settings, want) in [
            (r#""actors": []"#, "at least one actor"),
            (r#""stagger": 1"#, "at least one actor"),
            (r#""actors": "A""#, "standby actors"),
        ] {
            let e = json(settings).map(|_| ()).expect_err(settings);
            assert!(e.to_string().contains(want), "{settings}: {e}");
        }
        let c = json(
            r#""actors": ["A"], "colour": 1, "stagger": 0, "retryMin": 9, "retryMax": 3, "maxParallel": "x", "stable": 3"#,
        )
        .unwrap();
        let s = standby(&c);
        assert_eq!(
            (
                s.stagger_ms,
                s.retry_min,
                s.retry_max,
                s.max_parallel,
                s.stable_ms
            ),
            (1, 9, 9, 3, 3000)
        );
        assert!(note(&c, "standby colour").contains("unknown setting"));
        assert!(note(&c, "standby maxParallel").contains("\"x\" not valid"));
        assert!(note(&c, "standby [Auto] stagger").contains("out of range"));
        assert!(note(&c, "standby [Auto] retry").contains("3 out of range, 9 used"));
    }
}
