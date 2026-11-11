//! kiri settings (the `kiri` outbound and the `[Kiri]` section / `kiri`
//! object) from the common config to the internal one: checked here, so a
//! bad setting fails the config load instead of the first connection.
//!
//! An outbound takes what it leaves out (ROOT keys, signed config, state
//! directory, dev settings) from the section. Without the leaf features the
//! settings are refused with a message naming the feature.

use anyhow::{anyhow, bail, Result};

#[cfg(feature = "kiri-host")]
use crate::config::common::KiriDevSettings;
use crate::config::common::{KiriOutboundSettings, KiriSettings};

#[cfg(feature = "outbound-kiri")]
use protobuf::Message;

#[cfg(feature = "kiri-host")]
use crate::config::internal;

/// Most paths a session may use at once.
#[cfg(feature = "outbound-kiri")]
pub const MAX_PATHS: u32 = 8;

#[cfg(feature = "kiri-host")]
fn root_keys(v: &[String]) -> Result<Vec<Vec<u8>>> {
    v.iter()
        .map(|k| {
            let k = k.trim();
            if k.len() != 64 || !k.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("kiri root-pubkey must be 64 hex characters");
            }
            Ok((0..32)
                .map(|i| u8::from_str_radix(&k[2 * i..2 * i + 2], 16).unwrap())
                .collect())
        })
        .collect()
}

/// Standard or URL-safe base64, padding optional.
#[cfg(feature = "kiri-host")]
fn signed_config(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    let s = s.trim();
    let raw = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(s).ok())
        .ok_or_else(|| anyhow!("kiri config must be base64 (a signed config)"))?;
    if raw.is_empty() {
        bail!("kiri config is empty");
    }
    Ok(raw)
}

#[cfg(feature = "kiri-host")]
fn dev(d: Option<&KiriDevSettings>) -> internal::KiriDev {
    let mut out = internal::KiriDev::new();
    if let Some(d) = d {
        out.transports = d.transports.clone().unwrap_or_default();
        out.udp_bind = d.udp_bind.clone().unwrap_or_default();
        out.webrtc_all_host_candidates = d.webrtc_all_host_candidates.unwrap_or(false);
        out.tls_pin_only = d.tls_pin_only.unwrap_or(false);
        out.config_fallback_urls = d.config_fallback_urls.clone().unwrap_or_default();
    }
    out
}

/// The internal settings of the `kiri` outbound `tag`.
#[cfg(feature = "outbound-kiri")]
pub fn outbound(
    tag: &str,
    o: Option<&KiriOutboundSettings>,
    section: Option<&KiriSettings>,
) -> Result<Vec<u8>> {
    let empty = KiriOutboundSettings::default();
    let o = o.unwrap_or(&empty);
    let sec = section.cloned().unwrap_or_default();
    let mut s = internal::KiriOutboundSettings::new();
    let roots = o.root_pubkeys.as_ref().or(sec.root_pubkeys.as_ref());
    s.root_pubkeys = root_keys(roots.map(Vec::as_slice).unwrap_or_default())?;
    if s.root_pubkeys.is_empty() {
        bail!("kiri outbound [{tag}] needs root-pubkey (here or in [Kiri])");
    }
    if let Some(c) = o.config.as_ref().or(sec.config.as_ref()) {
        s.signed_config = signed_config(c)?;
    }
    s.bootstrap = o.bootstrap.clone().unwrap_or_default();
    for b in &s.bootstrap {
        if !b.starts_with("kiri://boot/") {
            bail!("kiri bootstrap must be a kiri://boot/... link");
        }
    }
    if s.signed_config.is_empty() && s.bootstrap.is_empty() {
        bail!("kiri outbound [{tag}] needs a config (here or in [Kiri]) or a bootstrap link");
    }
    s.state_dir = o
        .state_dir
        .clone()
        .or(sec.state_dir.clone())
        .unwrap_or_default();
    s.paths = o.paths.unwrap_or(2);
    if s.paths == 0 || s.paths > MAX_PATHS {
        bail!("kiri paths must be 1 to {MAX_PATHS}");
    }
    s.egress_id = o.egress_id.clone().unwrap_or_default();
    s.dev = protobuf::MessageField::some(dev(o.dev.as_ref().or(sec.dev.as_ref())));
    Ok(s.write_to_bytes().unwrap())
}

#[cfg(not(feature = "outbound-kiri"))]
pub fn outbound(
    tag: &str,
    _o: Option<&KiriOutboundSettings>,
    _section: Option<&KiriSettings>,
) -> Result<Vec<u8>> {
    Err(anyhow!(
        "outbound [{tag}]: kiri is not built in (leaf feature `outbound-kiri`)"
    ))
}

/// The internal `[Kiri]` section, if there is one.
#[cfg(feature = "kiri-host")]
pub fn section(k: Option<&KiriSettings>) -> Result<Option<internal::Kiri>> {
    let Some(k) = k else { return Ok(None) };
    let mut s = internal::Kiri::new();
    s.root_pubkeys = root_keys(k.root_pubkeys.as_deref().unwrap_or_default())?;
    if let Some(c) = &k.config {
        s.signed_config = signed_config(c)?;
    }
    s.state_dir = k.state_dir.clone().unwrap_or_default();
    s.bridge = k.bridge.unwrap_or(false);
    s.bridge_max_kbps = k.bridge_max_kbps.unwrap_or(0);
    s.bridge_max_circuits = k.bridge_max_circuits.unwrap_or(0);
    s.bridge_circuit_kbps = k.bridge_circuit_kbps.unwrap_or(0);
    s.dev = protobuf::MessageField::some(dev(k.dev.as_ref()));
    if s.bridge {
        if !cfg!(feature = "kiri-bridge") {
            bail!("[Kiri] bridge: not built in (leaf feature `kiri-bridge`)");
        }
        if s.root_pubkeys.is_empty() || s.signed_config.is_empty() {
            bail!("[Kiri] bridge needs root-pubkey and config");
        }
    }
    Ok(Some(s))
}

/// Without kiri a section is refused only when it asks for the bridge.
#[cfg(not(feature = "kiri-host"))]
pub fn section(k: Option<&KiriSettings>) -> Result<Option<crate::config::internal::Kiri>> {
    if k.and_then(|k| k.bridge).unwrap_or(false) {
        bail!("[Kiri] bridge: not built in (leaf feature `kiri-bridge`)");
    }
    Ok(None)
}

#[cfg(all(test, feature = "kiri"))]
mod tests {
    use protobuf::Message;

    use crate::config::internal::{Config, KiriOutboundSettings};

    const K1: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const K2: &str = "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
    /// Base64 with `+`, `/` and padding: the bytes 0 1 2 255 239.
    const CFG: &str = "AAEC/+8=";

    fn conf(kiri: &str, proxy: &str) -> anyhow::Result<Config> {
        crate::config::conf::from_string(&format!(
            "[General]\nsocks-interface = 127.0.0.1\nsocks-port = 1086\n\n[Kiri]\n{kiri}\n\n[Proxy]\n{proxy}\n"
        ))
    }

    fn outbound(c: &Config, tag: &str) -> KiriOutboundSettings {
        let o = c.outbounds.iter().find(|o| o.tag == tag).expect("outbound");
        assert_eq!(o.protocol, "kiri");
        KiriOutboundSettings::parse_from_bytes(&o.settings).unwrap()
    }

    #[test]
    fn conf_outbound_inherits_the_section() {
        let c = conf(
            &format!("root-pubkey = {K1}, {K2}\nconfig = {CFG}\nstate-dir = /var/kiri\nbridge = true\nbridge-max-kbps = 512\nbridge-max-circuits = 8\nbridge-circuit-kbps = 256"),
            &format!(
                "Kiri = kiri, paths=3, egress-id=eu1, bootstrap=kiri://boot/AbC-_9, bootstrap=kiri://boot/x\n\
                 Own = kiri, root-pubkey={K2}, config=AQ, state-dir=/own, transport=tcp-dev, udp-bind=127.0.0.1:0, \
                 webrtc-all-host-candidates=true, config-fallback-url=http://127.0.0.1:1"
            ),
        )
        .unwrap();
        let k = outbound(&c, "Kiri");
        assert_eq!(k.root_pubkeys, vec![vec![1u8; 32], vec![0xa2u8; 32]]);
        assert_eq!(k.signed_config, vec![0, 1, 2, 255, 239]);
        assert_eq!(k.state_dir, "/var/kiri");
        assert_eq!((k.paths, k.egress_id.as_str()), (3, "eu1"));
        assert_eq!(k.bootstrap, vec!["kiri://boot/AbC-_9", "kiri://boot/x"]);
        let o = outbound(&c, "Own");
        assert_eq!(
            o.root_pubkeys,
            vec![vec![0xa2u8; 32]],
            "its own keys replace the section's"
        );
        assert_eq!(
            (o.signed_config.as_slice(), o.state_dir.as_str(), o.paths),
            (&[1u8][..], "/own", 2)
        );
        let d = o.dev.as_ref().unwrap();
        assert_eq!(
            (d.transports.clone(), d.udp_bind.clone()),
            (vec!["tcp-dev".to_string()], vec!["127.0.0.1:0".to_string()])
        );
        assert!(d.webrtc_all_host_candidates);
        assert_eq!(d.config_fallback_urls, vec!["http://127.0.0.1:1"]);
        let s = c.kiri.as_ref().unwrap();
        assert!(s.bridge);
        assert_eq!(
            (
                s.bridge_max_kbps,
                s.bridge_max_circuits,
                s.bridge_circuit_kbps
            ),
            (512, 8, 256)
        );
        assert_eq!(
            (
                s.root_pubkeys.len(),
                s.signed_config.len(),
                s.state_dir.as_str()
            ),
            (2, 5, "/var/kiri")
        );
    }

    /// The Apple apps' conf: a tun inbound from the packet tunnel's fd, the
    /// kiri state in the App Group container (a path with a space:
    /// `~/Library/Group Containers/...` on macOS), a bridge and an outbound,
    /// both trusting a self-signed egress by its pin (`tls-pin-only`).
    #[test]
    fn conf_apple_tunnel_with_app_group_state_dir() {
        let dir = "/Users/u/Library/Group Containers/group.io.example.demo/kiri";
        let c = crate::config::conf::from_string(&format!(
            "[General]\nloglevel = debug\ndns-server = 1.1.1.1\ntun-fd = 7\n\n\
             [Kiri]\nroot-pubkey = {K1}\nconfig = {CFG}\nstate-dir = {dir}\nbridge = true\ntls-pin-only = true\n\n\
             [Proxy]\nKiri = kiri\n\n[Rule]\nFINAL, Kiri\n"
        ))
        .unwrap();
        let o = outbound(&c, "Kiri");
        assert_eq!(o.state_dir, dir);
        assert!(
            o.dev.as_ref().unwrap().tls_pin_only,
            "outbound inherits tls-pin-only"
        );
        let s = c.kiri.as_ref().unwrap();
        assert_eq!((s.state_dir.as_str(), s.bridge), (dir, true));
        assert!(
            s.dev.as_ref().unwrap().tls_pin_only,
            "bridge has tls-pin-only"
        );
        let tun = c
            .inbounds
            .iter()
            .find(|i| i.protocol == "tun")
            .expect("tun inbound");
        let t =
            crate::config::internal::TunInboundSettings::parse_from_bytes(&tun.settings).unwrap();
        assert_eq!(t.fd, 7);
    }

    #[test]
    fn conf_bridge_alone_and_no_section() {
        let c = conf(
            &format!("root-pubkey = {K1}\nconfig = {CFG}\nbridge = true"),
            "Direct = direct",
        )
        .unwrap();
        assert!(c.kiri.as_ref().unwrap().bridge);
        assert_eq!(c.outbounds.len(), 1);
        let c = crate::config::conf::from_string("[Proxy]\nDirect = direct\n").unwrap();
        assert!(c.kiri.is_none());
    }

    #[test]
    fn conf_bad_settings_are_refused() {
        let ok = format!("root-pubkey = {K1}\nconfig = {CFG}");
        let cases: Vec<(String, String, &str)> = vec![
            (
                format!("root-pubkey = {}\nconfig = {CFG}", &K1[..62]),
                "K = kiri".into(),
                "64 hex",
            ),
            (
                format!("root-pubkey = {}zz\nconfig = {CFG}", &K1[..62]),
                "K = kiri".into(),
                "64 hex",
            ),
            (
                format!("root-pubkey = {K1}\nconfig = not*base64"),
                "K = kiri".into(),
                "base64",
            ),
            (ok.clone(), "K = kiri, paths=0".into(), "paths"),
            (ok.clone(), "K = kiri, paths=9".into(), "paths"),
            (ok.clone(), "K = kiri, paths=two".into(), "number"),
            (
                ok.clone(),
                "K = kiri, colour=red".into(),
                "unknown setting colour",
            ),
            (ok.clone(), "K = kiri, bootstrap".into(), "key=value"),
            (
                ok.clone(),
                "K = kiri, bootstrap=https://x".into(),
                "kiri://boot/",
            ),
            (format!("config = {CFG}"), "K = kiri".into(), "root-pubkey"),
            (format!("root-pubkey = {K1}"), "K = kiri".into(), "config"),
            (
                format!("{ok}\nbridge = yes"),
                "D = direct".into(),
                "true or false",
            ),
            (
                format!("{ok}\ntls-pin-only = 1"),
                "K = kiri".into(),
                "true or false",
            ),
            (
                format!("{ok}\nbridge-max-kbps = -1"),
                "D = direct".into(),
                "number",
            ),
            (
                format!("{ok}\nbridges = true"),
                "D = direct".into(),
                "unknown setting bridges",
            ),
            (
                format!("root-pubkey = {K1}\nbridge = true"),
                "D = direct".into(),
                "bridge needs",
            ),
        ];
        for (kiri, proxy, want) in cases {
            let e = conf(&kiri, &proxy)
                .map(|_| ())
                .expect_err(&format!("{kiri} / {proxy}"));
            assert!(e.to_string().contains(want), "{kiri} / {proxy}: {e}");
        }
        // A bootstrap link alone is enough for an outbound (it carries a config).
        let c = conf(
            &format!("root-pubkey = {K1}"),
            "K = kiri, bootstrap=kiri://boot/x",
        )
        .unwrap();
        assert!(outbound(&c, "K").signed_config.is_empty());
    }

    fn json(kiri: &str, settings: &str) -> anyhow::Result<Config> {
        crate::config::json::from_string(&format!(
            r#"{{ {kiri} "outbounds": [{{ "protocol": "kiri", "tag": "kiri", "settings": {{ {settings} }} }}] }}"#
        ))
    }

    #[test]
    fn json_outbound_and_section() {
        let c = json(
            &format!(r#""kiri": {{ "rootPubkeys": ["{K1}"], "config": "{CFG}", "stateDir": "/s", "bridge": true, "bridgeMaxKbps": 100, "bridgeMaxCircuits": 4, "dev": {{ "udpBind": ["127.0.0.1:0"], "webrtcAllHostCandidates": true, "tlsPinOnly": true }} }},"#),
            r#""bootstrap": ["kiri://boot/x"], "paths": 1, "egressId": "eu2""#,
        )
        .unwrap();
        let k = outbound(&c, "kiri");
        assert_eq!(
            (
                k.root_pubkeys.len(),
                k.signed_config.len(),
                k.paths,
                k.egress_id.as_str()
            ),
            (1, 5, 1, "eu2")
        );
        assert_eq!(
            k.dev.as_ref().unwrap().udp_bind,
            vec!["127.0.0.1:0"],
            "dev settings inherited"
        );
        let s = c.kiri.as_ref().unwrap();
        assert!(s.bridge && s.dev.as_ref().unwrap().webrtc_all_host_candidates);
        assert!(s.dev.as_ref().unwrap().tls_pin_only);
        assert_eq!((s.bridge_max_kbps, s.bridge_max_circuits), (100, 4));
        // Everything on the outbound, no section.
        let c = json(
            "",
            &format!(r#""rootPubkeys": ["{K2}"], "config": "{CFG}""#),
        )
        .unwrap();
        assert_eq!(outbound(&c, "kiri").paths, 2);
        assert!(c.kiri.is_none());
    }

    #[test]
    fn json_bad_settings_are_refused() {
        for (kiri, settings, want) in [
            (
                "",
                format!(r#""rootPubkeys": ["{K1}"], "config": "{CFG}", "colour": 1"#),
                "unknown field",
            ),
            (
                "",
                format!(r#""rootPubkeys": ["{K1}"], "config": "{CFG}", "paths": 0"#),
                "paths",
            ),
            (
                "",
                format!(r#""rootPubkeys": ["nothex"], "config": "{CFG}""#),
                "64 hex",
            ),
            ("", format!(r#""rootPubkeys": ["{K1}"]"#), "config"),
            (
                r#""kiri": { "bridge": true, "colour": 1 },"#,
                format!(r#""rootPubkeys": ["{K1}"], "config": "{CFG}""#),
                "unknown field",
            ),
            (
                r#""kiri": { "bridge": true },"#,
                format!(r#""rootPubkeys": ["{K1}"], "config": "{CFG}""#),
                "bridge needs",
            ),
        ] {
            let e = json(kiri, &settings).map(|_| ()).expect_err(&settings);
            assert!(e.to_string().contains(want), "{kiri} {settings}: {e}");
        }
    }
}

/// Without the features a kiri outbound or bridge is refused by name.
#[cfg(all(test, not(feature = "outbound-kiri"), not(feature = "kiri-bridge")))]
mod without_kiri {
    #[test]
    fn kiri_settings_name_the_missing_feature() {
        let e = crate::config::conf::from_string("[Proxy]\nK = kiri, paths=2\n").unwrap_err();
        assert!(e.to_string().contains("feature `outbound-kiri`"), "{e}");
        let e = crate::config::conf::from_string("[Kiri]\nbridge = true\n[Proxy]\nD = direct\n")
            .unwrap_err();
        assert!(e.to_string().contains("feature `kiri-bridge`"), "{e}");
        // A section that asks for no bridge is harmless.
        crate::config::conf::from_string("[Kiri]\nbridge = false\n[Proxy]\nD = direct\n").unwrap();
    }
}
