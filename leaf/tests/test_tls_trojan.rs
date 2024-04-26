mod common;

// app(socks) -> (socks)client(chain(tls+trojan)) -> (chain(tls+trojan))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-tls",
    feature = "outbound-trojan",
    feature = "inbound-tls",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_tls_trojan() {
    let config1 = r#"
    {
        "inbounds": [
            {
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 1086
            }
        ],
        "outbounds": [
            {
                "protocol": "chain",
                "settings": {
                    "actors": [
                        "tls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "tls",
                "tag": "tls",
                "settings": {
                    "serverName": "localhost",
                    "certificate": "cert.pem"
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3001,
                    "password": "password"
                }
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "inbounds": [
            {
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 3001,
                "settings": {
                    "actors": [
                        "tls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "tls",
                "tag": "tls",
                "settings": {
                    "certificate": "cert.pem",
                    "certificateKey": "key.pem"
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
                    "passwords": [
                        "password"
                    ]
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "direct"
            }
        ]
    }
    "#;

    let config3 = r#"
    {
        "inbounds": [
            {
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 1087
            }
        ],
        "outbounds": [
            {
                "protocol": "chain",
                "settings": {
                    "actors": [
                        "tls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "tls",
                "tag": "tls",
                "settings": {
                    "serverName": "localhost",
                    "certificate": "cert.pem"
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3002,
                    "password": "password"
                }
            }
        ]
    }
    "#;

    let config4 = r#"
    {
        "inbounds": [
            {
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 3002,
                "settings": {
                    "actors": [
                        "tls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "tls",
                "tag": "tls",
                "settings": {
                    "certificate": "cert.pem",
                    "certificateKey": "key.pem"
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
                    "passwords": [
                        "password"
                    ]
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "direct"
            }
        ]
    }
    "#;

    let mut path = std::env::current_exe().unwrap();
    path.pop();
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&path.join("key.der"), &key_pair.serialize_der()).unwrap();
    std::fs::write(&path.join("cert.der"), &cert.der().to_vec()).unwrap();
    std::fs::write(&path.join("key.pem"), &key_pair.serialize_pem()).unwrap();
    std::fs::write(&path.join("cert.pem"), &cert.pem()).unwrap();
    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086);
    let configs = vec![config3.to_string(), config4.to_string()];
    common::test_configs(configs, "127.0.0.1", 1087);
}
