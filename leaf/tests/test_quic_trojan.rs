mod common;

// app(socks) -> (socks)client(chain(quic+trojan)) -> (chain(quic+trojan))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-quic",
    feature = "outbound-trojan",
    feature = "inbound-quic",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_quic_trojan() {
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
                        "quic",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "quic",
                "tag": "quic",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3001,
                    "serverName": "localhost",
                    "certificate": "cert.der"
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
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
                        "quic",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "quic",
                "tag": "quic",
                "settings": {
                    "certificate": "cert.der",
                    "certificateKey": "key.der"
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
                        "quic",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "quic",
                "tag": "quic",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3002,
                    "serverName": "localhost",
                    "certificate": "cert.pem"
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
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
                        "quic",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "quic",
                "tag": "quic",
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
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&path.join("key.der"), &cert.serialize_private_key_der()).unwrap();
    std::fs::write(&path.join("cert.der"), &cert.serialize_der().unwrap()).unwrap();
    std::fs::write(&path.join("key.pem"), &cert.serialize_private_key_pem()).unwrap();
    std::fs::write(&path.join("cert.pem"), &cert.serialize_pem().unwrap()).unwrap();
    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086);
    let configs = vec![config3.to_string(), config4.to_string()];
    common::test_configs(configs, "127.0.0.1", 1087);
}
