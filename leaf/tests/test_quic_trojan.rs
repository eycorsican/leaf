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
                    "certificate": "cert.der",
                    "alpn": [
                        "http/1.1",
                        "trojan"
                    ]
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
                "tag": "quic-in",
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
                    "certificateKey": "key.der",
                    "alpn": [
                        "http/1.1",
                        "trojan"
                    ]
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
                "tag": "quic-in",
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

    std::env::set_var("TCP_DOWNLINK_TIMEOUT", "3");
    std::env::set_var("TCP_UPLINK_TIMEOUT", "3");

    let mut path = std::env::current_exe().unwrap();
    path.pop();
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&path.join("key.der"), &key_pair.serialize_der()).unwrap();
    std::fs::write(&path.join("cert.der"), &cert.der().to_vec()).unwrap();
    std::fs::write(&path.join("key.pem"), &key_pair.serialize_pem()).unwrap();
    std::fs::write(&path.join("cert.pem"), &cert.pem()).unwrap();

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs.clone(), "127.0.0.1", 1086);
    common::test_tcp_half_close_on_configs(configs.clone(), "127.0.0.1", 1086);
    common::test_data_transfering_reliability_on_configs(configs.clone(), "127.0.0.1", 1086);

    let configs = vec![config3.to_string(), config4.to_string()];
    common::test_configs(configs.clone(), "127.0.0.1", 1087);
}
