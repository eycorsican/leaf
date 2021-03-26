mod common;

// app(socks) -> (socks)client(quic+trojan) -> (quic+trojan)server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-quic",
    feature = "outbound-trojan",
    feature = "inbound-quic",
    feature = "inbound-trojan",
    feature = "outbound-direct",
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
                    "certificate": "/tmp/cert.der"
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
                    "certificate": "/tmp/cert.der",
                    "certificateKey": "/tmp/key.der"
                }
            },
            {
                "protocol": "trojan",
                "tag": "trojan",
                "settings": {
                    "password": "password"
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

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086);
}
