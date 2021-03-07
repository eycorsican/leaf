mod common;

// app(socks) -> (socks)client(ws+amux->trojan) -> (ws+amux->trojan)server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-ws",
    feature = "outbound-amux",
    feature = "outbound-trojan",
    feature = "inbound-ws",
    feature = "inbound-amux",
    feature = "inbound-trojan",
    feature = "outbound-direct",
))]
#[test]
fn test_ws_amux_trojan() {
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
                        "amux",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "amux",
                "tag": "amux",
                "settings": {
                    "actors": [
                        "ws"
                    ],
                    "address": "127.0.0.1",
                    "port": 3001,
                    "maxAccepts": 16,
                    "concurrency": 1
                }
            },
            {
                "protocol": "ws",
                "tag": "ws",
                "settings": {
                    "path": "/leaf"
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
                        "amux",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "amux",
                "tag": "amux",
                "settings": {
                    "actors": [
                        "ws"
                    ]
                }
            },
            {
                "protocol": "ws",
                "tag": "ws",
                "settings": {
                    "path": "/leaf"
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
