mod common;

// app(socks) -> (socks)client(chain(chain(amux(ws)+trojan)+shadowsocks)) -> (chain(amux(ws)+trojan))server1(direct) -> (shadowsocks)server2(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-amux",
    feature = "outbound-ws",
    feature = "outbound-trojan",
    feature = "inbound-amux",
    feature = "inbound-ws",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
    feature = "inbound-shadowsocks",
    feature = "outbound-shadowsocks",
))]
#[test]
fn test_out_chain_10() {
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
                "tag": "out",
                "settings": {
                    "actors": [
                        "chain-amux-ws-trojan",
                        "shadowsocks"
                    ]
                }
            },
            {
                "protocol": "chain",
                "tag": "chain-amux-ws-trojan",
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
            },
            {
                "protocol": "shadowsocks",
                "tag": "shadowsocks",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3002,
                    "method": "chacha20-ietf-poly1305",
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
                "tag": "in",
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
                "protocol": "ws",
                "tag": "ws",
                "settings": {
                    "path": "/leaf"
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
                "protocol": "shadowsocks",
                "address": "127.0.0.1",
                "port": 3002,
                "settings": {
                    "method": "chacha20-ietf-poly1305",
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

    let configs = vec![
        config1.to_string(),
        config2.to_string(),
        config3.to_string(),
    ];
    common::test_configs(configs, "127.0.0.1", 1086);
}
