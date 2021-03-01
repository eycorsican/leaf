mod common;

// app(socks) -> (socks)client(ws+trojan->shadowsocks->ws+trojan) -> (ws+trojan)server1(direct) -> (shadowsocks)server2(direct) -> (ws+trojan)server3(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-ws",
    feature = "outbound-trojan",
    feature = "inbound-ws",
    feature = "inbound-trojan",
    feature = "outbound-shadowsocks",
    feature = "inbound-shadowsocks",
    feature = "outbound-direct",
))]
#[test]
fn test_out_chain_7() {
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
                "tag": "chain-server1-server2",
                "settings": {
                    "actors": [
                        "server1",
                        "server2",
                        "server3"
                    ]
                }
            },
            {
                "protocol": "chain",
                "tag": "server1",
                "settings": {
                    "actors": [
                        "server1-ws",
                        "server1-trojan"
                    ]
                }
            },
            {
                "protocol": "ws",
                "tag": "server1-ws",
                "settings": {
                    "path": "/leaf"
                }
            },
            {
                "protocol": "trojan",
                "tag": "server1-trojan",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3001,
                    "password": "password"
                }
            },
            {
                "protocol": "shadowsocks",
                "tag": "server2",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3002,
                    "method": "aes-128-gcm",
                    "password": "password"
                }
            },
            {
                "protocol": "chain",
                "tag": "server3",
                "settings": {
                    "actors": [
                        "server3-ws",
                        "server3-trojan"
                    ]
                }
            },
            {
                "protocol": "ws",
                "tag": "server3-ws",
                "settings": {
                    "path": "/leaf"
                }
            },
            {
                "protocol": "trojan",
                "tag": "server3-trojan",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3003,
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
                "tag": "server1",
                "address": "127.0.0.1",
                "port": 3001,
                "settings": {
                    "actors": [
                        "ws",
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

    let config3 = r#"
    {
        "inbounds": [
            {
                "protocol": "shadowsocks",
                "address": "127.0.0.1",
                "port": 3002,
                "settings": {
                    "method": "aes-128-gcm",
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

    let config4 = r#"
    {
        "inbounds": [
            {
                "protocol": "chain",
                "tag": "server1",
                "address": "127.0.0.1",
                "port": 3003,
                "settings": {
                    "actors": [
                        "ws",
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

    let configs = vec![
        config1.to_string(),
        config2.to_string(),
        config3.to_string(),
        config4.to_string(),
    ];
    common::test_configs(configs, "127.0.0.1", 1086);
}
