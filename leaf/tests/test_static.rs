mod common;

// app(socks) -> (socks)client(static(shadowsocks)) -> (shadowsocks)server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-shadowsocks",
    feature = "inbound-shadowsocks",
    feature = "outbound-direct",
    feature = "outbound-static",
))]
#[test]
fn test_static() {
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
                "protocol": "static",
                "settings": {
                    "actors": [
                        "ss_out"
                    ],
                    "method": "rr"
                }
            },
            {
                "protocol": "shadowsocks",
                "tag": "ss_out",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3001,
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
                "protocol": "socks",
                "address": "127.0.0.1",
                "port": 1086
            }
        ],
        "outbounds": [
            {
                "protocol": "static",
                "settings": {
                    "actors": [
                        "ss_out"
                    ],
                    "method": "random"
                }
            },
            {
                "protocol": "shadowsocks",
                "tag": "ss_out",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 3001,
                    "method": "chacha20-ietf-poly1305",
                    "password": "password"
                }
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
                "port": 3001,
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

    let configs = vec![config1.to_string(), config3.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086);
    let configs = vec![config2.to_string(), config3.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086);
}
