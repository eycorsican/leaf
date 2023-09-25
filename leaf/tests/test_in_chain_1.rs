mod common;

// app(socks) -> (socks)client(chain(ws+trojan)) -> (chain(ws+trojan))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-ws",
    feature = "outbound-trojan",
    feature = "inbound-ws",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_in_chain_1() {
    let config1 = r#"
    {
        "log": {
            "level": "trace"
        },
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
        "log": {
            "level": "trace"
        },
        "inbounds": [
            {
                "protocol": "chain",
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

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086);
}
