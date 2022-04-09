mod common;

#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-shadowsocks",
    feature = "inbound-shadowsocks",
    feature = "outbound-direct",
))]
#[test]
fn test_tcp_half_close_shadowsocks() {
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
                "protocol": "shadowsocks",
                "tag": "shadowsocks",
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
                "protocol": "shadowsocks",
                "tag": "shadowsocks",
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

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_tcp_half_close_on_configs(configs, "127.0.0.1", 1086);
}
