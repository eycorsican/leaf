mod common;

// app(socks) -> (socks)client(shadowsocks) -> (shadowsocks)server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-shadowsocks",
    feature = "inbound-shadowsocks",
    feature = "outbound-direct",
))]
#[test]
fn test_shadowsocks() {
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

    std::env::set_var("TCP_DOWNLINK_TIMEOUT", "3");
    std::env::set_var("TCP_UPLINK_TIMEOUT", "3");

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs.clone(), "127.0.0.1", 1086);
    common::test_tcp_half_close_on_configs(configs.clone(), "127.0.0.1", 1086);
    common::test_data_transfering_reliability_on_configs(configs.clone(), "127.0.0.1", 1086);
}
