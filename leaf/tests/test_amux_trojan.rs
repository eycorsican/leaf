mod common;

// app(socks) -> (socks)client(chain(amux(tcp)+trojan)) -> (chain(amux(tcp)+trojan))server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-amux",
    feature = "outbound-trojan",
    feature = "inbound-amux",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_amux_trojan() {
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
                    "address": "127.0.0.1",
                    "port": 3001
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
                "tag": "amux"
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

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs.clone(), "127.0.0.1", 1086);
    common::test_tcp_half_close_on_configs(configs.clone(), "127.0.0.1", 1086);
    common::test_data_transfering_reliability_on_configs(configs.clone(), "127.0.0.1", 1086);
}
