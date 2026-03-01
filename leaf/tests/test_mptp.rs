mod common;

// app(socks) -> (socks)client(mptp(direct1, direct2)) -> (mptp)server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-mptp",
    feature = "inbound-mptp",
    feature = "outbound-direct",
))]
#[test]
fn test_mptp() -> anyhow::Result<()> {
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
                "protocol": "mptp",
                "settings": {
                    "actors": [
                        "direct1",
                        "direct2"
                    ],
                    "address": "127.0.0.1",
                    "port": 3001
                }
            },
            {
                "protocol": "direct",
                "tag": "direct1"
            },
            {
                "protocol": "direct",
                "tag": "direct2"
            }
        ]
    }
    "#;

    let config2 = r#"
    {
        "inbounds": [
            {
                "protocol": "mptp",
                "address": "127.0.0.1",
                "port": 3001
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
    common::test_configs(configs.clone(), "127.0.0.1", 1086)?;
    common::test_tcp_half_close_on_configs(configs.clone(), "127.0.0.1", 1086)?;
    common::test_data_transfering_reliability_on_configs(configs.clone(), "127.0.0.1", 1086)
}
