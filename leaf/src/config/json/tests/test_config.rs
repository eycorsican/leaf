#[test]
fn test_config() {
    let json_str = r#"
    {
        "api": {
            "address": "127.0.0.1",
            "port": 9991
        },
        "log": {
            "level": "trace",
            "output": "leaf.log"
        },
        "dns": {
            "servers": [
                "8.8.8.8",
                "8.8.4.4"
            ],
            "hosts": {
                "example.com": [
                    "192.168.0.1",
                    "192.168.0.2"
                ]
            }
        },
        "inbounds": [
            {
                "tag": "socks_in",
                "address": "127.0.0.1",
                "port": 1086,
                "protocol": "socks"
            }
        ],
        "outbounds": [
            {
                "protocol": "direct",
                "tag": "direct_out"
            }
        ],
        "router": {
            "domainResolve": true,
            "rules": [
                {
                    "ip": [
                        "8.8.8.8",
                        "8.8.4.4"
                    ],
                    "target": "direct_out"
                },
                {
                    "portRange": [
                        "22-22",
                        "1024-65535"
                    ],
                    "target": "direct_out"
                },
                {
                    "domain": [
                        "www.google.com"
                    ],
                    "target": "direct_out"
                },
                {
                    "domainSuffix": [
                        "google.com"
                    ],
                    "target": "direct_out"
                },
                {
                    "domainKeyword": [
                        "google"
                    ],
                    "target": "direct_out"
                },
                {
                    "external": [
                        "site:cn"
                    ],
                    "target": "direct_out"
                },
                {
                    "external": [
                        "mmdb:cn"
                    ],
                    "target": "direct_out"
                }
            ]
        }
    }
    "#;

    assert!(crate::config::json::from_string(json_str.to_string()).is_ok());
}
