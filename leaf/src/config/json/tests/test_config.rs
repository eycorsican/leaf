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

    assert!(crate::config::json::json_from_string(json_str).is_ok());
}

#[test]
fn test_invalid_config() {
    // Missing protocol
    let json_str = r#"
    {
        "inbounds": [
            {
                "tag": "socks_in",
                "address": "127.0.0.1",
                "port": 1086
            }
        ]
    }
    "#;
    assert!(crate::config::json::json_from_string(json_str).is_err());

    // Invalid port
    let json_str = r#"
    {
        "inbounds": [
            {
                "tag": "socks_in",
                "address": "127.0.0.1",
                "port": 70000,
                "protocol": "socks"
            }
        ]
    }
    "#;
    assert!(crate::config::json::json_from_string(json_str).is_err());
}

#[test]
fn test_dns_config() {
    let json_str = r#"
    {
        "dns": {
            "servers": ["1.1.1.1"],
            "hosts": {
                "google.com": ["127.0.0.1"]
            }
        }
    }
    "#;
    let config = crate::config::json::json_from_string(json_str).unwrap();
    let dns = config.dns.as_ref().unwrap();
    assert_eq!(dns.servers.as_ref().unwrap().len(), 1);
    assert_eq!(dns.servers.as_ref().unwrap()[0], "1.1.1.1");
}
