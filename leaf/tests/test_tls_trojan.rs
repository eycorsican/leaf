mod common;

// app(socks) -> (socks)client(tls+trojan) -> (tls+trojan)server(direct) -> echo
#[cfg(all(
    feature = "outbound-socks",
    feature = "inbound-socks",
    feature = "outbound-tls",
    feature = "outbound-trojan",
    feature = "inbound-tls",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "inbound-chain",
    feature = "outbound-chain",
))]
#[test]
fn test_tls_trojan() {
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
                        "tls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "tls",
                "tag": "tls",
                "settings": {
                    "serverName": "localhost",
                    "certificate": "cert.pem"
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
        "inbounds": [
            {
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 3001,
                "settings": {
                    "actors": [
                        "tls",
                        "trojan"
                    ]
                }
            },
            {
                "protocol": "tls",
                "tag": "tls",
                "settings": {
                    "certificate": "cert.pem",
                    "certificateKey": "key.pem"
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

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    let cert_path = path.join("cert.pem");
    let key_path = path.join("key.pem");
    let key = cert.serialize_private_key_pem();
    let cert = cert.serialize_pem().unwrap();
    std::fs::write(&cert_path, &cert).unwrap();
    std::fs::write(&key_path, &key).unwrap();

    let configs = vec![config1.to_string(), config2.to_string()];
    common::test_configs(configs, "127.0.0.1", 1086);
}
