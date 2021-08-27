#[test]
fn test_dns_hosts() {
    let json_str = r#"
    {
        "dns": {
            "hosts": {
                "example.com": [
                    "192.168.0.1",
                    "192.168.0.2"
                ]
            }
        }
    }
    "#;
    let mut config = crate::config::json::json_from_string(json_str).unwrap();
    let hosts = config.dns.as_ref().unwrap().hosts.as_ref().unwrap();
    let ips = vec!["192.168.0.1".to_string(), "192.168.0.2".to_string()];

    assert_eq!(hosts.get("example.com").unwrap(), &ips);

    let config = crate::config::json::to_internal(&mut config).unwrap();

    assert_eq!(
        config
            .dns
            .unwrap()
            .hosts
            .get("example.com")
            .unwrap()
            .values
            .as_slice(),
        &ips
    );
}
