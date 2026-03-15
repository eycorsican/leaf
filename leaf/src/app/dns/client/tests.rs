#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::{DnsClient, Resolver, ServerSelectorState};

    fn new_client(servers: Vec<&str>) -> DnsClient {
        let mut dns = crate::config::Dns::new();
        dns.servers = servers.into_iter().map(|s| s.to_string()).collect();
        DnsClient::new(&protobuf::MessageField::some(dns)).unwrap()
    }

    fn collect_server_strings(client: &DnsClient, is_direct_outbound: bool) -> Vec<String> {
        client
            .collect_servers(is_direct_outbound)
            .into_iter()
            .map(|server| server.to_string())
            .collect()
    }

    #[test]
    fn load_servers_supports_legacy_and_doh_with_ip() {
        let mut dns = crate::config::Dns::new();
        dns.servers = vec![
            "1.1.1.1".to_string(),
            "direct:system".to_string(),
            "doh:example.com@9.9.9.9".to_string(),
            "direct:doh:example.com@8.8.8.8".to_string(),
            "doh:example.net".to_string(),
        ];
        let servers = DnsClient::load_servers(&dns).unwrap();

        match &servers[0] {
            Resolver::Server(addr, false) => assert_eq!(
                *addr,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
            ),
            _ => panic!("unexpected resolver"),
        }
        match &servers[1] {
            Resolver::System(true) => {}
            _ => panic!("unexpected resolver"),
        }
        match &servers[2] {
            Resolver::DoH(doh) => {
                assert_eq!(doh.domain, "example.com");
                assert_eq!(
                    doh.bootstrap_ip,
                    Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
                );
                assert!(!doh.is_direct);
            }
            _ => panic!("unexpected resolver"),
        }
        match &servers[3] {
            Resolver::DoH(doh) => {
                assert_eq!(doh.domain, "example.com");
                assert_eq!(
                    doh.bootstrap_ip,
                    Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
                );
                assert!(doh.is_direct);
            }
            _ => panic!("unexpected resolver"),
        }
        match &servers[4] {
            Resolver::DoH(doh) => {
                assert_eq!(doh.domain, "example.net");
                assert_eq!(doh.bootstrap_ip, None);
                assert!(!doh.is_direct);
            }
            _ => panic!("unexpected resolver"),
        }
    }

    #[test]
    fn load_servers_ignores_invalid_doh_value_if_any_valid_server_exists() {
        let mut dns = crate::config::Dns::new();
        dns.servers = vec![
            "doh:@1.1.1.1".to_string(),
            "direct:doh:example.com@not-an-ip".to_string(),
            "doh:example.com#8.8.8.8".to_string(),
            "1.1.1.1".to_string(),
        ];
        let servers = DnsClient::load_servers(&dns).unwrap();
        assert_eq!(servers.len(), 1);
        match &servers[0] {
            Resolver::Server(addr, false) => assert_eq!(
                *addr,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
            ),
            _ => panic!("unexpected resolver"),
        }
    }

    #[test]
    fn load_servers_rejects_when_all_servers_invalid() {
        let mut dns = crate::config::Dns::new();
        dns.servers = vec![
            "doh:@1.1.1.1".to_string(),
            "direct:doh:example.com@not-an-ip".to_string(),
            "doh:example.com#8.8.8.8".to_string(),
        ];
        let err = DnsClient::load_servers(&dns).unwrap_err();
        assert!(err.to_string().contains("no dns servers"));
    }

    #[test]
    fn collect_servers_includes_direct_doh_for_direct_outbound() {
        let client = new_client(vec![
            "1.1.1.1",
            "doh:normal.example",
            "direct:doh:direct.example@8.8.8.8",
        ]);
        let selected = collect_server_strings(&client, true);
        assert_eq!(selected, vec!["direct:doh:direct.example@8.8.8.8"]);
    }

    #[test]
    fn collect_servers_fallback_to_normal_keeps_non_direct_doh() {
        let client = new_client(vec!["doh:normal.example", "1.1.1.1", "system"]);
        let selected = collect_server_strings(&client, true);
        assert_eq!(
            selected,
            vec![
                "doh:normal.example".to_string(),
                "1.1.1.1:53".to_string(),
                "system".to_string()
            ]
        );
    }

    #[test]
    fn parse_doh_http_body_supports_content_length() {
        let body = b"\x01\x02\x03\x04";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut raw = response.into_bytes();
        raw.extend_from_slice(body);

        let parsed = DnsClient::parse_doh_http_body(&raw).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn parse_doh_http_body_supports_chunked() {
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nABCD\r\n2\r\nEF\r\n0\r\n\r\n";
        let parsed = DnsClient::parse_doh_http_body(response).unwrap();
        assert_eq!(parsed, b"ABCDEF");
    }

    #[test]
    fn parse_doh_http_body_rejects_non_200() {
        let response = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 3\r\n\r\nbad".to_vec();
        let err = DnsClient::parse_doh_http_body(&response).unwrap_err();
        assert!(err
            .to_string()
            .contains("doh server returned http status 503"));
    }

    #[test]
    fn selector_primary_switches_after_consecutive_failures() {
        let s1 = DnsClient::parse_server("1.1.1.1").unwrap();
        let s2 = DnsClient::parse_server("8.8.8.8").unwrap();
        let servers = vec![&s1, &s2];
        let mut selector = ServerSelectorState::default();
        let initial = selector.select_primary_index(&servers);
        assert_eq!(initial, 0);
        let key = s1.to_string();
        let threshold = (*crate::option::DNS_SERVER_SWITCH_THRESHOLD).max(1);
        for _ in 0..threshold {
            selector.mark_failure(&key, true);
        }
        let selected = selector.select_primary_index(&servers);
        assert_eq!(selected, 1);
    }

    #[test]
    fn selector_prefers_lower_latency_in_fallback_order() {
        let s1 = DnsClient::parse_server("1.1.1.1").unwrap();
        let s2 = DnsClient::parse_server("8.8.8.8").unwrap();
        let s3 = DnsClient::parse_server("9.9.9.9").unwrap();
        let servers = vec![&s1, &s2, &s3];
        let mut selector = ServerSelectorState::default();
        selector.mark_success(&s2.to_string(), Duration::from_millis(30));
        selector.mark_success(&s3.to_string(), Duration::from_millis(450));
        let order = selector.fallback_indices(&servers, 0);
        assert_eq!(order, vec![1, 2]);
    }

    #[test]
    fn selector_marks_slow_server_as_degraded() {
        let server = DnsClient::parse_server("1.1.1.1").unwrap();
        let mut selector = ServerSelectorState::default();
        let key = server.to_string();
        let threshold = (*crate::option::DNS_SERVER_SWITCH_THRESHOLD).max(1);
        let slow_elapsed = Duration::from_millis(*crate::option::DNS_SERVER_SLOW_RESPONSE_MS + 50);
        for _ in 0..threshold {
            selector.mark_success(&key, slow_elapsed);
        }
        assert!(selector.is_degraded(&key));
    }
}
