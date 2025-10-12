use leaf::config::{conf, json};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conf_process_name_rule() {
        let conf_content = r#"
[General]
loglevel = info

[Rule]
PROCESS-NAME,chrome.exe,Proxy
PROCESS-NAME,firefox.exe,Proxy
DOMAIN,google.com,Direct
FINAL,Direct
"#;

        let result = conf::config::from_string(conf_content);
        assert!(result.is_ok());
        
        let config = result.unwrap();
        assert!(config.router.is_some());
        
        let router = config.router.unwrap();
        assert!(!router.rules.is_empty());
        
        // Check that PROCESS-NAME rules are parsed
        let process_name_rules: Vec<_> = router.rules
            .iter()
            .filter(|rule| !rule.process_names.is_empty())
            .collect();
        
        #[cfg(feature = "rule-process-name")]
        {
            assert!(!process_name_rules.is_empty());
            // Verify the process names are correctly parsed
            for rule in process_name_rules {
                assert!(!rule.process_names.is_empty());
                assert!(rule.process_names.contains(&"chrome.exe".to_string()) ||
                        rule.process_names.contains(&"firefox.exe".to_string()));
            }
        }
        
        #[cfg(not(feature = "rule-process-name"))]
        {
            // When feature is disabled, process_names should be empty
            assert!(process_name_rules.is_empty());
        }
    }

    #[test]
    fn test_json_process_name_rule() {
        let json_content = r#"
{
    "log": {
        "level": "info"
    },
    "router": {
        "rules": [
            {
                "processName": ["chrome.exe", "firefox.exe"],
                "target": "Proxy"
            },
            {
                "domain": ["google.com"],
                "target": "Direct"
            },
            {
                "target": "Direct"
            }
        ]
    }
}
"#;

        let result = json::config::from_string(json_content);
        assert!(result.is_ok());
        
        let config = result.unwrap();
        assert!(config.router.is_some());
        
        let router = config.router.unwrap();
        assert!(!router.rules.is_empty());
        
        // Check that PROCESS-NAME rules are parsed
        let process_name_rules: Vec<_> = router.rules
            .iter()
            .filter(|rule| !rule.process_names.is_empty())
            .collect();
        
        #[cfg(feature = "rule-process-name")]
        {
            assert!(!process_name_rules.is_empty());
            // Verify the process names are correctly parsed
            for rule in process_name_rules {
                assert!(!rule.process_names.is_empty());
                assert!(rule.process_names.contains(&"chrome.exe".to_string()) ||
                        rule.process_names.contains(&"firefox.exe".to_string()));
            }
        }
        
        #[cfg(not(feature = "rule-process-name"))]
        {
            // When feature is disabled, process_names should be empty
            assert!(process_name_rules.is_empty());
        }
    }

    #[test]
    fn test_conf_process_name_with_regex() {
        let conf_content = r#"
[General]
loglevel = info

[Rule]
PROCESS-NAME,.*chrome.*,Proxy
PROCESS-NAME,.*firefox.*,Proxy
FINAL,Direct
"#;

        let result = conf::config::from_string(conf_content);
        assert!(result.is_ok());
        
        let config = result.unwrap();
        let router = config.router.unwrap();
        
        #[cfg(feature = "rule-process-name")]
        {
            let process_name_rules: Vec<_> = router.rules
                .iter()
                .filter(|rule| !rule.process_names.is_empty())
                .collect();
            
            assert!(!process_name_rules.is_empty());
            // Verify regex patterns are preserved
            for rule in process_name_rules {
                assert!(rule.process_names.contains(&".*chrome.*".to_string()) ||
                        rule.process_names.contains(&".*firefox.*".to_string()));
            }
        }
    }

    #[test]
    fn test_json_process_name_with_regex() {
        let json_content = r#"
{
    "log": {
        "level": "info"
    },
    "router": {
        "rules": [
            {
                "processName": [".*chrome.*", ".*firefox.*"],
                "target": "Proxy"
            },
            {
                "target": "Direct"
            }
        ]
    }
}
"#;

        let result = json::config::from_string(json_content);
        assert!(result.is_ok());
        
        let config = result.unwrap();
        let router = config.router.unwrap();
        
        #[cfg(feature = "rule-process-name")]
        {
            let process_name_rules: Vec<_> = router.rules
                .iter()
                .filter(|rule| !rule.process_names.is_empty())
                .collect();
            
            assert!(!process_name_rules.is_empty());
            // Verify regex patterns are preserved
            for rule in process_name_rules {
                assert!(rule.process_names.contains(&".*chrome.*".to_string()) ||
                        rule.process_names.contains(&".*firefox.*".to_string()));
            }
        }
    }

    #[test]
    fn test_config_without_process_name() {
        let conf_content = r#"
[General]
loglevel = info

[Rule]
DOMAIN,google.com,Direct
FINAL,Direct
"#;

        let result = conf::config::from_string(conf_content);
        assert!(result.is_ok());
        
        let config = result.unwrap();
        let router = config.router.unwrap();
        
        // Should work fine without PROCESS-NAME rules
        assert!(!router.rules.is_empty());
        
        let process_name_rules: Vec<_> = router.rules
            .iter()
            .filter(|rule| !rule.process_names.is_empty())
            .collect();
        
        // No PROCESS-NAME rules, so should be empty
        assert!(process_name_rules.is_empty());
    }
}
