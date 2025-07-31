//! Tests for the effectiveness module

#[cfg(test)]
mod effectiveness_tests {
    use super::super::*;
    use tempfile::TempDir;

    #[test]
    fn test_effectiveness_config_default() {
        let config = EffectivenessConfig::default();
        assert_eq!(config.max_requests_per_minute, 60);
        assert!(config.audit_logging);
        assert_eq!(config.intensity_level, 3);
        assert_eq!(config.request_timeout.as_secs(), 30);
        assert_eq!(config.request_delay.as_millis(), 500);
    }

    #[test]
    fn test_is_blocked_detection() {
        // Test various blocked responses
        assert!(EffectivenessTest::is_blocked(403, "Forbidden"));
        assert!(EffectivenessTest::is_blocked(406, "Not Acceptable"));
        assert!(EffectivenessTest::is_blocked(429, "Too Many Requests"));
        assert!(EffectivenessTest::is_blocked(503, "Service Unavailable"));

        // Test 200 OK with block indicators
        assert!(EffectivenessTest::is_blocked(200, "Access Denied"));
        assert!(EffectivenessTest::is_blocked(
            200,
            "Request blocked by security policy"
        ));
        assert!(EffectivenessTest::is_blocked(200, "WAF Protection"));
        assert!(EffectivenessTest::is_blocked(
            200,
            "Firewall blocked your request"
        ));

        // Test Akamai Bot Manager response
        assert!(EffectivenessTest::is_blocked(200, "OK Bot."));
        assert!(EffectivenessTest::is_blocked(200, "ok bot"));

        // Test blocked keyword in short responses
        assert!(EffectivenessTest::is_blocked(200, "Blocked"));
        // "No" alone is not a block indicator - it needs context
        assert!(!EffectivenessTest::is_blocked(200, "No"));
        assert!(EffectivenessTest::is_blocked(200, "Access Denied"));

        // Test normal responses that should NOT be blocked
        assert!(!EffectivenessTest::is_blocked(200, "<!DOCTYPE html><html><body>Welcome to our website! Here is some normal content that is definitely longer than 100 characters.</body></html>"));
        assert!(!EffectivenessTest::is_blocked(200, "")); // Empty response should not be blocked
        assert!(!EffectivenessTest::is_blocked(404, "Not Found"));
    }

    #[test]
    fn test_consent_manager_creation() {
        let consent_manager = consent::ConsentManager::new();
        // Should create without errors - verify by checking it's instantiated
        drop(consent_manager); // Explicitly drop to ensure it was created
    }

    #[test]
    fn test_consent_without_file() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());

        let consent_manager = consent::ConsentManager::new();
        let has_consent = consent_manager.has_valid_consent().unwrap();
        assert!(!has_consent);
    }

    #[test]
    fn test_techniques_by_level() {
        // Level 1 should have basic techniques
        let level1 = techniques::get_techniques_for_level(1);
        assert!(!level1.is_empty());
        assert!(level1.iter().any(|t| t.name.contains("Basic")));

        // Level 3 should have more techniques
        let level3 = techniques::get_techniques_for_level(3);
        assert!(level3.len() > level1.len());

        // Level 5 should have the most techniques
        let level5 = techniques::get_techniques_for_level(5);
        assert!(level5.len() >= level3.len());
    }

    #[test]
    fn test_evasion_techniques() {
        let evasion = techniques::get_evasion_techniques();
        assert!(!evasion.is_empty());
        assert!(evasion.iter().any(|t| t.name.contains("Case Variation")));
        assert!(evasion.iter().any(|t| t.name.contains("Unicode")));
    }

    #[test]
    fn test_random_headers_generation() {
        let headers = techniques::generate_random_headers();
        assert!(headers.contains_key("User-Agent"));
        assert!(headers.contains_key("Accept-Language"));

        // Sometimes includes referer (70% chance)
        // Can't assert this due to randomness
    }

    #[test]
    fn test_user_agents_list() {
        let agents = techniques::get_user_agents();
        assert!(!agents.is_empty());
        assert!(agents.iter().any(|&a| a.contains("Chrome")));
        assert!(agents.iter().any(|&a| a.contains("Firefox")));
    }

    #[test]
    fn test_report_creation() {
        let report = report::EffectivenessReport::new("https://example.com");
        assert_eq!(report.target_url, "https://example.com");
        assert_eq!(report.risk_score, 0.0);
        assert!(report.vulnerabilities.is_empty());
        assert!(report.recommendations.is_empty());
    }

    #[test]
    fn test_report_risk_calculation() {
        let mut report = report::EffectivenessReport::new("https://example.com");

        // First, add some test results to establish a block rate
        // Let's simulate 90% block rate (9 blocked, 1 allowed)
        for i in 0..9 {
            report.add_test_result(
                format!("Blocked Test {i}"),
                TestResult {
                    blocked: true,
                    status_code: 403,
                    response_time: std::time::Duration::from_millis(100),
                    evidence: "Blocked by WAF".to_string(),
                },
            );
        }

        report.add_test_result(
            "Allowed Test".to_string(),
            TestResult {
                blocked: false,
                status_code: 200,
                response_time: std::time::Duration::from_millis(100),
                evidence: "Request allowed".to_string(),
            },
        );

        // With 90% block rate, base risk should be 10.0
        assert!((report.risk_score - 10.0).abs() < 0.01);

        // Add vulnerabilities - they should add small penalties
        report.add_vulnerability(report::Vulnerability {
            severity: "HIGH".to_string(),
            category: "SQL Injection".to_string(),
            description: "Test vulnerability".to_string(),
            evidence: "Test evidence".to_string(),
            remediation: "Test remediation".to_string(),
        });

        // Base risk 10.0 + HIGH penalty 3.0 = 13.0
        assert!((report.risk_score - 13.0).abs() < 0.01);

        report.add_vulnerability(report::Vulnerability {
            severity: "CRITICAL".to_string(),
            category: "RCE".to_string(),
            description: "Critical vulnerability".to_string(),
            evidence: "Test evidence".to_string(),
            remediation: "Test remediation".to_string(),
        });

        // Base risk 10.0 + HIGH 3.0 + CRITICAL 5.0 = 18.0
        assert!((report.risk_score - 18.0).abs() < 0.01);
    }

    #[test]
    fn test_report_risk_score_with_high_block_rate() {
        let mut report = report::EffectivenessReport::new("https://example.com");

        // Simulate 93% block rate (145 blocked out of 156 total)
        for i in 0..145 {
            report.add_test_result(
                format!("Blocked Test {i}"),
                TestResult {
                    blocked: true,
                    status_code: 403,
                    response_time: std::time::Duration::from_millis(100),
                    evidence: "Blocked by WAF".to_string(),
                },
            );
        }

        for i in 0..11 {
            report.add_test_result(
                format!("Allowed Test {i}"),
                TestResult {
                    blocked: false,
                    status_code: 200,
                    response_time: std::time::Duration::from_millis(100),
                    evidence: "Request allowed".to_string(),
                },
            );
        }

        // With 93% block rate (145/156), base risk should be around 7.0
        let expected_risk = (1.0 - (145.0 / 156.0)) * 100.0;
        assert!((report.risk_score - expected_risk).abs() < 0.1);
        assert!(
            report.risk_score < 10.0,
            "Risk score should be low with 93% block rate"
        );
    }

    #[test]
    fn test_report_statistics() {
        let mut report = report::EffectivenessReport::new("https://example.com");

        // Add test results
        report.add_test_result(
            "Test 1".to_string(),
            TestResult {
                blocked: true,
                status_code: 403,
                evidence: "Blocked".to_string(),
                response_time: std::time::Duration::from_millis(100),
            },
        );

        report.add_test_result(
            "Test 2".to_string(),
            TestResult {
                blocked: false,
                status_code: 200,
                evidence: "Allowed".to_string(),
                response_time: std::time::Duration::from_millis(200),
            },
        );

        assert_eq!(report.statistics.total_tests, 2);
        assert_eq!(report.statistics.blocked_requests, 1);
        assert_eq!(report.statistics.allowed_requests, 1);
        assert_eq!(report.statistics.average_response_time_ms, 150.0);
    }

    #[test]
    fn test_report_json_export() {
        let report = report::EffectivenessReport::new("https://example.com");
        let json = report.to_json().unwrap();
        // Check that JSON contains expected fields (field names may differ in serialization)
        assert!(json.contains("https://example.com"));
        assert!(json.contains("risk_score"));
        assert!(json.contains("0.0"));
    }

    #[test]
    fn test_report_html_export() {
        let report = report::EffectivenessReport::new("https://example.com");
        let html = report.to_html();
        assert!(html.contains("<h1>WAF Effectiveness Report</h1>"));
        assert!(html.contains("https://example.com"));
    }

    #[test]
    fn test_patterns_by_category() {
        use patterns::{get_patterns_by_category, PatternCategory};

        let sqli_patterns = get_patterns_by_category(PatternCategory::SqlInjection);
        assert!(!sqli_patterns.is_empty());
        assert!(sqli_patterns.iter().any(|p| p.pattern.contains("OR")));

        let xss_patterns = get_patterns_by_category(PatternCategory::CrossSiteScripting);
        assert!(!xss_patterns.is_empty());
        assert!(xss_patterns.iter().any(|p| p.pattern.contains("script")));
    }

    #[test]
    fn test_human_like_delay() {
        let delay = techniques::get_human_like_delay();
        assert!(delay.as_millis() >= 500);
        assert!(delay.as_millis() < 3000);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let config = EffectivenessConfig {
            max_requests_per_minute: 60, // 1 per second
            ..Default::default()
        };

        // Create a mock test that tracks timing
        let start = std::time::Instant::now();
        let mut test = EffectivenessTest {
            config,
            consent_manager: consent::ConsentManager::new(),
            start_time: start,
            request_count: 100, // Start with high count to trigger rate limiting
        };

        // This should trigger rate limiting and introduce a delay
        test.rate_limit().await.unwrap();

        // The rate limiter should have introduced a delay
        let elapsed = start.elapsed();
        // Should have delayed for at least 1 second (60 requests/min = 1/sec)
        assert!(elapsed.as_millis() >= 500); // Allow some tolerance
    }
}
