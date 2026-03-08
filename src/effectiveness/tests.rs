//! Tests for the effectiveness module

#[cfg(test)]
mod effectiveness_tests {
    use super::super::*;
    use axum::{
        body::Bytes,
        extract::OriginalUri,
        http::{HeaderMap, StatusCode},
        routing::any,
        Router,
    };
    use tempfile::TempDir;

    fn with_temp_home<F>(f: F)
    where
        F: FnOnce(&TempDir),
    {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("WAF_DETECTOR_HOME").ok();
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("WAF_DETECTOR_HOME", temp_dir.path());
        f(&temp_dir);
        if let Some(value) = original_home {
            std::env::set_var("WAF_DETECTOR_HOME", value);
        } else {
            std::env::remove_var("WAF_DETECTOR_HOME");
        }
    }

    fn write_valid_consent(temp_dir: &TempDir, authorized_targets: &[&str]) {
        let consent_path = temp_dir.path().join(".waf-detector-consent.json");
        let record = serde_json::json!({
            "timestamp": chrono::Utc::now(),
            "terms_version": "1.0.0",
            "authorized_targets": authorized_targets,
            "acknowledgment": "I AGREE"
        });
        std::fs::write(consent_path, serde_json::to_string_pretty(&record).unwrap()).unwrap();
    }

    async fn start_effectiveness_server() -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route("/", any(effectiveness_test_handler));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/"), handle)
    }

    async fn effectiveness_test_handler(
        headers: HeaderMap,
        OriginalUri(uri): OriginalUri,
        body: Bytes,
    ) -> (StatusCode, String) {
        let content_type = headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let body_text = String::from_utf8_lossy(&body);
        let query = uri.query().unwrap_or_default().to_ascii_lowercase();

        let parser_variant = content_type.contains("profile=")
            || content_type.contains("charset=\"utf-8\"")
            || content_type.contains("text/xml")
            || content_type.contains("multipart/form-data; boundary=fake-boundary")
            || content_type.contains("boundary*0=real-")
            || content_type.contains("boundary=\"real-boundary\"")
            || content_type == "multipart/form-data; boundary=real-boundary;"
            || content_type.contains("multipart/form-data; boundary=real-boundary; charset=utf-8")
            || body_text.contains(r#""field1":"safe","field1":"#)
            || body_text.contains(r#""field1":["#)
            || body_text.contains("<![CDATA[")
            || body_text.contains("xmlns:ns=")
            || body_text.contains("<field0>safe</field0>")
            || body_text.contains("<!doctype root");

        let obvious_attack = query.contains("union select")
            || query.contains("waitfor")
            || query.contains("../etc/passwd")
            || query.contains("169.254.169.254")
            || query.contains("{{7*7}}")
            || query.contains("<script>")
            || query.contains("ping=127.0.0.1;id")
            || body_text.contains("<script>alert(1)</script>")
            || body_text.contains("document.cookie")
            || body_text.contains("' union select null--");

        if obvious_attack && !parser_variant {
            return (StatusCode::FORBIDDEN, "Access Denied".to_string());
        }

        (StatusCode::OK, "ok".to_string())
    }

    #[test]
    fn test_effectiveness_config_default() {
        let config = EffectivenessConfig::default();
        assert_eq!(config.max_requests_per_minute, 60);
        assert!(config.audit_logging);
        assert_eq!(config.intensity_level, 3);
        assert_eq!(config.request_timeout.as_secs(), 30);
        assert_eq!(config.request_delay.as_millis(), 500);
        assert_eq!(config.similarity_threshold, 0.65);
        assert_eq!(config.reduction_ratio, 0.70);
        assert_eq!(config.min_length_diff, 1200);
        assert!(config.parser_discrepancy_enabled);
        assert_eq!(config.parser_discrepancy_max_pairs, 18);
    }

    #[test]
    fn test_effectiveness_config_overrides() {
        let mut config = EffectivenessConfig::default();
        let overrides = EffectivenessConfigOverrides {
            max_requests_per_minute: Some(120),
            audit_logging: Some(false),
            intensity_level: Some(5),
            request_timeout_seconds: Some(10),
            request_delay_ms: Some(250),
            similarity_threshold: Some(0.5),
            reduction_ratio: Some(0.6),
            min_length_diff: Some(500),
            parser_discrepancy_enabled: Some(false),
            parser_discrepancy_max_pairs: Some(6),
        };

        config.apply_overrides(overrides);

        assert_eq!(config.max_requests_per_minute, 120);
        assert!(!config.audit_logging);
        assert_eq!(config.intensity_level, 5);
        assert_eq!(config.request_timeout.as_secs(), 10);
        assert_eq!(config.request_delay.as_millis(), 250);
        assert_eq!(config.similarity_threshold, 0.5);
        assert_eq!(config.reduction_ratio, 0.6);
        assert_eq!(config.min_length_diff, 500);
        assert!(!config.parser_discrepancy_enabled);
        assert_eq!(config.parser_discrepancy_max_pairs, 6);
    }

    #[test]
    fn test_is_blocked_detection() {
        let config = EffectivenessConfig::default();
        // Test various blocked responses
        assert!(
            EffectivenessTest::is_blocked(
                403,
                "Forbidden",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );
        assert!(
            EffectivenessTest::is_blocked(
                406,
                "Not Acceptable",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );
        assert!(
            EffectivenessTest::is_blocked(
                429,
                "Too Many Requests",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );
        assert!(
            EffectivenessTest::is_blocked(
                503,
                "Service Unavailable",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );

        // Test 200 OK with block indicators
        assert!(
            EffectivenessTest::is_blocked(
                200,
                "Access Denied",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );
        assert!(
            EffectivenessTest::is_blocked(
                200,
                "Request blocked by security policy",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );
        assert!(
            EffectivenessTest::is_blocked(
                200,
                "WAF Protection",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );
        assert!(
            EffectivenessTest::is_blocked(
                200,
                "Firewall blocked your request",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );

        // Test Akamai Bot Manager response
        assert!(
            EffectivenessTest::is_blocked(
                200,
                "OK Bot.",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );
        assert!(
            EffectivenessTest::is_blocked(
                200,
                "ok bot",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );

        // Test blocked keyword in short responses
        assert!(
            EffectivenessTest::is_blocked(
                200,
                "Blocked",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );
        // "No" alone is not a block indicator - it needs context
        assert!(
            !EffectivenessTest::is_blocked(
                200,
                "No",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );
        assert!(
            EffectivenessTest::is_blocked(
                200,
                "Access Denied",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );

        // Test normal responses that should NOT be blocked
        assert!(!EffectivenessTest::is_blocked(200, "<!DOCTYPE html><html><body>Welcome to our website! Here is some normal content that is definitely longer than 100 characters.</body></html>", &std::collections::HashMap::new(), None, &config).0);
        assert!(
            !EffectivenessTest::is_blocked(
                200,
                "",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        ); // Empty response should not be blocked
        assert!(
            !EffectivenessTest::is_blocked(
                404,
                "Not Found",
                &std::collections::HashMap::new(),
                None,
                &config,
            )
            .0
        );
    }

    #[test]
    fn test_is_blocked_header_diff_baseline() {
        use std::collections::HashMap;
        let config = EffectivenessConfig::default();

        let baseline = BaselineSignature {
            status_code: 200,
            body_sample: "Welcome to the site".to_string(),
            body_length: 21,
            headers: HashMap::new(),
        };

        let mut response_headers = HashMap::new();
        response_headers.insert("x-waf".to_string(), "blocked".to_string());

        let (blocked, reasons) = EffectivenessTest::is_blocked(
            200,
            "Welcome to the site",
            &response_headers,
            Some(&baseline),
            &config,
        );

        assert!(blocked);
        assert!(reasons.iter().any(|r| r.contains("Blocking header")));

        // If the baseline already has the same header/value, it should not be treated as a block
        let mut baseline_headers = HashMap::new();
        baseline_headers.insert("x-waf".to_string(), "blocked".to_string());
        let baseline_with_header = BaselineSignature {
            status_code: 200,
            body_sample: "Welcome to the site".to_string(),
            body_length: 21,
            headers: baseline_headers,
        };

        let (blocked_same, reasons_same) = EffectivenessTest::is_blocked(
            200,
            "Welcome to the site",
            &response_headers,
            Some(&baseline_with_header),
            &config,
        );

        assert!(!blocked_same);
        assert!(reasons_same.is_empty());
    }

    #[test]
    fn test_is_blocked_header_value_change() {
        use std::collections::HashMap;
        let config = EffectivenessConfig::default();

        let mut baseline_headers = HashMap::new();
        baseline_headers.insert("x-waf".to_string(), "monitoring".to_string());
        let baseline = BaselineSignature {
            status_code: 200,
            body_sample: "Welcome".to_string(),
            body_length: 7,
            headers: baseline_headers,
        };

        let mut response_headers = HashMap::new();
        response_headers.insert("x-waf".to_string(), "blocked".to_string());

        let (blocked, reasons) = EffectivenessTest::is_blocked(
            200,
            "Welcome",
            &response_headers,
            Some(&baseline),
            &config,
        );

        assert!(blocked);
        assert!(reasons.iter().any(|r| r.contains("Blocking header")));
    }

    #[test]
    fn test_consent_manager_creation() {
        let consent_manager = consent::ConsentManager::new();
        // Should create without errors - verify by checking it's instantiated
        drop(consent_manager); // Explicitly drop to ensure it was created
    }

    #[test]
    fn test_consent_without_file() {
        with_temp_home(|_temp_dir| {
            let consent_manager = consent::ConsentManager::new();
            let has_consent = consent_manager.has_valid_consent().unwrap();
            assert!(!has_consent);
        });
    }

    #[test]
    fn test_consent_status_without_file() {
        with_temp_home(|_temp_dir| {
            let consent_manager = consent::ConsentManager::new();
            let status = consent_manager.status().unwrap();
            assert!(!status.has_consent);
            assert!(status.authorized_targets.is_empty());
            assert!(status.expires_in_days.is_none());
        });
    }

    #[test]
    fn test_consent_status_with_file() {
        with_temp_home(|temp_dir| {
            let consent_path = temp_dir.path().join(".waf-detector-consent.json");
            let record = serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "terms_version": "1.0.0",
                "authorized_targets": ["example.com", "api.example.com"],
                "acknowledgment": "I AGREE"
            });
            std::fs::write(
                &consent_path,
                serde_json::to_string_pretty(&record).unwrap(),
            )
            .unwrap();

            let consent_manager = consent::ConsentManager::new();
            let status = consent_manager.status().unwrap();
            assert!(status.has_consent);
            assert_eq!(status.authorized_targets.len(), 2);
            assert_eq!(status.terms_version, "1.0.0");
            assert!(status.expires_in_days.unwrap_or(0) > 0);
        });
    }

    #[test]
    fn test_remove_authorized_target() {
        with_temp_home(|temp_dir| {
            let consent_path = temp_dir.path().join(".waf-detector-consent.json");
            let record = serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "terms_version": "1.0.0",
                "authorized_targets": ["example.com", "api.example.com"],
                "acknowledgment": "I AGREE"
            });
            std::fs::write(
                &consent_path,
                serde_json::to_string_pretty(&record).unwrap(),
            )
            .unwrap();

            let consent_manager = consent::ConsentManager::new();
            let removed = consent_manager
                .remove_authorized_target("api.example.com")
                .unwrap();
            assert!(removed);

            let status = consent_manager.status().unwrap();
            assert_eq!(status.authorized_targets, vec!["example.com".to_string()]);
        });
    }

    #[test]
    fn test_remove_missing_authorized_target() {
        with_temp_home(|temp_dir| {
            let consent_path = temp_dir.path().join(".waf-detector-consent.json");
            let record = serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "terms_version": "1.0.0",
                "authorized_targets": ["example.com"],
                "acknowledgment": "I AGREE"
            });
            std::fs::write(
                &consent_path,
                serde_json::to_string_pretty(&record).unwrap(),
            )
            .unwrap();

            let consent_manager = consent::ConsentManager::new();
            let removed = consent_manager
                .remove_authorized_target("missing.example.com")
                .unwrap();
            assert!(!removed);

            let status = consent_manager.status().unwrap();
            assert_eq!(status.authorized_targets, vec!["example.com".to_string()]);
        });
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
                    response_body_sample: String::new(),
                    response_body_length: 0,
                    response_headers: std::collections::HashMap::new(),
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
                response_body_sample: String::new(),
                response_body_length: 0,
                response_headers: std::collections::HashMap::new(),
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
                    response_body_sample: String::new(),
                    response_body_length: 0,
                    response_headers: std::collections::HashMap::new(),
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
                    response_body_sample: String::new(),
                    response_body_length: 0,
                    response_headers: std::collections::HashMap::new(),
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
                response_body_sample: String::new(),
                response_body_length: 0,
                response_headers: std::collections::HashMap::new(),
            },
        );

        report.add_test_result(
            "Test 2".to_string(),
            TestResult {
                blocked: false,
                status_code: 200,
                evidence: "Allowed".to_string(),
                response_time: std::time::Duration::from_millis(200),
                response_body_sample: String::new(),
                response_body_length: 0,
                response_headers: std::collections::HashMap::new(),
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
    fn test_report_parser_discrepancy_json_roundtrip() {
        let mut report = report::EffectivenessReport::new("https://example.com");
        report.parser_discrepancy = Some(report::ParserDiscrepancySummary {
            executed_pairs: 2,
            candidate_bypasses: 1,
            unique_bypasses: 1,
            by_content_type: std::collections::HashMap::from([("application/json".to_string(), 1)]),
            by_canonical_class: std::collections::HashMap::from([(
                "duplicate_json_keys".to_string(),
                1,
            )]),
            findings: vec![report::DiscrepancyFinding {
                content_type: "application/json".to_string(),
                canonical_class: "duplicate_json_keys".to_string(),
                severity: "HIGH".to_string(),
                confidence: 1.0,
                suppressed_variants: 0,
                evidence: "Control blocked; variant allowed".to_string(),
                control_replay: report::ReplayRequest {
                    method: "POST".to_string(),
                    url: "https://example.com".to_string(),
                    headers: std::collections::HashMap::from([(
                        "Content-Type".to_string(),
                        "application/json".to_string(),
                    )]),
                    body: "{\"field1\":\"safe\"}".to_string(),
                },
                variant_replay: report::ReplayRequest {
                    method: "POST".to_string(),
                    url: "https://example.com".to_string(),
                    headers: std::collections::HashMap::from([(
                        "Content-Type".to_string(),
                        "application/json; profile=\"waffled\"".to_string(),
                    )]),
                    body: "{\"field1\":\"<script>alert(1)</script>\"}".to_string(),
                },
            }],
        });

        let json = report.to_json().unwrap();
        let parsed: report::EffectivenessReport = serde_json::from_str(&json).unwrap();
        let parser_discrepancy = parsed.parser_discrepancy.unwrap();
        assert_eq!(parser_discrepancy.executed_pairs, 2);
        assert_eq!(parser_discrepancy.findings.len(), 1);
        assert_eq!(
            parser_discrepancy.findings[0].canonical_class,
            "duplicate_json_keys"
        );
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
            baseline_signature: None,
        };

        // This should trigger rate limiting and introduce a delay
        test.rate_limit().await.unwrap();

        // The rate limiter should have introduced a delay
        let elapsed = start.elapsed();
        // Should have delayed for at least 1 second (60 requests/min = 1/sec)
        assert!(elapsed.as_millis() >= 500); // Allow some tolerance
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_effectiveness_runs_parser_discrepancy_phase_by_default() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("WAF_DETECTOR_HOME").ok();
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("WAF_DETECTOR_HOME", temp_dir.path());
        write_valid_consent(&temp_dir, &["127.0.0.1"]);
        let (url, handle) = start_effectiveness_server().await;

        let mut config = EffectivenessConfig::default();
        config.max_requests_per_minute = 10_000;
        config.request_delay = std::time::Duration::from_millis(0);

        let mut test = EffectivenessTest::new(config).await.unwrap();
        let report = test.test_effectiveness(&url).await.unwrap();

        handle.abort();
        if let Some(value) = original_home {
            std::env::set_var("WAF_DETECTOR_HOME", value);
        } else {
            std::env::remove_var("WAF_DETECTOR_HOME");
        }

        assert!(report
            .phases
            .iter()
            .any(|phase| phase.name == "Parser Discrepancy Testing"));
        let parser_discrepancy = report.parser_discrepancy.unwrap();
        assert_eq!(parser_discrepancy.executed_pairs, 18);
        assert!(parser_discrepancy.candidate_bypasses > 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_effectiveness_can_disable_parser_discrepancy_via_toml_override() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("WAF_DETECTOR_HOME").ok();
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("WAF_DETECTOR_HOME", temp_dir.path());
        write_valid_consent(&temp_dir, &["127.0.0.1"]);
        let (url, handle) = start_effectiveness_server().await;

        let mut config = EffectivenessConfig::default();
        let overrides: EffectivenessConfigOverrides = toml::from_str(
            r#"
parser_discrepancy_enabled = false
parser_discrepancy_max_pairs = 3
"#,
        )
        .unwrap();
        config.apply_overrides(overrides);
        config.max_requests_per_minute = 10_000;
        config.request_delay = std::time::Duration::from_millis(0);

        let mut test = EffectivenessTest::new(config).await.unwrap();
        let report = test.test_effectiveness(&url).await.unwrap();

        handle.abort();
        if let Some(value) = original_home {
            std::env::set_var("WAF_DETECTOR_HOME", value);
        } else {
            std::env::remove_var("WAF_DETECTOR_HOME");
        }

        assert!(!report
            .phases
            .iter()
            .any(|phase| phase.name == "Parser Discrepancy Testing"));
        assert!(report.parser_discrepancy.is_none());
    }
}
