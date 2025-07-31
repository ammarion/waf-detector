use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Test case definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub name: String,
    pub description: String,
    pub url: String,
    pub expectations: TestExpectation,
    pub mock_responses: Option<HashMap<String, MockResponseConfig>>,
    pub timeout_seconds: Option<u64>,
    pub tags: Vec<String>,
}

/// Expected test outcomes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestExpectation {
    pub waf_provider: Option<String>,
    pub cdn_provider: Option<String>,
    pub min_confidence: Option<f64>,
    pub should_detect_waf: bool,
    pub should_detect_cdn: bool,
    pub expected_headers: Option<Vec<String>>,
    pub expected_status: Option<u16>,
    pub expected_evidence_count: Option<usize>,
}

/// Mock response configuration for test cases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockResponseConfig {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub body_file: Option<String>,
}

/// Collection of test data for various scenarios
#[allow(dead_code)]
pub struct TestDataProvider;

impl TestDataProvider {
    /// Get CloudFlare test cases
    pub fn cloudflare_test_cases() -> Vec<TestCase> {
        vec![
            TestCase {
                name: "cloudflare_basic_detection".to_string(),
                description: "Basic CloudFlare detection with standard headers".to_string(),
                url: "https://example.com".to_string(),
                expectations: TestExpectation {
                    waf_provider: Some("CloudFlare".to_string()),
                    cdn_provider: Some("CloudFlare".to_string()),
                    min_confidence: Some(0.95),
                    should_detect_waf: true,
                    should_detect_cdn: true,
                    expected_headers: Some(vec!["cf-ray".to_string()]),
                    expected_status: Some(200),
                    expected_evidence_count: Some(3),
                },
                mock_responses: None,
                timeout_seconds: Some(10),
                tags: vec!["cloudflare".to_string(), "basic".to_string()],
            },
            TestCase {
                name: "cloudflare_challenge_page".to_string(),
                description: "CloudFlare challenge page detection".to_string(),
                url: "https://example.com/challenge".to_string(),
                expectations: TestExpectation {
                    waf_provider: Some("CloudFlare".to_string()),
                    cdn_provider: Some("CloudFlare".to_string()),
                    min_confidence: Some(1.0),
                    should_detect_waf: true,
                    should_detect_cdn: true,
                    expected_headers: Some(vec!["cf-ray".to_string()]),
                    expected_status: Some(503),
                    expected_evidence_count: Some(4),
                },
                mock_responses: None,
                timeout_seconds: Some(10),
                tags: vec!["cloudflare".to_string(), "challenge".to_string()],
            },
            TestCase {
                name: "cloudflare_rate_limit".to_string(),
                description: "CloudFlare rate limiting detection".to_string(),
                url: "https://example.com/api".to_string(),
                expectations: TestExpectation {
                    waf_provider: Some("CloudFlare".to_string()),
                    cdn_provider: Some("CloudFlare".to_string()),
                    min_confidence: Some(0.95),
                    should_detect_waf: true,
                    should_detect_cdn: true,
                    expected_headers: Some(vec!["cf-ray".to_string()]),
                    expected_status: Some(429),
                    expected_evidence_count: Some(3),
                },
                mock_responses: None,
                timeout_seconds: Some(10),
                tags: vec!["cloudflare".to_string(), "rate-limit".to_string()],
            },
        ]
    }

    /// Get AWS test cases
    pub fn aws_test_cases() -> Vec<TestCase> {
        vec![
            TestCase {
                name: "aws_cloudfront_basic".to_string(),
                description: "AWS CloudFront basic detection".to_string(),
                url: "https://example.com".to_string(),
                expectations: TestExpectation {
                    waf_provider: None,
                    cdn_provider: Some("AWS".to_string()),
                    min_confidence: Some(0.90),
                    should_detect_waf: false,
                    should_detect_cdn: true,
                    expected_headers: Some(vec!["x-amz-cf-id".to_string()]),
                    expected_status: Some(200),
                    expected_evidence_count: Some(2),
                },
                mock_responses: None,
                timeout_seconds: Some(10),
                tags: vec!["aws".to_string(), "cloudfront".to_string()],
            },
            TestCase {
                name: "aws_waf_blocked".to_string(),
                description: "AWS WAF blocking request".to_string(),
                url: "https://example.com/blocked".to_string(),
                expectations: TestExpectation {
                    waf_provider: Some("AWS".to_string()),
                    cdn_provider: Some("AWS".to_string()),
                    min_confidence: Some(0.95),
                    should_detect_waf: true,
                    should_detect_cdn: true,
                    expected_headers: Some(vec!["x-amzn-requestid".to_string()]),
                    expected_status: Some(403),
                    expected_evidence_count: Some(3),
                },
                mock_responses: None,
                timeout_seconds: Some(10),
                tags: vec!["aws".to_string(), "waf".to_string(), "blocked".to_string()],
            },
        ]
    }

    /// Get all provider test cases
    pub fn all_provider_test_cases() -> Vec<TestCase> {
        let mut cases = Vec::new();
        cases.extend(Self::cloudflare_test_cases());
        cases.extend(Self::aws_test_cases());
        cases.extend(Self::akamai_test_cases());
        cases.extend(Self::fastly_test_cases());
        cases.extend(Self::azure_test_cases());
        cases.extend(Self::f5_test_cases());
        cases
    }

    /// Get Akamai test cases
    pub fn akamai_test_cases() -> Vec<TestCase> {
        vec![TestCase {
            name: "akamai_basic_detection".to_string(),
            description: "Akamai CDN basic detection".to_string(),
            url: "https://example.com".to_string(),
            expectations: TestExpectation {
                waf_provider: Some("Akamai".to_string()),
                cdn_provider: Some("Akamai".to_string()),
                min_confidence: Some(0.85),
                should_detect_waf: true,
                should_detect_cdn: true,
                expected_headers: Some(vec!["x-akamai-edgescape".to_string()]),
                expected_status: Some(200),
                expected_evidence_count: Some(2),
            },
            mock_responses: None,
            timeout_seconds: Some(10),
            tags: vec!["akamai".to_string(), "basic".to_string()],
        }]
    }

    /// Get Fastly test cases
    pub fn fastly_test_cases() -> Vec<TestCase> {
        vec![TestCase {
            name: "fastly_basic_detection".to_string(),
            description: "Fastly CDN basic detection".to_string(),
            url: "https://example.com".to_string(),
            expectations: TestExpectation {
                waf_provider: Some("Fastly".to_string()),
                cdn_provider: Some("Fastly".to_string()),
                min_confidence: Some(0.90),
                should_detect_waf: true,
                should_detect_cdn: true,
                expected_headers: Some(vec!["x-served-by".to_string()]),
                expected_status: Some(200),
                expected_evidence_count: Some(3),
            },
            mock_responses: None,
            timeout_seconds: Some(10),
            tags: vec!["fastly".to_string(), "basic".to_string()],
        }]
    }

    /// Get Azure test cases
    pub fn azure_test_cases() -> Vec<TestCase> {
        vec![TestCase {
            name: "azure_front_door_detection".to_string(),
            description: "Azure Front Door detection".to_string(),
            url: "https://example.com".to_string(),
            expectations: TestExpectation {
                waf_provider: Some("Azure".to_string()),
                cdn_provider: Some("Azure".to_string()),
                min_confidence: Some(0.85),
                should_detect_waf: true,
                should_detect_cdn: true,
                expected_headers: Some(vec!["x-azure-ref".to_string()]),
                expected_status: Some(200),
                expected_evidence_count: Some(2),
            },
            mock_responses: None,
            timeout_seconds: Some(10),
            tags: vec!["azure".to_string(), "front-door".to_string()],
        }]
    }

    /// Get F5 test cases
    pub fn f5_test_cases() -> Vec<TestCase> {
        vec![TestCase {
            name: "f5_big_ip_detection".to_string(),
            description: "F5 BIG-IP detection".to_string(),
            url: "https://example.com".to_string(),
            expectations: TestExpectation {
                waf_provider: Some("F5".to_string()),
                cdn_provider: None,
                min_confidence: Some(0.85),
                should_detect_waf: true,
                should_detect_cdn: false,
                expected_headers: Some(vec!["x-wa-info".to_string()]),
                expected_status: Some(200),
                expected_evidence_count: Some(2),
            },
            mock_responses: None,
            timeout_seconds: Some(10),
            tags: vec!["f5".to_string(), "big-ip".to_string()],
        }]
    }

    /// Get negative test cases (no WAF/CDN)
    pub fn negative_test_cases() -> Vec<TestCase> {
        vec![TestCase {
            name: "no_waf_cdn_plain_site".to_string(),
            description: "Plain website with no WAF or CDN".to_string(),
            url: "https://example.com".to_string(),
            expectations: TestExpectation {
                waf_provider: None,
                cdn_provider: None,
                min_confidence: None,
                should_detect_waf: false,
                should_detect_cdn: false,
                expected_headers: None,
                expected_status: Some(200),
                expected_evidence_count: Some(0),
            },
            mock_responses: None,
            timeout_seconds: Some(10),
            tags: vec!["negative".to_string(), "no-protection".to_string()],
        }]
    }

    /// Get edge case test scenarios
    pub fn edge_case_test_cases() -> Vec<TestCase> {
        vec![
            TestCase {
                name: "multiple_cdns_layered".to_string(),
                description: "Multiple CDNs in front of each other".to_string(),
                url: "https://example.com".to_string(),
                expectations: TestExpectation {
                    waf_provider: Some("CloudFlare".to_string()),
                    cdn_provider: Some("CloudFlare".to_string()),
                    min_confidence: Some(0.80),
                    should_detect_waf: true,
                    should_detect_cdn: true,
                    expected_headers: None,
                    expected_status: Some(200),
                    expected_evidence_count: Some(5),
                },
                mock_responses: None,
                timeout_seconds: Some(15),
                tags: vec!["edge-case".to_string(), "multiple-cdn".to_string()],
            },
            TestCase {
                name: "false_positive_test".to_string(),
                description: "Headers that might trigger false positives".to_string(),
                url: "https://example.com".to_string(),
                expectations: TestExpectation {
                    waf_provider: None,
                    cdn_provider: None,
                    min_confidence: None,
                    should_detect_waf: false,
                    should_detect_cdn: false,
                    expected_headers: None,
                    expected_status: Some(200),
                    expected_evidence_count: Some(0),
                },
                mock_responses: None,
                timeout_seconds: Some(10),
                tags: vec!["edge-case".to_string(), "false-positive".to_string()],
            },
        ]
    }
}
