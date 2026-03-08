//! WAF Effectiveness Testing Module
//!
//! This module provides functionality to test the effectiveness of Web Application Firewalls
//! in a responsible and ethical manner. It is designed for security professionals to validate
//! their own defensive systems.
//!
//! ⚠️ WARNING: Only use this module against systems you own or have explicit permission to test.

use crate::active::{guard_target, ResolvedTarget};
use crate::http::HttpClient;
use anyhow::{anyhow, Result};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{info, warn};

pub mod consent;
pub mod parser_discrepancy;
pub mod patterns;
pub mod report;
pub mod static_detection;
pub mod techniques;
pub mod waffled_techniques;

#[cfg(test)]
mod tests;

use consent::ConsentManager;
use parser_discrepancy::{execute_campaign, ParserDiscrepancyExecutor};
use report::{EffectivenessReport, Recommendation, Vulnerability};
use static_detection::{analyze_static_page, format_static_page_warning};
use techniques::TestingTechnique;

/// Configuration for WAF effectiveness testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivenessConfig {
    /// Maximum requests per minute (rate limiting)
    pub max_requests_per_minute: u32,
    /// Enable audit logging
    pub audit_logging: bool,
    /// Test intensity level (1-5, where 5 is most aggressive)
    pub intensity_level: u8,
    /// Custom headers to include in requests
    pub custom_headers: HashMap<String, String>,
    /// Timeout for each request
    pub request_timeout: Duration,
    /// Delay between requests (for stealth)
    pub request_delay: Duration,
    /// Body similarity threshold for detecting abnormal block pages
    pub similarity_threshold: f64,
    /// Minimum reduction ratio relative to baseline to flag an unusual response
    pub reduction_ratio: f64,
    /// Avoid flagging small responses; require meaningful absolute length change
    pub min_length_diff: usize,
    /// Whether curated parser discrepancy testing is enabled
    pub parser_discrepancy_enabled: bool,
    /// Maximum number of curated parser discrepancy pairs to execute
    pub parser_discrepancy_max_pairs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EffectivenessConfigOverrides {
    pub max_requests_per_minute: Option<u32>,
    pub audit_logging: Option<bool>,
    pub intensity_level: Option<u8>,
    pub request_timeout_seconds: Option<u64>,
    pub request_delay_ms: Option<u64>,
    pub similarity_threshold: Option<f64>,
    pub reduction_ratio: Option<f64>,
    pub min_length_diff: Option<usize>,
    pub parser_discrepancy_enabled: Option<bool>,
    pub parser_discrepancy_max_pairs: Option<usize>,
}

impl Default for EffectivenessConfig {
    fn default() -> Self {
        Self {
            max_requests_per_minute: 60,
            audit_logging: true,
            intensity_level: 3,
            custom_headers: HashMap::new(),
            request_timeout: Duration::from_secs(30),
            request_delay: Duration::from_millis(500),
            similarity_threshold: 0.65,
            reduction_ratio: 0.70,
            min_length_diff: 1200,
            parser_discrepancy_enabled: true,
            parser_discrepancy_max_pairs: 18,
        }
    }
}

impl EffectivenessConfig {
    pub fn apply_overrides(&mut self, overrides: EffectivenessConfigOverrides) {
        if let Some(value) = overrides.max_requests_per_minute {
            self.max_requests_per_minute = value;
        }
        if let Some(value) = overrides.audit_logging {
            self.audit_logging = value;
        }
        if let Some(value) = overrides.intensity_level {
            self.intensity_level = value;
        }
        if let Some(value) = overrides.request_timeout_seconds {
            self.request_timeout = Duration::from_secs(value);
        }
        if let Some(value) = overrides.request_delay_ms {
            self.request_delay = Duration::from_millis(value);
        }
        if let Some(value) = overrides.similarity_threshold {
            self.similarity_threshold = value;
        }
        if let Some(value) = overrides.reduction_ratio {
            self.reduction_ratio = value;
        }
        if let Some(value) = overrides.min_length_diff {
            self.min_length_diff = value;
        }
        if let Some(value) = overrides.parser_discrepancy_enabled {
            self.parser_discrepancy_enabled = value;
        }
        if let Some(value) = overrides.parser_discrepancy_max_pairs {
            self.parser_discrepancy_max_pairs = value.max(1);
        }
    }
}

/// Main WAF effectiveness testing engine
pub struct EffectivenessTest {
    config: EffectivenessConfig,
    consent_manager: ConsentManager,
    http_client: HttpClient,
    start_time: Instant,
    request_count: u32,
    baseline_signature: Option<BaselineSignature>,
    resolved_target: Option<ResolvedTarget>,
}

#[derive(Debug, Clone)]
pub(crate) struct BaselineSignature {
    status_code: u16,
    body_sample: String,
    body_length: usize,
    headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
struct BlockTemplate {
    vendor: &'static str,
    markers: &'static [&'static str],
}

const BLOCK_TEMPLATES: &[BlockTemplate] = &[
    BlockTemplate {
        vendor: "CloudFlare",
        markers: &["cloudflare", "attention required", "ray id"],
    },
    BlockTemplate {
        vendor: "Akamai",
        markers: &["akamai", "reference", "incident id"],
    },
    BlockTemplate {
        vendor: "AWS WAF",
        markers: &["request blocked", "aws waf"],
    },
    BlockTemplate {
        vendor: "F5 BIG-IP",
        markers: &["the requested url was rejected", "support id"],
    },
    BlockTemplate {
        vendor: "Sucuri",
        markers: &["access denied", "sucuri"],
    },
    BlockTemplate {
        vendor: "Imperva",
        markers: &["incapsula", "incident id"],
    },
];

impl EffectivenessTest {
    /// Check if a response indicates blocking
    pub(crate) fn is_blocked(
        status_code: u16,
        body: &str,
        response_headers: &HashMap<String, String>,
        baseline: Option<&BaselineSignature>,
        config: &EffectivenessConfig,
    ) -> (bool, Vec<String>) {
        let mut reasons = Vec::new();
        let similarity_threshold = config.similarity_threshold;
        let reduction_ratio = config.reduction_ratio;
        let min_length_diff = config.min_length_diff;

        // Check common block status codes
        if status_code == 403 || status_code == 406 || status_code == 429 || status_code == 503 {
            reasons.push(format!("Blocking status code: {status_code}"));
        }

        // Check for block patterns in response body (baseline-aware)
        let body_lower = body.to_lowercase();
        let block_indicators = [
            "access denied",
            "forbidden",
            "blocked",
            "firewall",
            "security policy",
            "violation",
            "suspicious",
            "malicious",
            "threat detected",
            "request rejected",
            "ok bot",
            "waf protection",
        ];

        for indicator in block_indicators {
            if body_lower.contains(indicator) {
                let baseline_has_indicator = baseline
                    .map(|b| b.body_sample.to_lowercase().contains(indicator))
                    .unwrap_or(false);

                if !baseline_has_indicator {
                    reasons.push(format!("Blocking keyword detected: {indicator}"));
                }
            }
        }

        if let Some(vendor) = Self::match_block_template(&body_lower, baseline) {
            reasons.push(format!("Block page template match: {vendor}"));
        }

        // Baseline-aware body delta: large reduction or low similarity can indicate blocking
        if let Some(baseline_sig) = baseline {
            // Header diffs: detect WAF/block indicators that appear only after the test
            let header_indicators = [
                "waf",
                "blocked",
                "denied",
                "forbidden",
                "cf-ray",
                "x-amz-cf-id",
                "x-amz-cf-pop",
                "x-akamai",
                "x-sucuri",
                "x-waf",
                "x-denied",
                "x-blocked",
                "x-azure",
            ];

            for (name, value) in response_headers {
                let name_lower = name.to_lowercase();
                let value_lower = value.to_lowercase();
                let baseline_has_header = baseline_sig.headers.contains_key(&name_lower);
                let baseline_header_value = baseline_sig
                    .headers
                    .get(&name_lower)
                    .map(|v| v.to_lowercase());

                let indicator_match = header_indicators.iter().any(|indicator| {
                    name_lower.contains(indicator) || value_lower.contains(indicator)
                });

                if indicator_match {
                    let is_new_or_changed = !baseline_has_header
                        || baseline_header_value
                            .map(|v| v != value_lower)
                            .unwrap_or(true);
                    if is_new_or_changed {
                        reasons.push(format!("Blocking header detected: {name}"));
                    }
                }
            }

            let similarity =
                static_detection::calculate_similarity(body, &baseline_sig.body_sample);
            let length_diff =
                (baseline_sig.body_length as i64 - body.len() as i64).unsigned_abs() as usize;
            let significant_reduction = body.len()
                < (baseline_sig.body_length as f64 * reduction_ratio) as usize
                && length_diff > min_length_diff;

            if similarity < similarity_threshold && significant_reduction {
                reasons.push("Response body deviates significantly from baseline".to_string());
            }
        }

        // Auth challenge allowlist: don't flag as blocked if it's likely auth and no other signals
        if let Some(_value) = response_headers.get("www-authenticate") {
            if status_code == 401 {
                if reasons.len() == 1
                    && reasons
                        .first()
                        .is_some_and(|r| r.contains("Blocking status code"))
                {
                    return (false, Vec::new());
                }

                if body.to_lowercase().contains("login") || body.to_lowercase().contains("sign in")
                {
                    return (false, Vec::new());
                }
            }

            // In rare cases a 403 with WWW-Authenticate is still an auth gate
            if status_code == 403
                && reasons.len() == 1
                && reasons
                    .first()
                    .is_some_and(|r| r.contains("Blocking status code"))
            {
                return (false, Vec::new());
            }
        }

        // If baseline status matches and only status triggered, treat as not blocked
        if let Some(baseline_sig) = baseline {
            if status_code == baseline_sig.status_code
                && reasons.len() == 1
                && reasons
                    .first()
                    .is_some_and(|r| r.contains("Blocking status code"))
            {
                return (false, Vec::new());
            }
        }

        (!reasons.is_empty(), reasons)
    }

    /// Create a new effectiveness test instance
    pub async fn new(config: EffectivenessConfig) -> Result<Self> {
        // Ensure user has acknowledged responsible use
        let consent_manager = ConsentManager::new();
        if !consent_manager.has_valid_consent()? {
            return Err(anyhow!(
                "An active target scope is required before using effectiveness testing features"
            ));
        }

        Ok(Self {
            config,
            consent_manager,
            http_client: HttpClient::new()?,
            start_time: Instant::now(),
            request_count: 0,
            baseline_signature: None,
            resolved_target: None,
        })
    }

    /// Test WAF effectiveness against a target URL
    pub async fn test_effectiveness(&mut self, url: &str) -> Result<EffectivenessReport> {
        let target = guard_target(&self.consent_manager, url)?;
        self.test_effectiveness_with_target(&target).await
    }

    pub async fn test_effectiveness_with_target(
        &mut self,
        target: &ResolvedTarget,
    ) -> Result<EffectivenessReport> {
        info!(
            "Starting WAF effectiveness test for: {}",
            target.normalized_url
        );

        self.resolved_target = Some(target.clone());

        // Check if target appears to be serving static content
        let parser_discrepancy_static_or_ambiguous = match analyze_static_page(&target.normalized_url).await {
            Ok(analysis) => {
                if analysis.is_likely_static {
                    warn!("{}", format_static_page_warning(&analysis));
                }
                analysis.is_likely_static
            }
            Err(e) => {
                warn!("Could not analyze if target is static: {}", e);
                true
            }
        };

        let mut report = EffectivenessReport::new(&target.normalized_url);

        // Phase 1: Baseline testing (benign requests)
        report.add_phase("Baseline Testing".to_string());
        self.test_baseline(&target.normalized_url, &mut report)
            .await?;

        // Phase 2: Detection testing (with various techniques)
        report.add_phase("Detection Testing".to_string());
        self.test_detection_capabilities(&target.normalized_url, &mut report)
            .await?;

        if self.config.parser_discrepancy_enabled {
            report.add_phase("Parser Discrepancy Testing".to_string());
            self.test_parser_discrepancy_techniques(
                &target.normalized_url,
                &mut report,
                parser_discrepancy_static_or_ambiguous,
            )
            .await?;
        }

        // Phase 3: Evasion testing (if intensity level allows)
        if self.config.intensity_level >= 4 {
            report.add_phase("Advanced Evasion Testing".to_string());
            self.test_evasion_techniques(&target.normalized_url, &mut report)
                .await?;
        }

        // Generate recommendations based on findings
        self.generate_recommendations(&mut report);

        // Log completion
        if self.config.audit_logging {
            self.log_test_completion(&report)?;
        }

        Ok(report)
    }

    /// Test baseline behavior with benign requests
    async fn test_baseline(&mut self, url: &str, report: &mut EffectivenessReport) -> Result<()> {
        info!("Testing baseline behavior");

        let baseline_tests = vec![
            ("Normal GET request", "GET", ""),
            (
                "Normal POST request",
                "POST",
                "name=test&email=test@example.com",
            ),
            ("Large header", "GET", ""), // Will add large header in implementation
        ];

        let mut response_bodies = Vec::new();
        let mut baseline_results = Vec::new();

        for (test_name, method, body) in baseline_tests {
            self.rate_limit().await?;

            // Add large header for the large header test
            let mut headers = HashMap::new();
            if test_name == "Large header" {
                headers.insert(
                    "X-Large-Header".to_string(),
                    "A".repeat(1000), // 1KB header
                );
            }

            // Perform test and record results
            let result = self.perform_request(url, method, body, headers).await?;

            // Store response for similarity check
            response_bodies.push(result.response_body_sample.clone());
            baseline_results.push(result.clone());

            report.add_baseline_result(test_name, result);
        }

        // Check if all responses are suspiciously similar (indicating no parameter processing)
        if response_bodies.len() >= 2 {
            let all_similar = response_bodies.windows(2).all(|w| {
                let similarity = static_detection::calculate_similarity(&w[0], &w[1]);
                similarity > 0.95
            });

            if all_similar {
                warn!("⚠️  All baseline requests returned nearly identical responses!");
                warn!("   This suggests the server may not be processing parameters.");
                report.add_recommendation(Recommendation {
                    priority: "WARNING".to_string(),
                    category: "Parameter Processing".to_string(),
                    description: "Server returns identical responses regardless of parameters".to_string(),
                    implementation: "Ensure you're testing endpoints that actually process user input. \
                                   Consider testing form submissions, API endpoints, or search functionality."
                        .to_string(),
                });
            }
        }

        if self.baseline_signature.is_none() {
            self.baseline_signature = Self::build_baseline_signature(&baseline_results);
        }

        Ok(())
    }

    /// Test detection capabilities with various attack patterns
    async fn test_detection_capabilities(
        &mut self,
        url: &str,
        report: &mut EffectivenessReport,
    ) -> Result<()> {
        info!("Testing detection capabilities");

        // Get testing techniques based on intensity level
        let techniques = techniques::get_techniques_for_level(self.config.intensity_level);

        for technique in techniques {
            self.rate_limit().await?;

            let result = self.apply_technique(url, &technique).await?;

            // Record vulnerability if WAF failed to block
            if !result.blocked {
                report.add_vulnerability(Vulnerability {
                    severity: technique.severity,
                    category: technique.category.clone(),
                    description: format!(
                        "WAF failed to block {} attack: {}",
                        technique.category, technique.name
                    ),
                    evidence: result.evidence.clone(),
                    remediation: technique.remediation.clone(),
                });
            }

            report.add_test_result(technique.name.clone(), result);
        }

        // Test benign patterns for false positive rate
        info!("Testing benign patterns for false positive detection");
        self.test_benign_patterns(url, report).await?;

        Ok(())
    }

    /// Test benign patterns to measure false positive rate
    async fn test_benign_patterns(
        &mut self,
        url: &str,
        report: &mut EffectivenessReport,
    ) -> Result<()> {
        let benign_techniques = techniques::get_benign_techniques();

        for technique in benign_techniques {
            self.rate_limit().await?;

            let result = self.apply_technique(url, &technique).await?;

            // Track false positives (benign requests that were blocked)
            report.statistics.benign_tests_count += 1;
            if result.blocked {
                report.statistics.false_positive_count += 1;

                warn!(
                    "False positive detected: Benign request '{}' was incorrectly blocked",
                    technique.name
                );
            }

            report.add_test_result(format!("Benign: {}", technique.name), result);
        }

        // Calculate false positive rate
        if report.statistics.benign_tests_count > 0 {
            report.statistics.false_positive_rate = report.statistics.false_positive_count as f64
                / report.statistics.benign_tests_count as f64;
        }

        Ok(())
    }

    /// Test advanced evasion techniques
    async fn test_evasion_techniques(
        &mut self,
        url: &str,
        report: &mut EffectivenessReport,
    ) -> Result<()> {
        warn!("Testing advanced evasion techniques - High intensity mode");

        let evasion_techniques = techniques::get_evasion_techniques();

        for technique in evasion_techniques {
            self.rate_limit().await?;

            let result = self.apply_technique(url, &technique).await?;

            if !result.blocked {
                report.add_vulnerability(Vulnerability {
                    severity: "HIGH".to_string(),
                    category: "Evasion".to_string(),
                    description: format!("WAF vulnerable to evasion technique: {}", technique.name),
                    evidence: result.evidence.clone(),
                    remediation: format!(
                        "Update WAF rules to detect {}. {}",
                        technique.name, technique.remediation
                    ),
                });
            }

            report.add_test_result(format!("Evasion: {}", technique.name), result);
        }

        Ok(())
    }

    async fn test_parser_discrepancy_techniques(
        &mut self,
        url: &str,
        report: &mut EffectivenessReport,
        static_or_ambiguous: bool,
    ) -> Result<()> {
        let run = execute_campaign(
            self,
            url,
            self.config.parser_discrepancy_max_pairs,
            static_or_ambiguous,
        )
        .await?;

        for pair in &run.executed_pairs {
            report.add_test_result(
                format!("Parser Discrepancy Control: {}", pair.pair.name),
                pair.control_result.clone(),
            );
            report.add_test_result(
                format!("Parser Discrepancy Variant: {}", pair.pair.name),
                pair.variant_result.clone(),
            );
        }

        for finding in &run.summary.findings {
            report.add_vulnerability(Vulnerability {
                severity: finding.severity.clone(),
                category: "Parser Discrepancy".to_string(),
                description: format!(
                    "Candidate parser discrepancy bypass via {} ({})",
                    finding.canonical_class, finding.content_type
                ),
                evidence: finding.evidence.clone(),
                remediation: "Normalize request bodies and enforce strict RFC-compliant content-type/body parsing before WAF evaluation.".to_string(),
            });
        }

        report.parser_discrepancy = Some(run.summary);
        Ok(())
    }

    /// Apply a specific testing technique
    async fn apply_technique(
        &mut self,
        url: &str,
        technique: &TestingTechnique,
    ) -> Result<TestResult> {
        // Apply technique-specific modifications
        let mut headers = self.config.custom_headers.clone();
        headers.extend(technique.headers.clone());

        let result = self
            .perform_request(url, &technique.method, &technique.payload, headers)
            .await?;

        Ok(result)
    }

    /// Perform an HTTP request with rate limiting
    async fn perform_request(
        &mut self,
        url: &str,
        method: &str,
        body: &str,
        headers: HashMap<String, String>,
    ) -> Result<TestResult> {
        self.request_count += 1;

        // Add request delay for stealth
        sleep(self.config.request_delay).await;

        let mut headers = headers;
        let has_valid_user_agent = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("user-agent") && !v.trim().is_empty());
        if !has_valid_user_agent {
            let agents = techniques::get_user_agents();
            let mut rng = rand::thread_rng();
            let ua = agents
                .choose(&mut rng)
                .copied()
                .unwrap_or("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
            headers.insert("User-Agent".to_string(), ua.to_string());
            let fingerprint = techniques::random_browser_fingerprint();
            techniques::apply_browser_fingerprint_headers(&mut headers, fingerprint);
        }

        let header_list = headers.into_iter().collect::<Vec<_>>();

        let start = Instant::now();
        let response_result = if let Some(target) = &self.resolved_target {
            self.http_client
                .request_pinned(
                    method,
                    url,
                    &header_list,
                    match method {
                        "POST" | "PUT" | "PATCH" | "DELETE" => Some(body),
                        _ => None,
                    },
                    target.pinned_ip,
                    Some(self.config.request_timeout),
                )
                .await
        } else {
            self.http_client
                .request(
                    method,
                    url,
                    &header_list,
                    match method {
                        "POST" | "PUT" | "PATCH" | "DELETE" => Some(body),
                        _ => None,
                    },
                )
                .await
        };
        let duration = start.elapsed();

        match response_result {
            Ok(response) => {
                let status_code = response.status;
                let headers = response.headers.clone();
                let response_text = response.body.clone();
                let (blocked, reasons) = Self::is_blocked(
                    status_code,
                    &response_text,
                    &headers,
                    self.baseline_signature.as_ref(),
                    &self.config,
                );

                Ok(TestResult {
                    blocked,
                    status_code,
                    evidence: if blocked {
                        format!(
                            "Blocked: {} | Sample: {}",
                            reasons.join("; "),
                            &response_text.chars().take(200).collect::<String>()
                        )
                    } else {
                        "Request allowed".to_string()
                    },
                    response_time: duration,
                    response_body_sample: response_text.chars().take(2000).collect(),
                    response_body_length: response_text.len(),
                    response_headers: headers,
                })
            }
            Err(e) => Ok(TestResult {
                blocked: false,
                status_code: 0,
                evidence: format!("Connection failed: {e}"),
                response_time: duration,
                response_body_sample: String::new(),
                response_body_length: 0,
                response_headers: HashMap::new(),
            }),
        }
    }

    pub(crate) async fn execute_replay_request(
        &mut self,
        request: &crate::effectiveness::report::ReplayRequest,
    ) -> Result<TestResult> {
        self.rate_limit().await?;
        self.perform_request(
            &request.url,
            &request.method,
            &request.body,
            request.headers.clone(),
        )
        .await
    }

    /// Enforce rate limiting
    async fn rate_limit(&mut self) -> Result<()> {
        let elapsed = self.start_time.elapsed().as_secs_f64() / 60.0;
        let current_rate = self.request_count as f64 / elapsed.max(1.0);

        if current_rate > self.config.max_requests_per_minute as f64 {
            let delay = Duration::from_secs_f64(60.0 / self.config.max_requests_per_minute as f64);
            sleep(delay).await;
        }

        Ok(())
    }

    /// Generate recommendations based on test results
    fn generate_recommendations(&self, report: &mut EffectivenessReport) {
        // Analyze vulnerabilities and generate recommendations
        let vuln_categories: Vec<String> = report
            .vulnerabilities
            .iter()
            .map(|v| v.category.clone())
            .collect();

        if vuln_categories.contains(&"SQL Injection".to_string()) {
            report.add_recommendation(Recommendation {
                priority: "HIGH".to_string(),
                category: "Rule Updates".to_string(),
                description: "Update WAF rules to better detect SQL injection patterns".to_string(),
                implementation: "Enable OWASP CRS SQLi rules and custom patterns for your database"
                    .to_string(),
            });
        }

        if vuln_categories.contains(&"XSS".to_string()) {
            report.add_recommendation(Recommendation {
                priority: "HIGH".to_string(),
                category: "Rule Updates".to_string(),
                description: "Strengthen XSS detection rules".to_string(),
                implementation: "Enable comprehensive XSS filters including DOM-based patterns"
                    .to_string(),
            });
        }

        if vuln_categories.contains(&"Parser Discrepancy".to_string()) {
            report.add_recommendation(Recommendation {
                priority: "HIGH".to_string(),
                category: "Normalization".to_string(),
                description: "Parser discrepancy candidate bypasses were observed".to_string(),
                implementation: "Add strict content-type normalization and RFC-compliant request validation ahead of WAF evaluation, especially for multipart, JSON, and XML bodies.".to_string(),
            });
        }

        if report.vulnerabilities.len() > 5 {
            report.add_recommendation(Recommendation {
                priority: "CRITICAL".to_string(),
                category: "Configuration".to_string(),
                description: "WAF appears to be in detection-only mode or misconfigured".to_string(),
                implementation: "Review WAF mode settings and ensure blocking is enabled for high-confidence attacks".to_string(),
            });
        }

        // Specific check for "Monitoring Mode" (WAF present but not blocking)
        if report.statistics.blocked_requests == 0 && report.statistics.total_tests > 0 {
            report.add_recommendation(Recommendation {
                priority: "CRITICAL".to_string(),
                category: "WAF Mode".to_string(),
                description: "No attacks were blocked (0% block rate).".to_string(),
                implementation: "If a WAF is present, it is likely in 'Monitoring' or 'Log-Only' mode. Change to 'Blocking' mode to prevent attacks.".to_string(),
            });
        }

        // Check for high false positive rate
        if report.statistics.false_positive_rate > 0.1 {
            report.add_recommendation(Recommendation {
                priority: "HIGH".to_string(),
                category: "False Positives".to_string(),
                description: format!(
                    "High false positive rate detected ({:.1}% of benign requests blocked)",
                    report.statistics.false_positive_rate * 100.0
                ),
                implementation: "Review and tune WAF rules to reduce false positives. Consider allowlisting legitimate patterns and adjusting sensitivity thresholds. High false positive rates can impact legitimate users."
                    .to_string(),
            });
        } else if report.statistics.false_positive_rate > 0.0
            && report.statistics.benign_tests_count > 0
        {
            report.add_recommendation(Recommendation {
                priority: "MEDIUM".to_string(),
                category: "False Positives".to_string(),
                description: format!(
                    "Some benign requests were blocked ({:.1}% false positive rate)",
                    report.statistics.false_positive_rate * 100.0
                ),
                implementation: "Monitor for false positives in production traffic and consider fine-tuning rules for specific edge cases."
                    .to_string(),
            });
        }
    }

    /// Log test completion for audit trail
    fn log_test_completion(&self, report: &EffectivenessReport) -> Result<()> {
        // Append-only audit persistence is handled by the caller. This remains
        // as a normal tracing event for local observability.
        info!(
            "WAF effectiveness test completed. Target: {}, Vulnerabilities found: {}, Duration: {:?}",
            report.target_url,
            report.vulnerabilities.len(),
            self.start_time.elapsed()
        );

        Ok(())
    }

    fn build_baseline_signature(baseline_results: &[TestResult]) -> Option<BaselineSignature> {
        if baseline_results.is_empty() {
            return None;
        }

        let mut status_counts: HashMap<u16, usize> = HashMap::new();
        for result in baseline_results {
            *status_counts.entry(result.status_code).or_insert(0) += 1;
        }

        let mut most_common_status = baseline_results[0].status_code;
        let mut best_count = 0;
        for (status, count) in status_counts {
            if count > best_count {
                most_common_status = status;
                best_count = count;
            }
        }

        baseline_results
            .iter()
            .filter(|r| r.status_code == most_common_status)
            .max_by_key(|r| r.response_body_length)
            .map(|r| BaselineSignature {
                status_code: r.status_code,
                body_sample: r.response_body_sample.clone(),
                body_length: r.response_body_length,
                headers: r.response_headers.clone(),
            })
    }

    fn match_block_template(
        body_lower: &str,
        baseline: Option<&BaselineSignature>,
    ) -> Option<&'static str> {
        let baseline_body = baseline
            .map(|b| b.body_sample.to_lowercase())
            .unwrap_or_default();

        for template in BLOCK_TEMPLATES {
            let is_match = template
                .markers
                .iter()
                .all(|marker| body_lower.contains(marker));

            if is_match && !baseline_body.contains(template.markers[0]) {
                return Some(template.vendor);
            }
        }

        None
    }
}

/// Result of a single test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub blocked: bool,
    pub status_code: u16,
    pub evidence: String,
    pub response_time: Duration,
    pub response_body_sample: String,
    pub response_body_length: usize,
    pub response_headers: HashMap<String, String>,
}

#[async_trait::async_trait]
impl ParserDiscrepancyExecutor for EffectivenessTest {
    async fn execute_replay(
        &mut self,
        request: &crate::effectiveness::report::ReplayRequest,
    ) -> Result<TestResult> {
        self.execute_replay_request(request).await
    }
}
