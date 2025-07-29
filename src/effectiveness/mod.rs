//! WAF Effectiveness Testing Module
//!
//! This module provides functionality to test the effectiveness of Web Application Firewalls
//! in a responsible and ethical manner. It is designed for security professionals to validate
//! their own defensive systems.
//!
//! ⚠️ WARNING: Only use this module against systems you own or have explicit permission to test.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{info, warn};

pub mod consent;
pub mod patterns;
pub mod report;
pub mod techniques;

use consent::ConsentManager;
use report::{EffectivenessReport, Recommendation, Vulnerability};
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
        }
    }
}

/// Main WAF effectiveness testing engine
pub struct EffectivenessTest {
    config: EffectivenessConfig,
    consent_manager: ConsentManager,
    start_time: Instant,
    request_count: u32,
}

impl EffectivenessTest {
    /// Create a new effectiveness test instance
    pub async fn new(config: EffectivenessConfig) -> Result<Self> {
        // Ensure user has acknowledged responsible use
        let consent_manager = ConsentManager::new();
        if !consent_manager.has_valid_consent()? {
            return Err(anyhow!(
                "User must acknowledge responsible use before using effectiveness testing features"
            ));
        }

        Ok(Self {
            config,
            consent_manager,
            start_time: Instant::now(),
            request_count: 0,
        })
    }

    /// Test WAF effectiveness against a target URL
    pub async fn test_effectiveness(&mut self, url: &str) -> Result<EffectivenessReport> {
        info!("Starting WAF effectiveness test for: {}", url);

        // Validate URL and permissions
        self.validate_target(url)?;

        let mut report = EffectivenessReport::new(url);

        // Phase 1: Baseline testing (benign requests)
        report.add_phase("Baseline Testing".to_string());
        self.test_baseline(url, &mut report).await?;

        // Phase 2: Detection testing (with various techniques)
        report.add_phase("Detection Testing".to_string());
        self.test_detection_capabilities(url, &mut report).await?;

        // Phase 3: Evasion testing (if intensity level allows)
        if self.config.intensity_level >= 4 {
            report.add_phase("Advanced Evasion Testing".to_string());
            self.test_evasion_techniques(url, &mut report).await?;
        }

        // Generate recommendations based on findings
        self.generate_recommendations(&mut report);

        // Log completion
        if self.config.audit_logging {
            self.log_test_completion(&report)?;
        }

        Ok(report)
    }

    /// Validate that we have permission to test this target
    fn validate_target(&self, url: &str) -> Result<()> {
        // Check if URL is in the allowed targets list
        if !self.consent_manager.is_target_allowed(url)? {
            return Err(anyhow!(
                "Target URL is not in the list of authorized targets. \
                Please add it to the authorized targets list first."
            ));
        }

        Ok(())
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

        for (test_name, method, body) in baseline_tests {
            self.rate_limit().await?;

            // Perform test and record results
            let result = self
                .perform_request(url, method, body, HashMap::new())
                .await?;
            report.add_baseline_result(test_name, result);
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
        _url: &str,
        _method: &str,
        _body: &str,
        _headers: HashMap<String, String>,
    ) -> Result<TestResult> {
        // This is a placeholder - in real implementation, this would use the HTTP client
        // For now, we'll return a mock result

        self.request_count += 1;

        // Add request delay for stealth
        sleep(self.config.request_delay).await;

        // Mock implementation
        Ok(TestResult {
            blocked: false,
            status_code: 200,
            evidence: "Mock response".to_string(),
            response_time: Duration::from_millis(100),
        })
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

        if report.vulnerabilities.len() > 5 {
            report.add_recommendation(Recommendation {
                priority: "CRITICAL".to_string(),
                category: "Configuration".to_string(),
                description: "WAF appears to be in detection-only mode or misconfigured".to_string(),
                implementation: "Review WAF mode settings and ensure blocking is enabled for high-confidence attacks".to_string(),
            });
        }
    }

    /// Log test completion for audit trail
    fn log_test_completion(&self, report: &EffectivenessReport) -> Result<()> {
        // In a real implementation, this would write to a secure audit log
        info!(
            "WAF effectiveness test completed. Target: {}, Vulnerabilities found: {}, Duration: {:?}",
            report.target_url,
            report.vulnerabilities.len(),
            self.start_time.elapsed()
        );

        Ok(())
    }
}

/// Result of a single test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub blocked: bool,
    pub status_code: u16,
    pub evidence: String,
    pub response_time: Duration,
}
