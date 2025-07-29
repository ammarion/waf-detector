//! WAF Effectiveness Testing Report Generation
//!
//! This module handles the generation of comprehensive reports from effectiveness testing.

use crate::effectiveness::TestResult;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Comprehensive report of WAF effectiveness testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivenessReport {
    /// Target URL tested
    pub target_url: String,
    /// When the test was performed
    pub timestamp: DateTime<Utc>,
    /// Overall risk score (0-100)
    pub risk_score: f64,
    /// Test phases performed
    pub phases: Vec<TestPhase>,
    /// Vulnerabilities found
    pub vulnerabilities: Vec<Vulnerability>,
    /// Recommendations for improvement
    pub recommendations: Vec<Recommendation>,
    /// Individual test results
    pub test_results: HashMap<String, TestResult>,
    /// Baseline behavior results
    pub baseline_results: HashMap<String, TestResult>,
    /// Summary statistics
    pub statistics: TestStatistics,
}

/// A phase of testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestPhase {
    pub name: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Identified vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

/// Recommendation for improvement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: String,
    pub category: String,
    pub description: String,
    pub implementation: String,
}

/// Test statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestStatistics {
    pub total_tests: usize,
    pub blocked_requests: usize,
    pub allowed_requests: usize,
    pub error_responses: usize,
    pub average_response_time_ms: f64,
}

impl EffectivenessReport {
    /// Create a new report
    pub fn new(target_url: &str) -> Self {
        Self {
            target_url: target_url.to_string(),
            timestamp: Utc::now(),
            risk_score: 0.0,
            phases: Vec::new(),
            vulnerabilities: Vec::new(),
            recommendations: Vec::new(),
            test_results: HashMap::new(),
            baseline_results: HashMap::new(),
            statistics: TestStatistics {
                total_tests: 0,
                blocked_requests: 0,
                allowed_requests: 0,
                error_responses: 0,
                average_response_time_ms: 0.0,
            },
        }
    }

    /// Add a test phase
    pub fn add_phase(&mut self, name: String) {
        // Complete previous phase if exists
        if let Some(last_phase) = self.phases.last_mut() {
            if last_phase.completed_at.is_none() {
                last_phase.completed_at = Some(Utc::now());
            }
        }

        self.phases.push(TestPhase {
            name,
            started_at: Utc::now(),
            completed_at: None,
        });
    }

    /// Add a vulnerability
    pub fn add_vulnerability(&mut self, vulnerability: Vulnerability) {
        self.vulnerabilities.push(vulnerability);
        self.recalculate_risk_score();
    }

    /// Add a recommendation
    pub fn add_recommendation(&mut self, recommendation: Recommendation) {
        self.recommendations.push(recommendation);
    }

    /// Add a test result
    pub fn add_test_result(&mut self, name: String, result: TestResult) {
        self.statistics.total_tests += 1;

        if result.blocked {
            self.statistics.blocked_requests += 1;
        } else {
            self.statistics.allowed_requests += 1;
        }

        if result.status_code >= 500 {
            self.statistics.error_responses += 1;
        }

        self.test_results.insert(name, result);
        self.update_statistics();
    }

    /// Add a baseline result
    pub fn add_baseline_result(&mut self, name: &str, result: TestResult) {
        self.baseline_results.insert(name.to_string(), result);
    }

    /// Recalculate risk score based on vulnerabilities
    fn recalculate_risk_score(&mut self) {
        let mut score: f64 = 0.0;

        for vuln in &self.vulnerabilities {
            match vuln.severity.as_str() {
                "CRITICAL" => score += 25.0,
                "HIGH" => score += 15.0,
                "MEDIUM" => score += 8.0,
                "LOW" => score += 3.0,
                _ => {}
            }
        }

        // Cap at 100
        self.risk_score = score.min(100.0);
    }

    /// Update statistics
    fn update_statistics(&mut self) {
        if self.test_results.is_empty() {
            return;
        }

        let total_time: f64 = self
            .test_results
            .values()
            .map(|r| r.response_time.as_millis() as f64)
            .sum();

        self.statistics.average_response_time_ms = total_time / self.test_results.len() as f64;
    }

    /// Generate a human-readable summary
    pub fn generate_summary(&self) -> String {
        let mut summary = String::new();

        summary.push_str("# WAF Effectiveness Report\n\n");
        summary.push_str(&format!("**Target:** {}\n", self.target_url));
        summary.push_str(&format!(
            "**Date:** {}\n",
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        summary.push_str(&format!("**Risk Score:** {:.1}/100\n\n", self.risk_score));

        // Statistics
        summary.push_str("## Statistics\n");
        summary.push_str(&format!("- Total Tests: {}\n", self.statistics.total_tests));
        summary.push_str(&format!(
            "- Blocked: {} ({:.1}%)\n",
            self.statistics.blocked_requests,
            (self.statistics.blocked_requests as f64 / self.statistics.total_tests as f64) * 100.0
        ));
        summary.push_str(&format!(
            "- Allowed: {} ({:.1}%)\n",
            self.statistics.allowed_requests,
            (self.statistics.allowed_requests as f64 / self.statistics.total_tests as f64) * 100.0
        ));
        summary.push_str(&format!(
            "- Avg Response Time: {:.0}ms\n\n",
            self.statistics.average_response_time_ms
        ));

        // Vulnerabilities
        if !self.vulnerabilities.is_empty() {
            summary.push_str("## Vulnerabilities Found\n");
            for vuln in &self.vulnerabilities {
                summary.push_str(&format!("### {} - {}\n", vuln.severity, vuln.category));
                summary.push_str(&format!("{}\n", vuln.description));
                summary.push_str(&format!("**Remediation:** {}\n\n", vuln.remediation));
            }
        } else {
            summary.push_str("## No Vulnerabilities Found ✅\n\n");
        }

        // Recommendations
        if !self.recommendations.is_empty() {
            summary.push_str("## Recommendations\n");
            for rec in &self.recommendations {
                summary.push_str(&format!("### [{}] {}\n", rec.priority, rec.description));
                summary.push_str(&format!("{}\n\n", rec.implementation));
            }
        }

        summary
    }

    /// Export report as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export report as HTML
    pub fn to_html(&self) -> String {
        let mut html = String::new();

        html.push_str(r#"<!DOCTYPE html>
<html>
<head>
    <title>WAF Effectiveness Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        h2 { color: #666; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .stat { display: inline-block; margin: 10px 20px 10px 0; }
        .stat-value { font-size: 24px; font-weight: bold; color: #1a73e8; }
        .vulnerability { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .severity-critical { border-left: 4px solid #dc3545; }
        .severity-high { border-left: 4px solid #fd7e14; }
        .severity-medium { border-left: 4px solid #ffc107; }
        .severity-low { border-left: 4px solid #28a745; }
        .recommendation { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .risk-score { font-size: 48px; font-weight: bold; }
        .risk-low { color: #28a745; }
        .risk-medium { color: #ffc107; }
        .risk-high { color: #fd7e14; }
        .risk-critical { color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
"#);

        // Header
        html.push_str("<h1>WAF Effectiveness Report</h1>");
        html.push_str(&format!(
            "<p><strong>Target:</strong> {}</p>",
            self.target_url
        ));
        html.push_str(&format!(
            "<p><strong>Date:</strong> {}</p>",
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Risk Score
        let risk_class = match self.risk_score {
            s if s >= 75.0 => "risk-critical",
            s if s >= 50.0 => "risk-high",
            s if s >= 25.0 => "risk-medium",
            _ => "risk-low",
        };
        html.push_str(&format!(
            r#"<p>Risk Score: <span class="risk-score {}">{:.1}</span>/100</p>"#,
            risk_class, self.risk_score
        ));

        // Statistics
        html.push_str("<h2>Statistics</h2>");
        html.push_str("<div>");
        html.push_str(&format!(
            r#"<div class="stat">Total Tests: <span class="stat-value">{}</span></div>"#,
            self.statistics.total_tests
        ));
        html.push_str(&format!(
            r#"<div class="stat">Blocked: <span class="stat-value">{}</span></div>"#,
            self.statistics.blocked_requests
        ));
        html.push_str(&format!(
            r#"<div class="stat">Allowed: <span class="stat-value">{}</span></div>"#,
            self.statistics.allowed_requests
        ));
        html.push_str("</div>");

        // Vulnerabilities
        if !self.vulnerabilities.is_empty() {
            html.push_str("<h2>Vulnerabilities</h2>");
            for vuln in &self.vulnerabilities {
                let severity_class = format!("severity-{}", vuln.severity.to_lowercase());
                html.push_str(&format!(r#"<div class="vulnerability {severity_class}">"#));
                html.push_str(&format!("<h3>{} - {}</h3>", vuln.severity, vuln.category));
                html.push_str(&format!("<p>{}</p>", vuln.description));
                html.push_str(&format!(
                    "<p><strong>Remediation:</strong> {}</p>",
                    vuln.remediation
                ));
                html.push_str("</div>");
            }
        }

        // Recommendations
        if !self.recommendations.is_empty() {
            html.push_str("<h2>Recommendations</h2>");
            for rec in &self.recommendations {
                html.push_str(r#"<div class="recommendation">"#);
                html.push_str(&format!("<h3>[{}] {}</h3>", rec.priority, rec.description));
                html.push_str(&format!("<p>{}</p>", rec.implementation));
                html.push_str("</div>");
            }
        }

        html.push_str("</div></body></html>");
        html
    }
}
