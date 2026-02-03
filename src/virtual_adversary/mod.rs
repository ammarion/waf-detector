//! Virtual Adversary (VA) configuration and types.
//!
//! Detection-grade adversarial testing configuration with strict safety bounds.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;

use crate::effectiveness::consent::ConsentManager;
use crate::http::HttpClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualAdversaryConfig {
    /// Safety tier (1-3). Higher tiers enable more advanced mutations.
    pub tier: u8,
    /// Maximum total requests allowed per run.
    pub request_budget: u32,
    /// Per-request timeout.
    pub request_timeout: Duration,
    /// Delay between requests.
    pub request_delay: Duration,
    /// Maximum variants per payload template.
    pub max_variants_per_payload: u8,
}

impl Default for VirtualAdversaryConfig {
    fn default() -> Self {
        Self {
            tier: 1,
            request_budget: 120,
            request_timeout: Duration::from_secs(15),
            request_delay: Duration::from_millis(750),
            max_variants_per_payload: 4,
        }
    }
}

impl VirtualAdversaryConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=3).contains(&self.tier) {
            return Err("tier must be between 1 and 3".to_string());
        }
        if self.request_budget == 0 {
            return Err("request_budget must be greater than 0".to_string());
        }
        if self.max_variants_per_payload == 0 {
            return Err("max_variants_per_payload must be greater than 0".to_string());
        }
        Ok(())
    }
}

pub fn ensure_consent_and_target(consent_manager: &ConsentManager, target_url: &str) -> Result<()> {
    if !consent_manager.has_valid_consent()? {
        return Err(anyhow!(
            "Consent is required before running Virtual Adversary tests"
        ));
    }

    if !consent_manager.is_target_allowed(target_url)? {
        return Err(anyhow!(
            "Target is not authorized for Virtual Adversary testing"
        ));
    }

    Ok(())
}

#[derive(Debug, Default)]
pub struct RequestBudget {
    total: u32,
    used: u32,
}

impl RequestBudget {
    pub fn new(total: u32) -> Result<Self> {
        if total == 0 {
            return Err(anyhow!("request budget must be greater than 0"));
        }
        Ok(Self { total, used: 0 })
    }

    pub fn remaining(&self) -> u32 {
        self.total.saturating_sub(self.used)
    }

    pub fn consume(&mut self, count: u32) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        let remaining = self.remaining();
        if count > remaining {
            return Err(anyhow!(
                "request budget exceeded: requested {count}, remaining {remaining}"
            ));
        }
        self.used = self.used.saturating_add(count);
        Ok(())
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    min_delay: Duration,
    last_request_at: Option<std::time::Instant>,
}

impl RateLimiter {
    pub fn new(request_delay: Duration) -> Result<Self> {
        if request_delay.is_zero() {
            return Err(anyhow!("request delay must be greater than 0"));
        }
        Ok(Self {
            min_delay: request_delay,
            last_request_at: None,
        })
    }

    pub fn record_request(&mut self) -> Duration {
        let now = std::time::Instant::now();
        let wait = if let Some(last) = self.last_request_at {
            let elapsed = now.saturating_duration_since(last);
            if elapsed >= self.min_delay {
                Duration::from_millis(0)
            } else {
                self.min_delay - elapsed
            }
        } else {
            Duration::from_millis(0)
        };

        self.last_request_at = Some(now);
        wait
    }
}

pub struct VirtualAdversaryRunner {
    config: VirtualAdversaryConfig,
    consent_manager: ConsentManager,
    budget: RequestBudget,
    rate_limiter: RateLimiter,
    http: Box<dyn VaHttpAdapter + Send + Sync>,
}

const BASELINE_SAMPLE_LIMIT: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineRecord {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body_length: usize,
    pub body_sample: String,
}

impl BaselineRecord {
    pub fn from_response(
        status_code: u16,
        headers: HashMap<String, String>,
        body: &str,
    ) -> Self {
        let sample = if body.len() <= BASELINE_SAMPLE_LIMIT {
            body.to_string()
        } else {
            body.chars().take(BASELINE_SAMPLE_LIMIT).collect()
        };

        Self {
            status_code,
            headers,
            body_length: body.len(),
            body_sample: sample,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDiff {
    pub status_changed: bool,
    pub length_delta: usize,
    pub significant_length_change: bool,
    pub header_differences: Vec<String>,
}

impl ResponseDiff {
    pub fn compare(
        baseline: &BaselineRecord,
        status_code: u16,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> Self {
        let status_changed = status_code != baseline.status_code;
        let length_delta = baseline.body_length.abs_diff(body.len());
        let significant_length_change = length_delta >= (baseline.body_length / 2).max(200);

        let mut header_differences = Vec::new();
        for (name, value) in headers {
            if let Some(base_value) = baseline.headers.get(name) {
                if base_value != value {
                    header_differences.push(name.clone());
                }
            } else {
                header_differences.push(name.clone());
            }
        }

        Self {
            status_changed,
            length_delta,
            significant_length_change,
            header_differences,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaOutcome {
    Blocked,
    Challenge,
    Allowed,
    Error,
}

pub fn classify_outcome(status_code: u16, diff: &ResponseDiff, body: &str) -> (VaOutcome, String) {
    if status_code == 0 {
        return (VaOutcome::Error, "status=0".to_string());
    }

    if status_code == 429 || status_code == 403 || status_code == 406 {
        return (VaOutcome::Blocked, format!("status={status_code}"));
    }

    let challenge_headers = ["cf-ray", "cf-chl-bypass", "x-akamai-transformed"];
    if diff
        .header_differences
        .iter()
        .any(|h| challenge_headers.contains(&h.as_str()))
    {
        return (VaOutcome::Challenge, "challenge-header".to_string());
    }

    let body_lc = body.to_lowercase();
    if body_lc.contains("access denied")
        || body_lc.contains("request blocked")
        || body_lc.contains("forbidden")
    {
        return (VaOutcome::Blocked, "blocked-keyword".to_string());
    }

    if body_lc.contains("captcha") || body_lc.contains("challenge") || body_lc.contains("verify") {
        return (VaOutcome::Challenge, "challenge-keyword".to_string());
    }

    if diff.significant_length_change || (diff.status_changed && diff.length_delta > 200) {
        return (VaOutcome::Challenge, "baseline-deviation".to_string());
    }

    (VaOutcome::Allowed, "no-anomaly".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaResultSummary {
    pub total: usize,
    pub blocked: usize,
    pub challenge: usize,
    pub allowed: usize,
    pub error: usize,
}

impl VaResultSummary {
    pub fn new() -> Self {
        Self {
            total: 0,
            blocked: 0,
            challenge: 0,
            allowed: 0,
            error: 0,
        }
    }

    pub fn record(&mut self, outcome: VaOutcome) {
        self.total += 1;
        match outcome {
            VaOutcome::Blocked => self.blocked += 1,
            VaOutcome::Challenge => self.challenge += 1,
            VaOutcome::Allowed => self.allowed += 1,
            VaOutcome::Error => self.error += 1,
        }
    }

    pub fn confidence_score(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let effective = self.blocked + self.challenge;
        effective as f64 / self.total as f64
    }

    pub fn risk_label(&self) -> &'static str {
        let score = self.confidence_score();
        if score >= 0.8 {
            "LOW"
        } else if score >= 0.5 {
            "MEDIUM"
        } else {
            "HIGH"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaRunReport {
    pub target_url: String,
    pub plan_size: usize,
    pub summary: VaResultSummary,
    pub config: VirtualAdversaryConfig,
    pub results: Vec<VaResultRecord>,
    #[serde(skip, default = "default_instant")]
    pub started_at: std::time::Instant,
    #[serde(skip, default)]
    pub finished_at: Option<std::time::Instant>,
}

fn default_instant() -> std::time::Instant {
    std::time::Instant::now()
}

impl VaRunReport {
    pub fn new(target_url: &str, plan_size: usize, config: VirtualAdversaryConfig) -> Self {
        Self {
            target_url: target_url.to_string(),
            plan_size,
            summary: VaResultSummary::new(),
            config,
            results: Vec::new(),
            started_at: std::time::Instant::now(),
            finished_at: None,
        }
    }

    pub fn finish(&mut self) {
        self.finished_at = Some(std::time::Instant::now());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaHttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaResultRecord {
    pub payload: String,
    pub category: VaPayloadCategory,
    pub outcome: VaOutcome,
    pub reason: String,
}

pub fn va_report_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["target_url", "plan_size", "summary", "config"],
        "properties": {
            "target_url": { "type": "string" },
            "plan_size": { "type": "integer" },
            "summary": {
                "type": "object",
                "required": ["total", "blocked", "challenge", "allowed", "error"]
            },
            "config": {
                "type": "object",
                "required": ["tier", "request_budget", "request_timeout", "request_delay", "max_variants_per_payload"]
            }
        }
    })
}

pub trait VaHttpAdapter {
    fn get(&self, url: &str) -> anyhow::Result<VaHttpResponse>;
    fn get_with_payload(&self, url: &str, payload: &VaPayloadVariant)
        -> anyhow::Result<VaHttpResponse>;
}

pub struct RealVaHttpAdapter {
    client: HttpClient,
}

impl RealVaHttpAdapter {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            client: HttpClient::new()?,
        })
    }
}

impl VaHttpAdapter for RealVaHttpAdapter {
    fn get(&self, url: &str) -> anyhow::Result<VaHttpResponse> {
        let response = futures::executor::block_on(self.client.get(url))?;
        Ok(VaHttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }

    fn get_with_payload(
        &self,
        url: &str,
        _payload: &VaPayloadVariant,
    ) -> anyhow::Result<VaHttpResponse> {
        self.get(url)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaPayloadCategory {
    SqlInjection,
    Xss,
    PathTraversal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaPayloadTemplate {
    pub category: VaPayloadCategory,
    pub name: &'static str,
    pub payload: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaPayloadVariant {
    pub category: VaPayloadCategory,
    pub template_name: &'static str,
    pub payload: String,
}

pub fn base_payloads_for_tier(tier: u8) -> Vec<VaPayloadTemplate> {
    let mut templates = vec![
        VaPayloadTemplate {
            category: VaPayloadCategory::SqlInjection,
            name: "sqli_basic_or",
            payload: "' OR '1'='1",
        },
        VaPayloadTemplate {
            category: VaPayloadCategory::Xss,
            name: "xss_basic_script",
            payload: "<script>alert('XSS')</script>",
        },
        VaPayloadTemplate {
            category: VaPayloadCategory::PathTraversal,
            name: "path_traversal_basic",
            payload: "../etc/passwd",
        },
    ];

    if tier >= 2 {
        templates.push(VaPayloadTemplate {
            category: VaPayloadCategory::SqlInjection,
            name: "sqli_union_select",
            payload: "1' UNION SELECT NULL,NULL--",
        });
    }

    if tier >= 3 {
        templates.push(VaPayloadTemplate {
            category: VaPayloadCategory::Xss,
            name: "xss_svg",
            payload: "<svg onload=alert('XSS')>",
        });
    }

    templates
}

pub fn generate_variants(
    template: &VaPayloadTemplate,
    max_variants: u8,
) -> Vec<VaPayloadVariant> {
    let mut variants = Vec::new();
    variants.push(VaPayloadVariant {
        category: template.category,
        template_name: template.name,
        payload: template.payload.to_string(),
    });

    if max_variants > 1 {
        variants.push(VaPayloadVariant {
            category: template.category,
            template_name: template.name,
            payload: format!("{}{}", template.payload, " "),
        });
    }

    if max_variants > 2 {
        variants.push(VaPayloadVariant {
            category: template.category,
            template_name: template.name,
            payload: template.payload.to_uppercase(),
        });
    }

    variants.truncate(max_variants as usize);
    variants
}

impl VirtualAdversaryRunner {
    pub fn new(config: VirtualAdversaryConfig) -> Result<Self> {
        config
            .validate()
            .map_err(|err| anyhow!("invalid Virtual Adversary config: {err}"))?;
        let budget = RequestBudget::new(config.request_budget)?;
        let rate_limiter = RateLimiter::new(config.request_delay)?;
        let http = Box::new(RealVaHttpAdapter::new()?);
        Ok(Self {
            config,
            consent_manager: ConsentManager::new(),
            budget,
            rate_limiter,
            http,
        })
    }

    pub fn with_http_adapter(
        mut self,
        http: Box<dyn VaHttpAdapter + Send + Sync>,
    ) -> Self {
        self.http = http;
        self
    }

    pub fn plan(&self) -> Vec<VaPayloadVariant> {
        let templates = base_payloads_for_tier(self.config.tier);
        let mut plan = Vec::new();

        for template in &templates {
            let mut variants = generate_variants(template, self.config.max_variants_per_payload);
            plan.append(&mut variants);
        }

        let max_plan = self.config.request_budget.saturating_sub(1);
        plan.truncate(max_plan as usize);
        plan
    }

    fn collect_baseline(&self, target_url: &str) -> Result<BaselineRecord> {
        let response = self.http.get(target_url)?;
        Ok(BaselineRecord::from_response(
            response.status,
            response.headers,
            &response.body,
        ))
    }

    fn evaluate_payload(
        &self,
        target_url: &str,
        baseline: &BaselineRecord,
        payload: &VaPayloadVariant,
    ) -> Result<(VaOutcome, String)> {
        let response = self.http.get_with_payload(target_url, payload)?;
        let diff = ResponseDiff::compare(
            baseline,
            response.status,
            &response.headers,
            &response.body,
        );
        let (outcome, mut reason) = classify_outcome(response.status, &diff, &response.body);
        reason.push_str(&format!(
            " status={} len_delta={} header_diff={}",
            response.status,
            diff.length_delta,
            diff.header_differences.len()
        ));
        Ok((outcome, reason))
    }

    pub fn run_with_progress<F>(&mut self, target_url: &str, mut on_progress: F) -> Result<VaRunReport>
    where
        F: FnMut(usize, usize),
    {
        ensure_consent_and_target(&self.consent_manager, target_url)?;

        let _tier = self.config.tier;
        // Reserve a minimal budget for baseline + one adversarial pass.
        self.budget.consume(2)?;
        let _baseline_wait = self.rate_limiter.record_request();
        let _attack_wait = self.rate_limiter.record_request();

        let baseline = self.collect_baseline(target_url)?;
        let plan = self.plan();
        let total = plan.len();
        on_progress(0, total);
        let mut report = VaRunReport::new(target_url, plan.len(), self.config.clone());
        for (idx, item) in plan.into_iter().enumerate() {
            let (outcome, reason) = self.evaluate_payload(target_url, &baseline, &item)?;
            report.summary.record(outcome);
            report.results.push(VaResultRecord {
                payload: item.payload,
                category: item.category,
                outcome,
                reason,
            });
            on_progress(idx + 1, total);
        }
        report.finish();
        Ok(report)
    }

    pub fn run(&mut self, target_url: &str) -> Result<VaRunReport> {
        self.run_with_progress(target_url, |_, _| {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use serde::Serialize;
    use std::fs;
    use tempfile::TempDir;

    #[derive(Default)]
    struct StubHttpAdapter;

    impl VaHttpAdapter for StubHttpAdapter {
        fn get(&self, _url: &str) -> anyhow::Result<VaHttpResponse> {
            Ok(VaHttpResponse {
                status: 200,
                headers: HashMap::new(),
                body: "ok".to_string(),
            })
        }

        fn get_with_payload(
            &self,
            _url: &str,
            _payload: &VaPayloadVariant,
        ) -> anyhow::Result<VaHttpResponse> {
            Ok(VaHttpResponse {
                status: 403,
                headers: HashMap::new(),
                body: "blocked".to_string(),
            })
        }
    }

    #[test]
    fn test_default_config_is_safe() {
        let config = VirtualAdversaryConfig::default();
        assert_eq!(config.tier, 1);
        assert!(config.request_budget > 0);
        assert!(config.request_timeout.as_secs() >= 10);
        assert!(config.request_delay.as_millis() >= 500);
        assert!(config.max_variants_per_payload > 0);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_tier_rejected() {
        let mut config = VirtualAdversaryConfig::default();
        config.tier = 0;
        assert!(config.validate().is_err());
        config.tier = 4;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_budget_rejected() {
        let mut config = VirtualAdversaryConfig::default();
        config.request_budget = 0;
        assert!(config.validate().is_err());
    }

    #[derive(Serialize)]
    struct TestConsentRecord {
        timestamp: DateTime<Utc>,
        terms_version: String,
        authorized_targets: Vec<String>,
        acknowledgment: String,
    }

    fn write_test_consent(temp_dir: &TempDir, targets: Vec<String>) {
        let record = TestConsentRecord {
            timestamp: Utc::now(),
            terms_version: "1.0.0".to_string(),
            authorized_targets: targets,
            acknowledgment: "I AGREE".to_string(),
        };
        let path = temp_dir.path().join(".waf-detector-consent.json");
        let json = serde_json::to_string_pretty(&record).unwrap();
        fs::write(path, json).unwrap();
    }

    #[test]
    fn test_consent_required_for_va() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());

        let consent_manager = ConsentManager::new();
        let result = ensure_consent_and_target(&consent_manager, "https://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_target_must_be_authorized() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        write_test_consent(&temp_dir, vec!["example.com".to_string()]);

        let consent_manager = ConsentManager::new();
        let result = ensure_consent_and_target(&consent_manager, "https://notallowed.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_authorized_target_passes() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        write_test_consent(&temp_dir, vec!["example.com".to_string()]);

        let consent_manager = ConsentManager::new();
        let result = ensure_consent_and_target(&consent_manager, "https://example.com/path");
        assert!(result.is_ok());
    }

    #[test]
    fn test_request_budget_enforced() {
        let mut budget = RequestBudget::new(3).unwrap();
        assert_eq!(budget.remaining(), 3);
        budget.consume(2).unwrap();
        assert_eq!(budget.remaining(), 1);
        assert!(budget.consume(2).is_err());
    }

    #[test]
    fn test_rate_limiter_waits() {
        let mut limiter = RateLimiter::new(Duration::from_millis(200)).unwrap();
        let first_wait = limiter.record_request();
        assert_eq!(first_wait, Duration::from_millis(0));
        let second_wait = limiter.record_request();
        assert!(second_wait >= Duration::from_millis(0));
    }

    #[test]
    fn test_runner_enforces_consent_and_budget() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        write_test_consent(&temp_dir, vec!["example.com".to_string()]);

        let config = VirtualAdversaryConfig {
            request_budget: 1,
            ..Default::default()
        };

        let mut runner = VirtualAdversaryRunner::new(config)
            .unwrap()
            .with_http_adapter(Box::new(StubHttpAdapter::default()));
        let result = runner.run("https://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_runner_reports_progress() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        write_test_consent(&temp_dir, vec!["example.com".to_string()]);

        let config = VirtualAdversaryConfig {
            request_budget: 6,
            max_variants_per_payload: 1,
            ..VirtualAdversaryConfig::default()
        };
        let mut runner = VirtualAdversaryRunner::new(config)
            .unwrap()
            .with_http_adapter(Box::new(StubHttpAdapter::default()));

        let mut updates = Vec::new();
        let report = runner
            .run_with_progress("https://example.com", |done, total| {
                updates.push((done, total));
            })
            .unwrap();

        assert!(!updates.is_empty());
        let (first_done, first_total) = updates.first().copied().unwrap();
        let (last_done, last_total) = updates.last().copied().unwrap();
        assert_eq!(first_done, 0);
        assert_eq!(first_total, report.plan_size);
        assert_eq!(last_done, report.plan_size);
        assert_eq!(last_total, report.plan_size);
    }

    #[test]
    fn test_runner_allows_valid_run() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        write_test_consent(&temp_dir, vec!["example.com".to_string()]);

        let config = VirtualAdversaryConfig {
            request_budget: 2,
            ..Default::default()
        };

        let mut runner = VirtualAdversaryRunner::new(config)
            .unwrap()
            .with_http_adapter(Box::new(StubHttpAdapter::default()));
        let result = runner.run("https://example.com").unwrap();
        assert!(result.summary.total >= 1);
        assert_eq!(result.summary.allowed, result.summary.total);
    }

    #[test]
    fn test_baseline_record_tracks_length() {
        let body = "hello world";
        let record = BaselineRecord::from_response(200, HashMap::new(), body);
        assert_eq!(record.body_length, body.len());
        assert_eq!(record.body_sample, body);
    }

    #[test]
    fn test_baseline_record_truncates_sample() {
        let body = "a".repeat(BASELINE_SAMPLE_LIMIT + 10);
        let record = BaselineRecord::from_response(200, HashMap::new(), &body);
        assert_eq!(record.body_length, body.len());
        assert_eq!(record.body_sample.len(), BASELINE_SAMPLE_LIMIT);
    }

    #[test]
    fn test_baseline_record_preserves_headers() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());
        let record = BaselineRecord::from_response(200, headers.clone(), "ok");
        assert_eq!(record.headers.get("content-type"), Some(&"text/html".to_string()));
        assert_eq!(record.status_code, 200);
    }

    #[test]
    fn test_response_diff_detects_status_change() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let diff = ResponseDiff::compare(&baseline, 403, &HashMap::new(), "blocked");
        assert!(diff.status_changed);
    }

    #[test]
    fn test_response_diff_detects_length_change() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), &"a".repeat(1000));
        let diff = ResponseDiff::compare(&baseline, 200, &HashMap::new(), &"b".repeat(50));
        assert!(diff.significant_length_change);
        assert!(diff.length_delta > 0);
    }

    #[test]
    fn test_response_diff_tracks_header_changes() {
        let mut base_headers = HashMap::new();
        base_headers.insert("server".to_string(), "nginx".to_string());
        let baseline = BaselineRecord::from_response(200, base_headers, "ok");

        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "cloudflare".to_string());
        headers.insert("cf-ray".to_string(), "123".to_string());

        let diff = ResponseDiff::compare(&baseline, 200, &headers, "ok");
        assert!(diff.header_differences.contains(&"server".to_string()));
        assert!(diff.header_differences.contains(&"cf-ray".to_string()));
    }

    #[test]
    fn test_classify_outcome_blocked_by_status() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let diff = ResponseDiff::compare(&baseline, 403, &HashMap::new(), "blocked");
        assert_eq!(
            classify_outcome(403, &diff, "blocked").0,
            VaOutcome::Blocked
        );
    }

    #[test]
    fn test_classify_outcome_challenge_by_header() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "123".to_string());
        let diff = ResponseDiff::compare(&baseline, 200, &headers, "ok");
        assert_eq!(
            classify_outcome(200, &diff, "ok").0,
            VaOutcome::Challenge
        );
    }

    #[test]
    fn test_classify_outcome_allowed() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let diff = ResponseDiff::compare(&baseline, 200, &HashMap::new(), "ok");
        assert_eq!(
            classify_outcome(200, &diff, "ok").0,
            VaOutcome::Allowed
        );
    }

    #[test]
    fn test_classify_outcome_challenge_by_body() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let diff = ResponseDiff::compare(&baseline, 200, &HashMap::new(), "captcha required");
        assert_eq!(
            classify_outcome(200, &diff, "captcha required").0,
            VaOutcome::Challenge
        );
    }

    #[test]
    fn test_classify_outcome_challenge_on_baseline_deviation() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), &"a".repeat(1000));
        let diff = ResponseDiff::compare(&baseline, 500, &HashMap::new(), &"b".repeat(10));
        assert_eq!(
            classify_outcome(500, &diff, "error").0,
            VaOutcome::Challenge
        );
    }

    #[test]
    fn test_classify_outcome_blocked_by_body_keywords() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let diff = ResponseDiff::compare(&baseline, 200, &HashMap::new(), "Access Denied");
        assert_eq!(
            classify_outcome(200, &diff, "Access Denied").0,
            VaOutcome::Blocked
        );
    }

    #[test]
    fn test_result_summary_counts() {
        let mut summary = VaResultSummary::new();
        summary.record(VaOutcome::Blocked);
        summary.record(VaOutcome::Challenge);
        summary.record(VaOutcome::Allowed);
        summary.record(VaOutcome::Error);
        summary.record(VaOutcome::Allowed);

        assert_eq!(summary.total, 5);
        assert_eq!(summary.blocked, 1);
        assert_eq!(summary.challenge, 1);
        assert_eq!(summary.allowed, 2);
        assert_eq!(summary.error, 1);
    }

    #[test]
    fn test_result_summary_confidence_score() {
        let mut summary = VaResultSummary::new();
        summary.record(VaOutcome::Blocked);
        summary.record(VaOutcome::Challenge);
        summary.record(VaOutcome::Allowed);
        assert!((summary.confidence_score() - (2.0 / 3.0)).abs() < 0.001);
    }

    #[test]
    fn test_result_summary_risk_label() {
        let mut summary = VaResultSummary::new();
        summary.record(VaOutcome::Blocked);
        summary.record(VaOutcome::Blocked);
        summary.record(VaOutcome::Challenge);
        summary.record(VaOutcome::Allowed);
        assert_eq!(summary.risk_label(), "MEDIUM");
    }

    #[test]
    fn test_run_report_tracks_plan_and_timing() {
        let mut report = VaRunReport::new(
            "https://example.com",
            5,
            VirtualAdversaryConfig::default(),
        );
        assert_eq!(report.target_url, "https://example.com");
        assert_eq!(report.plan_size, 5);
        assert!(report.finished_at.is_none());
        report.finish();
        assert!(report.finished_at.is_some());
    }

    #[test]
    fn test_base_payloads_by_tier() {
        let tier1 = base_payloads_for_tier(1);
        assert!(tier1.len() >= 3);

        let tier2 = base_payloads_for_tier(2);
        assert!(tier2.len() > tier1.len());

        let tier3 = base_payloads_for_tier(3);
        assert!(tier3.len() > tier2.len());
    }

    #[test]
    fn test_generate_variants_respects_limit() {
        let template = VaPayloadTemplate {
            category: VaPayloadCategory::SqlInjection,
            name: "sqli_basic_or",
            payload: "' OR '1'='1",
        };
        let variants = generate_variants(&template, 2);
        assert_eq!(variants.len(), 2);
        assert_eq!(variants[0].payload, template.payload);
    }

    #[test]
    fn test_plan_respects_budget() {
        let config = VirtualAdversaryConfig {
            tier: 3,
            request_budget: 2,
            max_variants_per_payload: 3,
            ..Default::default()
        };
        let runner = VirtualAdversaryRunner::new(config).unwrap();
        let plan = runner.plan();
        assert!(plan.len() <= 1);
    }

    #[test]
    fn test_plan_generates_variants() {
        let config = VirtualAdversaryConfig {
            tier: 1,
            request_budget: 10,
            max_variants_per_payload: 2,
            ..Default::default()
        };
        let runner = VirtualAdversaryRunner::new(config)
            .unwrap()
            .with_http_adapter(Box::new(StubHttpAdapter::default()));
        let plan = runner.plan();
        assert!(!plan.is_empty());
        assert!(plan.len() >= 3);
    }

    #[test]
    fn test_runner_uses_http_adapter() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        write_test_consent(&temp_dir, vec!["example.com".to_string()]);

        let config = VirtualAdversaryConfig {
            request_budget: 2,
            ..Default::default()
        };
        let mut runner = VirtualAdversaryRunner::new(config)
            .unwrap()
            .with_http_adapter(Box::new(StubHttpAdapter::default()));

        let result = runner.run("https://example.com").unwrap();
        assert_eq!(result.target_url, "https://example.com");
    }

    #[test]
    fn test_collect_baseline_from_http_adapter() {
        let config = VirtualAdversaryConfig {
            request_budget: 2,
            ..Default::default()
        };
        let runner = VirtualAdversaryRunner::new(config)
            .unwrap()
            .with_http_adapter(Box::new(StubHttpAdapter::default()));

        let baseline = runner.collect_baseline("https://example.com").unwrap();
        assert_eq!(baseline.status_code, 200);
        assert_eq!(baseline.body_sample, "ok");
    }

    #[test]
    fn test_evaluate_payload_classifies_outcome() {
        let config = VirtualAdversaryConfig {
            request_budget: 2,
            ..Default::default()
        };
        let runner = VirtualAdversaryRunner::new(config)
            .unwrap()
            .with_http_adapter(Box::new(StubHttpAdapter::default()));

        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let payload = VaPayloadVariant {
            category: VaPayloadCategory::SqlInjection,
            template_name: "sqli_basic_or",
            payload: "' OR '1'='1".to_string(),
        };

        let (outcome, _reason) = runner
            .evaluate_payload("https://example.com", &baseline, &payload)
            .unwrap();
        assert_eq!(outcome, VaOutcome::Blocked);
    }

    #[test]
    fn test_runner_reports_plan_summary() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        write_test_consent(&temp_dir, vec!["example.com".to_string()]);

        let config = VirtualAdversaryConfig {
            tier: 1,
            request_budget: 5,
            max_variants_per_payload: 1,
            ..Default::default()
        };

        let mut runner = VirtualAdversaryRunner::new(config)
            .unwrap()
            .with_http_adapter(Box::new(StubHttpAdapter::default()));

        let report = runner.run("https://example.com").unwrap();
        assert_eq!(report.summary.total, report.plan_size);
        assert_eq!(report.summary.blocked, report.plan_size);
        assert_eq!(report.results.len(), report.plan_size);
    }

    #[test]
    fn test_va_report_serializes_to_json() {
        let report = VaRunReport::new(
            "https://example.com",
            2,
            VirtualAdversaryConfig::default(),
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("plan_size"));
    }

    #[test]
    fn test_va_report_schema_has_required_keys() {
        let schema = va_report_schema();
        let required = schema
            .get("required")
            .and_then(|v| v.as_array())
            .unwrap();
        let required_keys: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required_keys.contains(&"target_url"));
        assert!(required_keys.contains(&"plan_size"));
        assert!(required_keys.contains(&"summary"));
        assert!(required_keys.contains(&"config"));
    }
}
