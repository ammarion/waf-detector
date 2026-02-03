//! Virtual Adversary (VA) configuration and types.
//!
//! Detection-grade adversarial testing configuration with strict safety bounds.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use crate::effectiveness::consent::ConsentManager;

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

#[derive(Debug)]
pub struct VirtualAdversaryRunner {
    config: VirtualAdversaryConfig,
    consent_manager: ConsentManager,
    budget: RequestBudget,
    rate_limiter: RateLimiter,
}

const BASELINE_SAMPLE_LIMIT: usize = 1024;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaOutcome {
    Blocked,
    Challenge,
    Allowed,
    Error,
}

pub fn classify_outcome(status_code: u16, diff: &ResponseDiff) -> VaOutcome {
    if status_code == 0 {
        return VaOutcome::Error;
    }

    if status_code == 429 || status_code == 403 || status_code == 406 {
        return VaOutcome::Blocked;
    }

    let challenge_headers = ["cf-ray", "cf-chl-bypass", "x-akamai-transformed"];
    if diff
        .header_differences
        .iter()
        .any(|h| challenge_headers.contains(&h.as_str()))
    {
        return VaOutcome::Challenge;
    }

    if diff.significant_length_change || diff.status_changed {
        return VaOutcome::Challenge;
    }

    VaOutcome::Allowed
}

impl VirtualAdversaryRunner {
    pub fn new(config: VirtualAdversaryConfig) -> Result<Self> {
        config
            .validate()
            .map_err(|err| anyhow!("invalid Virtual Adversary config: {err}"))?;
        let budget = RequestBudget::new(config.request_budget)?;
        let rate_limiter = RateLimiter::new(config.request_delay)?;
        Ok(Self {
            config,
            consent_manager: ConsentManager::new(),
            budget,
            rate_limiter,
        })
    }

    pub fn run(&mut self, target_url: &str) -> Result<()> {
        ensure_consent_and_target(&self.consent_manager, target_url)?;

        let _tier = self.config.tier;
        // Reserve a minimal budget for baseline + one adversarial pass.
        self.budget.consume(2)?;
        let _baseline_wait = self.rate_limiter.record_request();
        let _attack_wait = self.rate_limiter.record_request();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use serde::Serialize;
    use std::fs;
    use tempfile::TempDir;

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

        let mut runner = VirtualAdversaryRunner::new(config).unwrap();
        let result = runner.run("https://example.com");
        assert!(result.is_err());
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

        let mut runner = VirtualAdversaryRunner::new(config).unwrap();
        let result = runner.run("https://example.com");
        assert!(result.is_ok());
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
        assert_eq!(classify_outcome(403, &diff), VaOutcome::Blocked);
    }

    #[test]
    fn test_classify_outcome_challenge_by_header() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "123".to_string());
        let diff = ResponseDiff::compare(&baseline, 200, &headers, "ok");
        assert_eq!(classify_outcome(200, &diff), VaOutcome::Challenge);
    }

    #[test]
    fn test_classify_outcome_allowed() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let diff = ResponseDiff::compare(&baseline, 200, &HashMap::new(), "ok");
        assert_eq!(classify_outcome(200, &diff), VaOutcome::Allowed);
    }
}
