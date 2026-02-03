//! Virtual Adversary (VA) configuration and types.
//!
//! Detection-grade adversarial testing configuration with strict safety bounds.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
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
}
