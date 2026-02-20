//! Consent and Ethics Management
//!
//! This module ensures responsible use of the WAF effectiveness testing features
//! by requiring explicit user consent and maintaining authorized target lists.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use url::Url;

const CONSENT_FILE: &str = ".waf-detector-consent.json";
const CONSENT_VALIDITY_DAYS: i64 = 30;

/// Manages user consent and authorized targets
#[derive(Debug)]
pub struct ConsentManager {
    consent_file_path: PathBuf,
}

/// Public consent status for UI/API usage
#[derive(Debug, Serialize)]
pub struct ConsentStatus {
    pub has_consent: bool,
    pub terms_version: String,
    pub expires_in_days: Option<i64>,
    pub authorized_targets: Vec<String>,
    pub consent_timestamp: Option<DateTime<Utc>>,
}

/// Stored consent information
#[derive(Debug, Serialize, Deserialize)]
struct ConsentRecord {
    /// When consent was given
    timestamp: DateTime<Utc>,
    /// Version of terms accepted
    terms_version: String,
    /// List of authorized target domains/URLs
    authorized_targets: Vec<String>,
    /// User's acknowledgment
    acknowledgment: String,
}

impl ConsentManager {
    /// Create a new consent manager
    pub fn new() -> Self {
        let home_dir = match std::env::var("WAF_DETECTOR_HOME") {
            Ok(path) => PathBuf::from(path),
            Err(_) => dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")),
        };
        let consent_file_path = home_dir.join(CONSENT_FILE);

        Self { consent_file_path }
    }
}

impl Default for ConsentManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsentManager {
    /// Check if user has valid consent on file
    pub fn has_valid_consent(&self) -> Result<bool> {
        if !self.consent_file_path.exists() {
            return Ok(false);
        }

        let consent = self.load_consent()?;

        // Check if consent is still valid (not expired)
        let age = Utc::now() - consent.timestamp;
        if age > Duration::days(CONSENT_VALIDITY_DAYS) {
            return Ok(false);
        }

        // Check if terms version is current
        if consent.terms_version != Self::current_terms_version() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Fetch consent status for UI/API reporting
    pub fn status(&self) -> Result<ConsentStatus> {
        if !self.consent_file_path.exists() {
            return Ok(ConsentStatus {
                has_consent: false,
                terms_version: Self::current_terms_version(),
                expires_in_days: None,
                authorized_targets: Vec::new(),
                consent_timestamp: None,
            });
        }

        let consent = self.load_consent()?;
        let age = Utc::now() - consent.timestamp;
        let valid_terms = consent.terms_version == Self::current_terms_version();
        let valid_age = age <= Duration::days(CONSENT_VALIDITY_DAYS);
        let mut remaining = CONSENT_VALIDITY_DAYS - age.num_days();
        if remaining < 0 {
            remaining = 0;
        }

        Ok(ConsentStatus {
            has_consent: valid_terms && valid_age,
            terms_version: consent.terms_version,
            expires_in_days: Some(remaining),
            authorized_targets: consent.authorized_targets,
            consent_timestamp: Some(consent.timestamp),
        })
    }

    /// Request user consent
    pub fn request_consent(&self) -> Result<()> {
        println!("{}", Self::consent_text());
        println!("\n{}", "=".repeat(80));

        // Get user acknowledgment
        println!("\nDo you understand and agree to use this tool responsibly? (type 'I AGREE' to continue)");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim() != "I AGREE" {
            return Err(anyhow!("User did not provide consent"));
        }

        // Get authorized targets
        println!(
            "\nEnter authorized target domains (comma-separated, e.g., example.com,test.local):"
        );
        let mut targets_input = String::new();
        std::io::stdin().read_line(&mut targets_input)?;

        let targets: Vec<String> = targets_input
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(Self::normalize_target)
            .collect::<Result<Vec<_>>>()?;

        if targets.is_empty() {
            return Err(anyhow!("No authorized targets provided"));
        }

        // Save consent record
        let record = ConsentRecord {
            timestamp: Utc::now(),
            terms_version: Self::current_terms_version(),
            authorized_targets: targets,
            acknowledgment: "I AGREE".to_string(),
        };

        self.save_consent(&record)?;

        println!("\n✅ Consent recorded. Thank you for using this tool responsibly.");

        Ok(())
    }

    /// Check if a target URL is in the authorized list
    pub fn is_target_allowed(&self, target_url: &str) -> Result<bool> {
        let consent = self.load_consent()?;

        // Parse the target URL
        let url =
            Url::parse(target_url).or_else(|_| Url::parse(&format!("https://{target_url}")))?;

        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("Invalid URL: no host found"))?;

        // Check if host matches any authorized target
        for authorized in &consent.authorized_targets {
            let authorized =
                Self::normalize_target(authorized).unwrap_or_else(|_| authorized.to_string());
            if host == authorized || host.ends_with(&format!(".{authorized}")) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Add a new authorized target
    pub fn add_authorized_target(&self, target: &str) -> Result<()> {
        let mut consent = self.load_consent()?;
        let normalized = Self::normalize_target(target)?;

        if !consent.authorized_targets.contains(&normalized) {
            consent.authorized_targets.push(normalized);
            self.save_consent(&consent)?;
        }

        Ok(())
    }

    /// Remove an authorized target
    pub fn remove_authorized_target(&self, target: &str) -> Result<bool> {
        let mut consent = self.load_consent()?;
        let before = consent.authorized_targets.len();
        consent.authorized_targets.retain(|entry| entry != target);
        let removed = consent.authorized_targets.len() != before;
        if removed {
            self.save_consent(&consent)?;
        }
        Ok(removed)
    }

    /// Load consent from file
    fn load_consent(&self) -> Result<ConsentRecord> {
        let content = fs::read_to_string(&self.consent_file_path)?;
        let consent: ConsentRecord = serde_json::from_str(&content)?;
        Ok(consent)
    }

    /// Save consent to file
    fn save_consent(&self, consent: &ConsentRecord) -> Result<()> {
        let content = serde_json::to_string_pretty(consent)?;
        fs::write(&self.consent_file_path, content)?;
        Ok(())
    }

    /// Current version of terms
    fn current_terms_version() -> String {
        "1.0.0".to_string()
    }

    fn normalize_target(target: &str) -> Result<String> {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("Authorized target cannot be empty"));
        }
        let url = Url::parse(trimmed).or_else(|_| Url::parse(&format!("https://{trimmed}")));
        if let Ok(parsed) = url {
            if let Some(host) = parsed.host_str() {
                return Ok(host.to_lowercase());
            }
        }
        Ok(trimmed.to_lowercase())
    }

    /// Consent text displayed to users
    fn consent_text() -> &'static str {
        r#"
╔══════════════════════════════════════════════════════════════════════════════╗
║                    WAF EFFECTIVENESS TESTING - TERMS OF USE                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  This tool includes advanced WAF effectiveness testing capabilities that     ║
║  can be used to validate security controls. By using these features, you    ║
║  acknowledge and agree to the following:                                     ║
║                                                                              ║
║  1. AUTHORIZED USE ONLY                                                      ║
║     • You will only use this tool on systems you own or have explicit       ║
║       written permission to test                                             ║
║     • You will comply with all applicable laws and regulations               ║
║     • You will not use this tool for malicious purposes                     ║
║                                                                              ║
║  2. RESPONSIBLE DISCLOSURE                                                   ║
║     • If you discover vulnerabilities, you will report them responsibly     ║
║     • You will not publicly disclose vulnerabilities without permission     ║
║     • You will work with system owners to remediate issues                  ║
║                                                                              ║
║  3. AUDIT AND LOGGING                                                        ║
║     • All tests will be logged for audit purposes                           ║
║     • You may be required to provide test logs if requested                 ║
║     • Logs should be retained for compliance purposes                       ║
║                                                                              ║
║  4. RATE LIMITING AND ETHICS                                                 ║
║     • The tool implements rate limiting to prevent DoS                      ║
║     • You will not attempt to bypass safety features                        ║
║     • You will use the minimum testing intensity necessary                  ║
║                                                                              ║
║  5. NO WARRANTY                                                              ║
║     • This tool is provided as-is without warranty                          ║
║     • The authors are not liable for any damages or misuse                  ║
║     • You assume all risks associated with using this tool                  ║
║                                                                              ║
║  VIOLATION OF THESE TERMS MAY RESULT IN:                                    ║
║  • Criminal prosecution                                                      ║
║  • Civil liability                                                           ║
║  • Termination of access                                                     ║
║  • Reporting to law enforcement                                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝"#
    }
}

/// CLI command to manage consent
pub fn manage_consent_cli(args: Vec<String>) -> Result<()> {
    let consent_manager = ConsentManager::new();

    if args.is_empty() {
        // Check current consent status
        if consent_manager.has_valid_consent()? {
            println!("✅ Valid consent on file");
            let consent = consent_manager.load_consent()?;
            println!(
                "Authorized targets: {}",
                consent.authorized_targets.join(", ")
            );
        } else {
            println!("❌ No valid consent on file");
            println!("Run 'waf-detect consent request' to provide consent");
        }
    } else {
        match args[0].as_str() {
            "request" => consent_manager.request_consent()?,
            "status" => {
                let status = consent_manager.status()?;
                if status.has_consent {
                    println!("✅ Valid consent on file");
                } else {
                    println!("❌ No valid consent on file");
                }
                println!("Terms version: {}", status.terms_version);
                if let Some(days) = status.expires_in_days {
                    println!("Expires in: {} day(s)", days);
                }
                if let Some(ts) = status.consent_timestamp {
                    println!("Consent timestamp: {}", ts.to_rfc3339());
                }
                if status.authorized_targets.is_empty() {
                    println!("Authorized targets: (none)");
                } else {
                    println!("Authorized targets: {}", status.authorized_targets.join(", "));
                    println!(
                        "Authorized targets: {}",
                        status.authorized_targets.join(", ")
                    );
                }
            }
            "add-target" => {
                if args.len() < 2 {
                    return Err(anyhow!("Usage: consent add-target <domain>"));
                }
                consent_manager.add_authorized_target(&args[1])?;
                println!("✅ Added {} to authorized targets", args[1]);
            }
            _ => return Err(anyhow!("Unknown consent command: {}", args[0])),
        }
    }

    Ok(())
}
