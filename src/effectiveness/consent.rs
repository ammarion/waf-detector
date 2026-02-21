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

        // Try parsing as URL to extract host, falling through if host
        // cannot be extracted (e.g. bare IPv6 like "fe80::1" where "fe80"
        // looks like a URL scheme).
        let host = Url::parse(trimmed)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .or_else(|| {
                Url::parse(&format!("https://{trimmed}"))
                    .ok()
                    .and_then(|u| u.host_str().map(|h| h.to_string()))
            })
            .unwrap_or_else(|| trimmed.to_string());

        let host = host.to_lowercase();

        // Check if host is an IP address
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Self::validate_ip_address(&ip);
        }

        // Domain validation: check labels and public suffix
        Self::validate_domain(&host)?;

        Ok(host)
    }

    /// Validate IP address is not in private/loopback ranges
    fn validate_ip_address(ip: &std::net::IpAddr) -> Result<String> {
        use std::net::IpAddr;

        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // 127.0.0.0/8 - Loopback
                if octets[0] == 127 {
                    return Err(anyhow!(
                        "IP address {} is in loopback range (127.0.0.0/8) and not allowed",
                        ip
                    ));
                }
                // 10.0.0.0/8 - Private
                if octets[0] == 10 {
                    return Err(anyhow!(
                        "IP address {} is in private range (10.0.0.0/8) and not allowed",
                        ip
                    ));
                }
                // 172.16.0.0/12 - Private
                if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 {
                    return Err(anyhow!(
                        "IP address {} is in private range (172.16.0.0/12) and not allowed",
                        ip
                    ));
                }
                // 192.168.0.0/16 - Private
                if octets[0] == 192 && octets[1] == 168 {
                    return Err(anyhow!(
                        "IP address {} is in private range (192.168.0.0/16) and not allowed",
                        ip
                    ));
                }
                Ok(ip.to_string())
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                // ::1 - Loopback
                if ipv6.is_loopback() {
                    return Err(anyhow!(
                        "IPv6 address {} is loopback (::1) and not allowed",
                        ip
                    ));
                }
                // fe80::/10 - Link-local
                if segments[0] >= 0xfe80 && segments[0] <= 0xfebf {
                    return Err(anyhow!(
                        "IPv6 address {} is in link-local range (fe80::/10) and not allowed",
                        ip
                    ));
                }
                Ok(ip.to_string())
            }
        }
    }

    /// Validate domain is not a public suffix and has sufficient labels
    fn validate_domain(domain: &str) -> Result<()> {
        // Common public suffixes that should be rejected
        const PUBLIC_SUFFIXES: &[&str] = &[
            // Single-part TLDs
            "com", "net", "org", "io", "dev", "app", "edu", "gov", "mil", "int", "info", "biz",
            "name", "pro", "museum", "coop", "aero", "xxx", "idv", "tel", "asia", "cat", "jobs",
            "mobi", "post", "travel", "xxx", // Two-part country TLDs
            "co.uk", "com.au", "co.jp", "com.br", "co.in", "com.cn", "co.nz", "co.za", "com.mx",
            "com.sg", "co.kr", "com.ar", "com.co", "co.id", "com.my", "com.ph", "com.tw", "com.vn",
            "co.th", "com.tr", "com.ua", "co.il", "com.sa", "com.eg", "co.ke",
        ];

        let labels: Vec<&str> = domain.split('.').collect();

        // Require at least 2 labels (e.g., example.com)
        if labels.len() < 2 {
            return Err(anyhow!(
                "Domain '{}' must have at least 2 labels (e.g., example.com)",
                domain
            ));
        }

        // Check against hardcoded public suffix list
        if PUBLIC_SUFFIXES.contains(&domain) {
            return Err(anyhow!(
                "Domain '{}' is a public suffix and cannot be authorized as a target",
                domain
            ));
        }

        // Check if domain is just a two-part public suffix (e.g., co.uk)
        if labels.len() == 2 {
            let two_part = format!("{}.{}", labels[0], labels[1]);
            if PUBLIC_SUFFIXES.contains(&two_part.as_str()) {
                return Err(anyhow!(
                    "Domain '{}' is a public suffix and cannot be authorized as a target",
                    domain
                ));
            }
        }

        Ok(())
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
                    println!(
                        "Authorized targets: {}",
                        status.authorized_targets.join(", ")
                    );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_target_rejects_single_part_tld() {
        let result = ConsentManager::normalize_target("com");
        assert!(result.is_err());
        // Single-label domains hit the "must have at least 2 labels" check
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must have at least 2 labels"));
    }

    #[test]
    fn test_normalize_target_rejects_two_part_country_tld() {
        let result = ConsentManager::normalize_target("co.uk");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("public suffix"));
    }

    #[test]
    fn test_normalize_target_rejects_org_tld() {
        let result = ConsentManager::normalize_target("org");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must have at least 2 labels"));
    }

    #[test]
    fn test_normalize_target_accepts_valid_domain() {
        let result = ConsentManager::normalize_target("example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com");
    }

    #[test]
    fn test_normalize_target_accepts_subdomain() {
        let result = ConsentManager::normalize_target("sub.example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "sub.example.com");
    }

    #[test]
    fn test_normalize_target_extracts_domain_from_url() {
        let result = ConsentManager::normalize_target("https://example.com/path");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com");
    }

    #[test]
    fn test_normalize_target_rejects_localhost_ip() {
        let result = ConsentManager::normalize_target("127.0.0.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("loopback range"));
    }

    #[test]
    fn test_normalize_target_rejects_private_ip_192() {
        let result = ConsentManager::normalize_target("192.168.1.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private range"));
    }

    #[test]
    fn test_normalize_target_rejects_private_ip_10() {
        let result = ConsentManager::normalize_target("10.0.0.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private range"));
    }

    #[test]
    fn test_normalize_target_accepts_public_ip() {
        let result = ConsentManager::normalize_target("8.8.8.8");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "8.8.8.8");
    }

    #[test]
    fn test_normalize_target_rejects_empty_string() {
        let result = ConsentManager::normalize_target("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_normalize_target_rejects_private_ip_172() {
        let result = ConsentManager::normalize_target("172.16.0.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private range"));

        // Test upper bound of 172.16.0.0/12
        let result = ConsentManager::normalize_target("172.31.255.255");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_target_accepts_172_outside_private_range() {
        // 172.15.x.x should be allowed (below 172.16.0.0/12)
        let result = ConsentManager::normalize_target("172.15.1.1");
        assert!(result.is_ok());

        // 172.32.x.x should be allowed (above 172.16.0.0/12)
        let result = ConsentManager::normalize_target("172.32.1.1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_normalize_target_case_insensitive() {
        let result = ConsentManager::normalize_target("EXAMPLE.COM");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com");

        let result = ConsentManager::normalize_target("Sub.Example.COM");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "sub.example.com");
    }

    #[test]
    fn test_normalize_target_rejects_ipv6_loopback() {
        let result = ConsentManager::normalize_target("::1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("loopback"));
    }

    #[test]
    fn test_normalize_target_rejects_ipv6_link_local() {
        let result = ConsentManager::normalize_target("fe80::1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("link-local"));
    }

    #[test]
    fn test_normalize_target_accepts_public_ipv6() {
        let result = ConsentManager::normalize_target("2001:4860:4860::8888");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "2001:4860:4860::8888");
    }

    #[test]
    fn test_normalize_target_rejects_additional_tlds() {
        // Test a few more single-part TLDs from our list
        let tlds = vec!["io", "dev", "app", "edu", "info", "biz"];
        for tld in tlds {
            let result = ConsentManager::normalize_target(tld);
            assert!(result.is_err(), "TLD '{}' should be rejected", tld);
        }
    }

    #[test]
    fn test_normalize_target_rejects_additional_country_tlds() {
        // Test a few more two-part country TLDs from our list
        let tlds = vec!["com.au", "co.jp", "com.br", "co.in", "com.cn"];
        for tld in tlds {
            let result = ConsentManager::normalize_target(tld);
            assert!(result.is_err(), "TLD '{}' should be rejected", tld);
        }
    }

    #[test]
    fn test_normalize_target_trims_whitespace() {
        let result = ConsentManager::normalize_target("  example.com  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com");
    }

    #[test]
    fn test_normalize_target_handles_url_with_port() {
        let result = ConsentManager::normalize_target("https://example.com:8080/path");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com");
    }
}
