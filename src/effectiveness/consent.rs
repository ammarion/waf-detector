//! Owned-target scope management for active testing features.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use url::Url;

const CONSENT_FILE: &str = ".waf-detector-consent.json";
/// Manages the configured owned-target scope for active testing
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
    #[serde(default)]
    pub targets: Vec<ScopeTarget>,
    pub consent_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TargetClass {
    Public,
    Internal,
}

impl TargetClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ScopeTarget {
    pub host: String,
    pub class: TargetClass,
}

/// Stored scope information
#[derive(Debug, Serialize, Deserialize)]
struct ConsentRecord {
    /// When the target scope was last updated
    timestamp: DateTime<Utc>,
    /// Configuration schema version
    terms_version: String,
    /// Target scope schema v2
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    targets: Vec<ScopeTarget>,
    /// Legacy v1 format, read-only for compatibility
    #[serde(default, skip_serializing)]
    authorized_targets: Vec<String>,
    /// Legacy compatibility field
    acknowledgment: String,
}

impl ConsentRecord {
    fn effective_targets(&self) -> Vec<ScopeTarget> {
        let mut targets = Vec::new();
        for target in &self.targets {
            if !targets.iter().any(|entry: &ScopeTarget| entry == target) {
                targets.push(target.clone());
            }
        }
        if targets.is_empty() {
            for host in &self.authorized_targets {
                if let Ok(normalized) =
                    ConsentManager::normalize_target_for_class(host, TargetClass::Public)
                {
                    let target = ScopeTarget {
                        host: normalized,
                        class: TargetClass::Public,
                    };
                    if !targets.iter().any(|entry| entry == &target) {
                        targets.push(target);
                    }
                }
            }
        }
        targets
    }
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
    /// Check if an active target scope has been configured
    pub fn has_valid_consent(&self) -> Result<bool> {
        if !self.consent_file_path.exists() {
            return Ok(false);
        }

        let consent = self.load_consent()?;
        Ok(!consent.effective_targets().is_empty())
    }

    /// Fetch target scope status for UI/API reporting
    pub fn status(&self) -> Result<ConsentStatus> {
        if !self.consent_file_path.exists() {
            return Ok(ConsentStatus {
                has_consent: false,
                terms_version: Self::current_terms_version(),
                expires_in_days: None,
                authorized_targets: Vec::new(),
                targets: Vec::new(),
                consent_timestamp: None,
            });
        }

        let consent = self.load_consent()?;
        let authorized_targets = consent
            .targets
            .iter()
            .map(|target| target.host.clone())
            .collect::<Vec<_>>();

        Ok(ConsentStatus {
            has_consent: !consent.targets.is_empty(),
            terms_version: consent.terms_version,
            expires_in_days: None,
            authorized_targets,
            targets: consent.targets,
            consent_timestamp: Some(consent.timestamp),
        })
    }

    /// Replace the registered target scope
    pub fn set_authorized_targets(&self, targets: &[String]) -> Result<()> {
        self.set_authorized_targets_with_class(targets, TargetClass::Public)
    }

    pub fn set_authorized_targets_with_class(
        &self,
        targets: &[String],
        class: TargetClass,
    ) -> Result<()> {
        let mut normalized_targets = Vec::new();
        for target in targets {
            let normalized = Self::normalize_target_for_class(target, class)?;
            let scope_target = ScopeTarget {
                host: normalized,
                class,
            };
            if !normalized_targets.contains(&scope_target) {
                normalized_targets.push(scope_target);
            }
        }

        if normalized_targets.is_empty() {
            return Err(anyhow!("No authorized targets provided"));
        }

        let record = ConsentRecord {
            timestamp: Utc::now(),
            terms_version: Self::current_terms_version(),
            targets: normalized_targets,
            authorized_targets: Vec::new(),
            acknowledgment: "owned-target scope".to_string(),
        };

        self.save_consent(&record)
    }

    /// Request user consent
    pub fn request_consent(&self) -> Result<()> {
        Err(anyhow!(
            "Interactive consent is no longer used. Register owned targets with `--scope init <domain>` or `--consent init <domain>`."
        ))
    }

    /// Check if a target URL is in the authorized list
    pub fn is_target_allowed(&self, target_url: &str) -> Result<bool> {
        Ok(self.match_target(target_url)?.is_some())
    }

    pub fn match_target(&self, target_url: &str) -> Result<Option<ScopeTarget>> {
        if !self.consent_file_path.exists() {
            return Ok(None);
        }

        let consent = self.load_consent()?;

        // Parse the target URL
        let url =
            Url::parse(target_url).or_else(|_| Url::parse(&format!("https://{target_url}")))?;

        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("Invalid URL: no host found"))?
            .to_ascii_lowercase();

        // Check if host matches any authorized target
        for authorized in &consent.targets {
            if host == authorized.host || host.ends_with(&format!(".{}", authorized.host)) {
                return Ok(Some(authorized.clone()));
            }
        }

        Ok(None)
    }

    /// Add a new authorized target
    pub fn add_authorized_target(&self, target: &str) -> Result<()> {
        self.add_authorized_target_with_class(target, TargetClass::Public)
    }

    pub fn add_authorized_target_with_class(&self, target: &str, class: TargetClass) -> Result<()> {
        let mut consent = if self.consent_file_path.exists() {
            self.load_consent()?
        } else {
            ConsentRecord {
                timestamp: Utc::now(),
                terms_version: Self::current_terms_version(),
                targets: Vec::new(),
                authorized_targets: Vec::new(),
                acknowledgment: "owned-target scope".to_string(),
            }
        };
        let normalized = Self::normalize_target_for_class(target, class)?;
        let scope_target = ScopeTarget {
            host: normalized.clone(),
            class,
        };

        consent.targets.retain(|entry| entry.host != normalized);
        if !consent.targets.contains(&scope_target) {
            consent.targets.push(scope_target);
            consent.timestamp = Utc::now();
            self.save_consent(&consent)?;
        }

        Ok(())
    }

    /// Remove an authorized target
    pub fn remove_authorized_target(&self, target: &str) -> Result<bool> {
        let mut consent = self.load_consent()?;
        let normalized = Url::parse(target)
            .ok()
            .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
            .or_else(|| {
                Url::parse(&format!("https://{target}"))
                    .ok()
                    .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
            })
            .unwrap_or_else(|| target.trim().to_ascii_lowercase());
        let before = consent.targets.len();
        consent.targets.retain(|entry| entry.host != normalized);
        let removed = consent.targets.len() != before;
        if removed {
            consent.timestamp = Utc::now();
            self.save_consent(&consent)?;
        }
        Ok(removed)
    }

    /// Clear all authorized targets
    pub fn clear_authorized_targets(&self) -> Result<()> {
        let record = ConsentRecord {
            timestamp: Utc::now(),
            terms_version: Self::current_terms_version(),
            targets: Vec::new(),
            authorized_targets: Vec::new(),
            acknowledgment: "owned-target scope".to_string(),
        };
        self.save_consent(&record)
    }

    /// Load consent from file
    fn load_consent(&self) -> Result<ConsentRecord> {
        let content = fs::read_to_string(&self.consent_file_path)?;
        let mut consent: ConsentRecord = serde_json::from_str(&content)?;
        consent.targets = consent.effective_targets();
        Ok(consent)
    }

    /// Save consent to file
    fn save_consent(&self, consent: &ConsentRecord) -> Result<()> {
        if let Some(parent) = self.consent_file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(consent)?;
        fs::write(&self.consent_file_path, content)?;
        Ok(())
    }

    /// Current version of terms
    fn current_terms_version() -> String {
        "2.0.0".to_string()
    }

    #[cfg(test)]
    fn normalize_target(target: &str) -> Result<String> {
        Self::normalize_target_for_class(target, TargetClass::Public)
    }

    fn normalize_target_for_class(target: &str, class: TargetClass) -> Result<String> {
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
            return Self::validate_ip_address(&ip, class);
        }

        // Domain validation: check labels and public suffix
        Self::validate_domain(&host)?;

        Ok(host)
    }

    /// Validate IP address registration according to target class
    fn validate_ip_address(ip: &std::net::IpAddr, class: TargetClass) -> Result<String> {
        use std::net::IpAddr;

        if class == TargetClass::Internal {
            if Self::is_disallowed_internal_ip(ip) {
                return Err(anyhow!(
                    "IP address {} cannot be registered as an internal target",
                    ip
                ));
            }
            return Ok(ip.to_string());
        }

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
                // 100.64.0.0/10 - Carrier-grade NAT
                if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                    return Err(anyhow!(
                        "IP address {} is in carrier-grade NAT range (100.64.0.0/10) and not allowed",
                        ip
                    ));
                }
                // 169.254.0.0/16 - Link-local / metadata
                if octets[0] == 169 && octets[1] == 254 {
                    return Err(anyhow!(
                        "IP address {} is in link-local range (169.254.0.0/16) and not allowed",
                        ip
                    ));
                }
                if octets[0] == 0 || octets[0] >= 224 {
                    return Err(anyhow!(
                        "IP address {} is in a reserved non-public range and not allowed",
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
                if ipv6.is_unique_local() || ipv6.is_multicast() || ipv6.is_unspecified() {
                    return Err(anyhow!(
                        "IPv6 address {} is in a non-public range and not allowed",
                        ip
                    ));
                }
                Ok(ip.to_string())
            }
        }
    }

    fn is_disallowed_internal_ip(ip: &std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                ipv4.is_loopback()
                    || ipv4.is_unspecified()
                    || ipv4.is_multicast()
                    || *ipv4 == std::net::Ipv4Addr::new(169, 254, 169, 254)
                    || (ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254)
            }
            std::net::IpAddr::V6(ipv6) => {
                ipv6.is_loopback()
                    || ipv6.is_unspecified()
                    || ipv6.is_multicast()
                    || ipv6.is_unicast_link_local()
                    || *ipv6 == "fd00:ec2::254".parse::<std::net::Ipv6Addr>().unwrap()
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
}

/// CLI command to manage consent
pub fn manage_consent_cli(args: Vec<String>, target_class: TargetClass) -> Result<()> {
    let consent_manager = ConsentManager::new();

    if args.is_empty() {
        // Check current consent status
        if consent_manager.has_valid_consent()? {
            println!("✅ Active target scope configured");
            let consent = consent_manager.load_consent()?;
            println!(
                "Authorized targets: {}",
                consent
                    .targets
                    .iter()
                    .map(|target| format!("{} ({})", target.host, target.class.as_str()))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        } else {
            println!("❌ No active target scope configured");
            println!("Run 'waf-detect --scope init <domain>' to register owned targets");
        }
    } else {
        match args[0].as_str() {
            "request" | "init" => {
                if args.len() < 2 {
                    return Err(anyhow!(
                        "Usage: scope init <domain> [additional domains...]"
                    ));
                }
                let targets = args[1..]
                    .iter()
                    .flat_map(|arg| arg.split(','))
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                consent_manager.set_authorized_targets_with_class(&targets, target_class)?;
                println!(
                    "✅ Registered {} owned {} target(s)",
                    targets.len(),
                    target_class.as_str()
                );
            }
            "status" => {
                let status = consent_manager.status()?;
                if status.has_consent {
                    println!("✅ Active target scope configured");
                } else {
                    println!("❌ No active target scope configured");
                }
                println!("Scope policy version: {}", status.terms_version);
                if let Some(ts) = status.consent_timestamp {
                    println!("Updated at: {}", ts.to_rfc3339());
                }
                if status.authorized_targets.is_empty() {
                    println!("Authorized targets: (none)");
                } else {
                    for target in status.targets {
                        println!(
                            "Authorized target: {} ({})",
                            target.host,
                            target.class.as_str()
                        );
                    }
                }
            }
            "add-target" => {
                if args.len() < 2 {
                    return Err(anyhow!("Usage: scope add-target <domain>"));
                }
                consent_manager.add_authorized_target_with_class(&args[1], target_class)?;
                println!(
                    "✅ Added {} as an {} target",
                    args[1],
                    target_class.as_str()
                );
            }
            "remove-target" => {
                if args.len() < 2 {
                    return Err(anyhow!("Usage: scope remove-target <domain>"));
                }
                let removed = consent_manager.remove_authorized_target(&args[1])?;
                if removed {
                    println!("✅ Removed {} from authorized targets", args[1]);
                } else {
                    println!("ℹ️  {} was not present in the authorized targets", args[1]);
                }
            }
            "revoke" | "clear" => {
                consent_manager.clear_authorized_targets()?;
                println!("✅ Cleared all authorized targets");
            }
            _ => return Err(anyhow!("Unknown scope command: {}", args[0])),
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
