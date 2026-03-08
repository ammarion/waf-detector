use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod active;
pub mod audit;
pub mod cli;
pub mod confidence;
pub mod engine;
pub mod hardening;
pub mod http;
pub mod providers;
pub mod registry;
#[cfg(feature = "legacy-script-executor")]
pub mod script_executor;
pub mod surface;
pub mod utils;

#[cfg(test)]
mod test_utils;

// NEW: Advanced confidence and validation modules
pub mod dns;
pub mod http2;
pub mod payload;
pub mod perf;
pub mod testing;
pub mod timing;
pub mod tls;

// NEW: WAF Effectiveness Testing module
pub mod effectiveness;
pub mod origin_probe;
pub mod posture;
pub mod virtual_adversary;
pub mod virtual_adversary2;

/// Unified posture summary used by CLI/API for operator-facing risk reports.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PostureSummary {
    pub overall_posture_score: f64,
    pub monitor_mode_likelihood: f64,
    pub active_enforcement_likelihood: f64,
    #[serde(default)]
    pub coverage_by_vector: HashMap<String, f64>,
    pub confidence: f64,
    #[serde(default)]
    pub caveats: Vec<String>,
}

/// Snapshot of observed runtime latencies used for performance gates.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerformanceSnapshot {
    pub scan_p95_ms: u64,
    pub va_p95_ms: u64,
    pub va2_p95_ms: u64,
    pub sample_size: usize,
    pub mode: String,
    #[serde(default)]
    pub scan_p99_ms: u64,
    #[serde(default)]
    pub va_p99_ms: u64,
    #[serde(default)]
    pub va2_p99_ms: u64,
}

#[derive(Debug, Clone)]
pub struct DetectionContext {
    pub url: String,
    pub response: Option<http::HttpResponse>,
    pub dns_info: Option<DnsInfo>,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsInfo {
    #[serde(default)]
    pub cnames: Vec<String>,
    #[serde(default)]
    pub a_records: Vec<String>,
    #[serde(default)]
    pub txt_records: Vec<String>,
    #[serde(default)]
    pub mx_records: Vec<String>,
    #[serde(default)]
    pub ns_records: Vec<String>,
}

#[async_trait::async_trait]
pub trait DetectionProvider: Send + Sync {
    fn name(&self) -> &str;
    fn provider_type(&self) -> ProviderType;
    fn version(&self) -> &str;
    fn description(&self) -> Option<String>;
    fn confidence_base(&self) -> f64;
    fn priority(&self) -> u32;
    fn enabled(&self) -> bool;

    async fn detect(&self, context: &DetectionContext) -> anyhow::Result<Vec<Evidence>>;

    async fn passive_detect(
        &self,
        _response: &http::HttpResponse,
    ) -> anyhow::Result<Vec<Evidence>> {
        Ok(vec![])
    }

    async fn active_detect(
        &self,
        _client: &http::HttpClient,
        _url: &str,
    ) -> anyhow::Result<Vec<Evidence>> {
        Ok(vec![])
    }

    async fn dns_detect(&self, _dns_info: &DnsInfo) -> anyhow::Result<Vec<Evidence>> {
        Ok(vec![])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProviderType {
    WAF,
    CDN,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub method_type: DetectionMethod,
    pub confidence: f64,
    pub description: String,
    pub raw_data: String,
    pub signature_matched: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectionMethod {
    Header(String),
    Body(String),
    StatusCode(u16),
    DNS(String),
    Timing,
    Certificate,
    Payload,
}

// Alias for backward compatibility
pub type MethodType = DetectionMethod;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub url: String,
    pub detected_waf: Option<ProviderDetection>,
    pub detected_cdn: Option<ProviderDetection>,
    pub provider_scores: HashMap<String, f64>,
    pub evidence_map: HashMap<String, Vec<Evidence>>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    pub detection_time_ms: u64,
    pub metadata: DetectionMetadata,
    /// Operator-facing caveats about detection reliability
    #[serde(default)]
    pub caveats: Vec<String>,
    /// Security configuration active during this scan
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_posture: Option<SecurityPosture>,
    /// Error message if detection failed for this URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderDetection {
    pub name: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMetadata {
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub user_agent: String,
}

/// Records the security configuration active during a scan.
/// Included in every detection result for trust/audit purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPosture {
    /// Whether TLS certificate validation was disabled
    pub insecure_tls: bool,
    /// CORS policy mode: "restricted" or "default"
    pub cors_mode: String,
    /// Human-readable description of the CORS tier policy
    pub cors_policy_detail: String,
    /// Whether API token authentication is enabled
    pub api_auth_enabled: bool,
    /// List of authorized targets active during run
    #[serde(default, alias = "consent_scope")]
    pub target_scope: Vec<String>,
}

impl SecurityPosture {
    /// Build from current environment configuration.
    pub fn from_env() -> Self {
        let insecure_tls = std::env::var("WAF_DETECTOR_INSECURE_TLS").is_ok();
        let api_auth_enabled = std::env::var("WAF_DETECTOR_API_TOKEN")
            .map(|t| !t.is_empty())
            .unwrap_or(false);
        let (cors_mode, cors_policy_detail) =
            if std::env::var("WAF_DETECTOR_ALLOWED_ORIGINS").is_ok() || api_auth_enabled {
                (
                    "restricted".to_string(),
                    "all tiers: custom origins + localhost".to_string(),
                )
            } else {
                (
                    "default".to_string(),
                    "public: any origin, sensitive: localhost, active: localhost".to_string(),
                )
            };
        let target_scope = crate::effectiveness::consent::ConsentManager::new()
            .status()
            .map(|s| s.authorized_targets)
            .unwrap_or_default();

        Self {
            insecure_tls,
            cors_mode,
            cors_policy_detail,
            api_auth_enabled,
            target_scope,
        }
    }
}

impl DetectionResult {
    pub fn has_waf(&self) -> bool {
        self.detected_waf.is_some()
    }

    pub fn has_cdn(&self) -> bool {
        self.detected_cdn.is_some()
    }

    pub fn detected(&self) -> bool {
        self.has_waf() || self.has_cdn()
    }

    pub fn waf_name(&self) -> Option<&str> {
        self.detected_waf.as_ref().map(|w| w.name.as_str())
    }

    pub fn cdn_name(&self) -> Option<&str> {
        self.detected_cdn.as_ref().map(|c| c.name.as_str())
    }

    pub fn waf_confidence(&self) -> Option<f64> {
        self.detected_waf.as_ref().map(|w| w.confidence)
    }

    pub fn cdn_confidence(&self) -> Option<f64> {
        self.detected_cdn.as_ref().map(|c| c.confidence)
    }

    pub fn analysis_time_ms(&self) -> u64 {
        self.detection_time_ms
    }

    /// Get all evidence as a flat list for CLI/report rendering.
    pub fn evidence(&self) -> Vec<Evidence> {
        if !self.evidence.is_empty() {
            self.evidence.clone()
        } else {
            self.evidence_map.values().flatten().cloned().collect()
        }
    }

    /// Generate caveats based on detection conditions.
    pub fn generate_caveats(&mut self) {
        let mut caveats = Vec::new();

        // Caveat: insecure TLS
        if std::env::var("WAF_DETECTOR_INSECURE_TLS").is_ok() {
            caveats.push("TLS certificates were not validated during this scan".to_string());
        }

        // Caveat: low-confidence body-only detection
        for (provider, evidence_list) in &self.evidence_map {
            let has_header_evidence = evidence_list
                .iter()
                .any(|e| matches!(e.method_type, DetectionMethod::Header(_)));
            let has_body_evidence = evidence_list
                .iter()
                .any(|e| matches!(e.method_type, DetectionMethod::Body(_)));
            if has_body_evidence && !has_header_evidence {
                caveats.push(format!(
                    "Detection of {} relies on body patterns only — consider additional verification",
                    provider
                ));
            }
        }

        // Caveat: timing-dominant evidence
        for (provider, evidence_list) in &self.evidence_map {
            let timing_count = evidence_list
                .iter()
                .filter(|e| matches!(e.method_type, DetectionMethod::Timing))
                .count();
            let total = evidence_list.len();
            if total > 0 && timing_count as f64 / total as f64 > 0.5 {
                caveats.push(format!(
                    "Detection of {} relies heavily on timing analysis — results may vary with network conditions",
                    provider
                ));
            }
        }

        self.caveats = caveats;
    }

    pub fn format_as_table(&self) -> String {
        let mut table = String::new();

        // Table header
        table.push_str(
            "┌─────────────────────────────────────────────────────────────────────────┐\n",
        );
        table.push_str(
            "│                            WAF/CDN Detection Results                    │\n",
        );
        table.push_str(
            "├─────────────────────────────────────────────────────────────────────────┤\n",
        );

        // URL
        let url_display = if self.url.len() > 67 {
            format!("{}...", &self.url[..64])
        } else {
            self.url.clone()
        };
        table.push_str(&format!("│ URL: {url_display:<67} │\n"));
        table.push_str(
            "├─────────────────────────────────────────────────────────────────────────┤\n",
        );

        // WAF Detection
        if let Some(waf) = &self.detected_waf {
            table.push_str(&format!(
                "│ WAF: {:<20} Confidence: {:<6.1}%                    │\n",
                waf.name,
                waf.confidence * 100.0
            ));
        } else {
            table.push_str(
                "│ WAF: Not Detected                                                      │\n",
            );
        }

        // CDN Detection
        if let Some(cdn) = &self.detected_cdn {
            table.push_str(&format!(
                "│ CDN: {:<20} Confidence: {:<6.1}%                    │\n",
                cdn.name,
                cdn.confidence * 100.0
            ));
        } else {
            table.push_str(
                "│ CDN: Not Detected                                                      │\n",
            );
        }

        table.push_str(
            "├─────────────────────────────────────────────────────────────────────────┤\n",
        );
        table.push_str(&format!(
            "│ Detection Time: {:<8} ms                                          │\n",
            self.detection_time_ms
        ));
        table.push_str(
            "├─────────────────────────────────────────────────────────────────────────┤\n",
        );

        // Evidence Summary
        table.push_str(
            "│ Evidence Summary:                                                       │\n",
        );
        for (provider, evidence_list) in &self.evidence_map {
            if !evidence_list.is_empty() {
                table.push_str(&format!(
                    "│ • {:<20} Evidence Count: {:<3}                          │\n",
                    provider,
                    evidence_list.len()
                ));

                for (i, evidence) in evidence_list.iter().enumerate() {
                    if i < 3 {
                        // Show first 3 evidence items
                        let desc = if evidence.description.len() > 45 {
                            format!("{}...", &evidence.description[..42])
                        } else {
                            evidence.description.clone()
                        };
                        table.push_str(&format!("│   - {desc:<65} │\n"));

                        // Show the raw data if it's short enough
                        if evidence.raw_data.len() <= 50 {
                            table.push_str(&format!("│     Data: {:<59} │\n", evidence.raw_data));
                        }
                    }
                }
                if evidence_list.len() > 3 {
                    table.push_str(&format!("│   ... and {} more evidence items                                     │\n",
                        evidence_list.len() - 3));
                }
            }
        }

        // Add caveats section if any
        if !self.caveats.is_empty() {
            table.push_str(
                "├─────────────────────────────────────────────────────────────────────────┤\n",
            );
            table.push_str(
                "│ ⚠ Caveats                                                              │\n",
            );
            for caveat in &self.caveats {
                let display = if caveat.len() > 67 {
                    &caveat[..67]
                } else {
                    caveat
                };
                table.push_str(&format!("│  • {:<67} │\n", display));
            }
        }

        table.push_str(
            "└─────────────────────────────────────────────────────────────────────────┘\n",
        );

        table
    }

    pub fn format_pretty(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("🔍 Scanning: {}\n\n", self.url));
        output.push_str(&format!("🎯 Detection Results for: {}\n", self.url));
        output.push_str(&format!(
            "⏱️  Detection time: {}ms\n\n",
            self.detection_time_ms
        ));

        if let Some(waf) = &self.detected_waf {
            output.push_str(&format!(
                "🛡️  WAF Detected: {} (Confidence: {:.1}%)\n",
                waf.name,
                waf.confidence * 100.0
            ));
        }

        if let Some(cdn) = &self.detected_cdn {
            output.push_str(&format!(
                "🌐 CDN Detected: {} (Confidence: {:.1}%)\n",
                cdn.name,
                cdn.confidence * 100.0
            ));
        }

        output.push_str("\n📊 Evidence Details:\n\n");

        for (provider, evidence_list) in &self.evidence_map {
            if !evidence_list.is_empty() {
                output.push_str(&format!("  {provider} Evidence:\n"));
                for evidence in evidence_list {
                    output.push_str(&format!(
                        "    • {} (Confidence: {:.1}%)\n",
                        evidence.description,
                        evidence.confidence * 100.0
                    ));
                    output.push_str(&format!("      Data: {}\n", evidence.raw_data));
                }
                output.push('\n');
            }
        }

        output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Pretty,
    Table,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "pretty" => Ok(OutputFormat::Pretty),
            "table" => Ok(OutputFormat::Table),
            _ => Err(format!("Unknown output format: {s}")),
        }
    }
}

/// Deployment mode for the WAF detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    /// Development mode (default) — permissive settings
    Dev,
    /// Production mode — enforces security controls
    Prod,
}

impl DeploymentMode {
    /// Read deployment mode from WAF_DETECTOR_MODE env var.
    /// Defaults to Dev if unset or unrecognized.
    pub fn from_env() -> Self {
        match std::env::var("WAF_DETECTOR_MODE").as_deref() {
            Ok("prod") | Ok("production") => Self::Prod,
            _ => Self::Dev,
        }
    }

    pub fn is_prod(&self) -> bool {
        *self == Self::Prod
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_mode_defaults_to_dev() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::remove_var("WAF_DETECTOR_MODE");
        assert_eq!(DeploymentMode::from_env(), DeploymentMode::Dev);
    }

    #[test]
    fn deployment_mode_reads_prod() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::set_var("WAF_DETECTOR_MODE", "prod");
        assert_eq!(DeploymentMode::from_env(), DeploymentMode::Prod);
        std::env::remove_var("WAF_DETECTOR_MODE");
    }

    #[test]
    fn deployment_mode_reads_production() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::set_var("WAF_DETECTOR_MODE", "production");
        assert_eq!(DeploymentMode::from_env(), DeploymentMode::Prod);
        std::env::remove_var("WAF_DETECTOR_MODE");
    }

    #[test]
    fn deployment_mode_is_prod_check() {
        assert!(DeploymentMode::Prod.is_prod());
        assert!(!DeploymentMode::Dev.is_prod());
    }

    #[test]
    fn generate_caveats_empty_when_clean() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::remove_var("WAF_DETECTOR_INSECURE_TLS");

        let mut evidence_map = HashMap::new();
        evidence_map.insert(
            "CloudFlare".to_string(),
            vec![Evidence {
                method_type: DetectionMethod::Header("cf-ray".to_string()),
                confidence: 0.95,
                description: "CF-Ray header detected".to_string(),
                raw_data: "abcd1234-SEA".to_string(),
                signature_matched: "cf-ray-header".to_string(),
            }],
        );

        let mut result = DetectionResult {
            url: "https://example.com".to_string(),
            detected_waf: Some(ProviderDetection {
                name: "CloudFlare".to_string(),
                confidence: 0.95,
            }),
            detected_cdn: None,
            provider_scores: HashMap::new(),
            evidence_map,
            evidence: Vec::new(),
            detection_time_ms: 100,
            metadata: DetectionMetadata {
                timestamp: chrono::Utc::now(),
                version: "0.1.0".to_string(),
                user_agent: "WAF-Detector/1.0".to_string(),
            },
            caveats: Vec::new(),
            security_posture: None,
            error: None,
        };

        result.generate_caveats();
        assert!(result.caveats.is_empty());
    }

    #[test]
    fn generate_caveats_flags_insecure_tls() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::set_var("WAF_DETECTOR_INSECURE_TLS", "1");

        let mut result = DetectionResult {
            url: "https://example.com".to_string(),
            detected_waf: None,
            detected_cdn: None,
            provider_scores: HashMap::new(),
            evidence_map: HashMap::new(),
            evidence: Vec::new(),
            detection_time_ms: 100,
            metadata: DetectionMetadata {
                timestamp: chrono::Utc::now(),
                version: "0.1.0".to_string(),
                user_agent: "WAF-Detector/1.0".to_string(),
            },
            caveats: Vec::new(),
            security_posture: None,
            error: None,
        };

        result.generate_caveats();
        assert_eq!(result.caveats.len(), 1);
        assert!(result.caveats[0].contains("TLS certificates were not validated"));

        std::env::remove_var("WAF_DETECTOR_INSECURE_TLS");
    }

    #[test]
    fn generate_caveats_flags_body_only_detection() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::remove_var("WAF_DETECTOR_INSECURE_TLS");

        let mut evidence_map = HashMap::new();
        evidence_map.insert(
            "ModSecurity".to_string(),
            vec![Evidence {
                method_type: DetectionMethod::Body("ModSecurity".to_string()),
                confidence: 0.70,
                description: "ModSecurity pattern in body".to_string(),
                raw_data: "ModSecurity error page".to_string(),
                signature_matched: "modsecurity-error-body".to_string(),
            }],
        );

        let mut result = DetectionResult {
            url: "https://example.com".to_string(),
            detected_waf: Some(ProviderDetection {
                name: "ModSecurity".to_string(),
                confidence: 0.70,
            }),
            detected_cdn: None,
            provider_scores: HashMap::new(),
            evidence_map,
            evidence: Vec::new(),
            detection_time_ms: 100,
            metadata: DetectionMetadata {
                timestamp: chrono::Utc::now(),
                version: "0.1.0".to_string(),
                user_agent: "WAF-Detector/1.0".to_string(),
            },
            caveats: Vec::new(),
            security_posture: None,
            error: None,
        };

        result.generate_caveats();
        assert_eq!(result.caveats.len(), 1);
        assert!(result.caveats[0].contains("body patterns only"));
        assert!(result.caveats[0].contains("ModSecurity"));
    }

    #[test]
    fn generate_caveats_flags_timing_dominant() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::remove_var("WAF_DETECTOR_INSECURE_TLS");

        let mut evidence_map = HashMap::new();
        evidence_map.insert(
            "GenericWAF".to_string(),
            vec![
                Evidence {
                    method_type: DetectionMethod::Timing,
                    confidence: 0.65,
                    description: "Timing anomaly detected".to_string(),
                    raw_data: "500ms delay".to_string(),
                    signature_matched: "timing-waf-delay".to_string(),
                },
                Evidence {
                    method_type: DetectionMethod::Timing,
                    confidence: 0.70,
                    description: "Another timing anomaly".to_string(),
                    raw_data: "600ms delay".to_string(),
                    signature_matched: "timing-waf-delay-2".to_string(),
                },
            ],
        );

        let mut result = DetectionResult {
            url: "https://example.com".to_string(),
            detected_waf: Some(ProviderDetection {
                name: "GenericWAF".to_string(),
                confidence: 0.70,
            }),
            detected_cdn: None,
            provider_scores: HashMap::new(),
            evidence_map,
            evidence: Vec::new(),
            detection_time_ms: 100,
            metadata: DetectionMetadata {
                timestamp: chrono::Utc::now(),
                version: "0.1.0".to_string(),
                user_agent: "WAF-Detector/1.0".to_string(),
            },
            caveats: Vec::new(),
            security_posture: None,
            error: None,
        };

        result.generate_caveats();
        assert_eq!(result.caveats.len(), 1);
        assert!(result.caveats[0].contains("timing analysis"));
        assert!(result.caveats[0].contains("network conditions"));
    }

    #[test]
    fn security_posture_from_env_defaults() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::remove_var("WAF_DETECTOR_INSECURE_TLS");
        std::env::remove_var("WAF_DETECTOR_API_TOKEN");
        std::env::remove_var("WAF_DETECTOR_ALLOWED_ORIGINS");

        let posture = SecurityPosture::from_env();
        assert!(!posture.insecure_tls);
        assert!(!posture.api_auth_enabled);
        assert_eq!(posture.cors_mode, "default");
        assert_eq!(
            posture.cors_policy_detail,
            "public: any origin, sensitive: localhost, active: localhost"
        );

        std::env::remove_var("WAF_DETECTOR_INSECURE_TLS");
    }
}
