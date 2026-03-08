use crate::audit::RunAudit;
use crate::surface::{AuthClass, DiscoverySource, RefinedSurfaceMapStats, SurfaceMapSummary};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HardeningSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl HardeningSeverity {
    pub fn rank(self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ControlFamily {
    NormalizationGap,
    ParserMismatch,
    HeaderTrustGap,
    MethodSemanticsGap,
    PathHandlingGap,
    BodyInspectionGap,
    ChallengeEscalationGap,
    RateLimitGap,
    StatefulnessGap,
    SurfaceUnsuitable,
}

impl ControlFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NormalizationGap => "normalization_gap",
            Self::ParserMismatch => "parser_mismatch",
            Self::HeaderTrustGap => "header_trust_gap",
            Self::MethodSemanticsGap => "method_semantics_gap",
            Self::PathHandlingGap => "path_handling_gap",
            Self::BodyInspectionGap => "body_inspection_gap",
            Self::ChallengeEscalationGap => "challenge_escalation_gap",
            Self::RateLimitGap => "rate_limit_gap",
            Self::StatefulnessGap => "statefulness_gap",
            Self::SurfaceUnsuitable => "surface_unsuitable",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CiGateMode {
    #[default]
    Off,
    Critical,
    Any,
}

impl CiGateMode {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "off" => Ok(Self::Off),
            "critical" => Ok(Self::Critical),
            "any" => Ok(Self::Any),
            other => Err(anyhow::anyhow!(
                "invalid ci gate '{other}' (expected off|critical|any)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Critical => "critical",
            Self::Any => "any",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum VendorMode {
    #[default]
    Auto,
    Cloudflare,
    Aws,
}

impl VendorMode {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Self::Auto),
            "cloudflare" => Ok(Self::Cloudflare),
            "aws" => Ok(Self::Aws),
            other => Err(anyhow::anyhow!(
                "invalid vendor mode '{other}' (expected auto|cloudflare|aws)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Cloudflare => "cloudflare",
            Self::Aws => "aws",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderDetectionSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_waf: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waf_confidence: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_cdn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdn_confidence: Option<f64>,
    pub vendor_mode: VendorMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SurfaceAssessment {
    pub suitable: bool,
    pub confidence: f64,
    pub reason: String,
    #[serde(default)]
    pub indicators: Vec<String>,
    #[serde(default)]
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningFinding {
    pub id: String,
    pub title: String,
    pub severity: HardeningSeverity,
    pub confidence: f64,
    pub control_family: ControlFamily,
    pub vector: String,
    #[serde(default)]
    pub channels: Vec<String>,
    pub reproducible: bool,
    #[serde(default)]
    pub preconditions: Vec<String>,
    pub bypass_summary: String,
    pub likely_root_cause: String,
    #[serde(default)]
    pub fix_guidance: Vec<String>,
    #[serde(default)]
    pub vendor_guidance: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_class: Option<AuthClass>,
    #[serde(default)]
    pub discovery_sources: Vec<DiscoverySource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regression_assertion: Option<RegressionAssertion>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservedAction {
    Allowed,
    Blocked,
    Challenge,
    RateLimited,
    BaselineMatch,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Detection,
    SurfaceAssessment,
    Smoke,
    Va,
    Va2,
    Effectiveness,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseComparison {
    #[serde(default)]
    pub summary: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub id: String,
    pub source: EvidenceSource,
    pub summary: String,
    pub observed_action: ObservedAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<EvidenceRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_request: Option<EvidenceRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_comparison: Option<ResponseComparison>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegressionExpectedAction {
    Block,
    Challenge,
    RateLimit,
    BaselineMatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegressionStabilityLevel {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegressionPassCriteria {
    #[serde(default)]
    pub expected_status_codes: Vec<u16>,
    #[serde(default)]
    pub expected_indicators: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_delta_ratio: Option<f64>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionAssertion {
    pub finding_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,
    pub expected_action: RegressionExpectedAction,
    pub request: EvidenceRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_request: Option<EvidenceRequest>,
    pub pass_criteria: RegressionPassCriteria,
    pub stability_level: RegressionStabilityLevel,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionPack {
    pub schema_version: String,
    pub generated_at: DateTime<Utc>,
    #[serde(default)]
    pub assertions: Vec<RegressionAssertion>,
}

impl Default for RegressionPack {
    fn default() -> Self {
        Self {
            schema_version: "hardening-regression-pack/v1".to_string(),
            generated_at: Utc::now(),
            assertions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoverageSummary {
    #[serde(default)]
    pub sources_run: Vec<String>,
    #[serde(default)]
    pub findings_by_family: HashMap<String, usize>,
    #[serde(default)]
    pub channel_scores: HashMap<String, f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_score: Option<f64>,
    pub evidence_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HardeningSummary {
    pub total_findings: usize,
    pub actionable_findings: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_severity: Option<HardeningSeverity>,
    pub ci_gate: CiGateMode,
    pub ci_gate_triggered: bool,
    pub vendor_mode: VendorMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningReport {
    pub target: String,
    pub provider_detection: ProviderDetectionSummary,
    pub surface_assessment: SurfaceAssessment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_map_summary: Option<SurfaceMapSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refined_surface_map_stats: Option<RefinedSurfaceMapStats>,
    #[serde(default)]
    pub findings: Vec<HardeningFinding>,
    pub regression_pack: RegressionPack,
    pub coverage: CoverageSummary,
    #[serde(default)]
    pub evidence_inventory: Vec<EvidenceRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<RunAudit>,
    pub summary: HardeningSummary,
}

impl HardeningReport {
    pub fn refresh_summary(
        &mut self,
        ci_gate: CiGateMode,
        vendor_mode: VendorMode,
        provider: Option<String>,
        notes: Vec<String>,
    ) {
        let highest_severity = self
            .findings
            .iter()
            .map(|finding| finding.severity)
            .max_by_key(|severity| severity.rank());
        self.summary = HardeningSummary {
            total_findings: self.findings.len(),
            actionable_findings: self
                .findings
                .iter()
                .filter(|finding| finding.severity != HardeningSeverity::Info)
                .count(),
            highest_severity,
            ci_gate,
            ci_gate_triggered: ci_gate_triggered(&self.findings, ci_gate),
            vendor_mode,
            provider,
            notes,
        };
    }
}

pub fn ci_gate_triggered(findings: &[HardeningFinding], ci_gate: CiGateMode) -> bool {
    ci_gate_failures(findings, ci_gate).next().is_some()
}

pub fn ci_gate_failures<'a>(
    findings: &'a [HardeningFinding],
    ci_gate: CiGateMode,
) -> impl Iterator<Item = &'a HardeningFinding> {
    findings.iter().filter(move |finding| match ci_gate {
        CiGateMode::Off => false,
        CiGateMode::Critical => {
            matches!(
                finding.severity,
                HardeningSeverity::Critical | HardeningSeverity::High
            ) && finding.confidence >= 0.8
        }
        CiGateMode::Any => matches!(
            finding.severity,
            HardeningSeverity::Critical | HardeningSeverity::High | HardeningSeverity::Medium
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding(id: &str, severity: HardeningSeverity, confidence: f64) -> HardeningFinding {
        HardeningFinding {
            id: id.to_string(),
            title: "finding".to_string(),
            severity,
            confidence,
            control_family: ControlFamily::NormalizationGap,
            vector: "query".to_string(),
            channels: vec!["query".to_string()],
            reproducible: true,
            preconditions: Vec::new(),
            bypass_summary: "summary".to_string(),
            likely_root_cause: "cause".to_string(),
            fix_guidance: Vec::new(),
            vendor_guidance: Vec::new(),
            endpoint_id: None,
            path_template: None,
            auth_class: None,
            discovery_sources: Vec::new(),
            regression_assertion: None,
            evidence_refs: Vec::new(),
        }
    }

    #[test]
    fn test_ci_gate_critical_requires_confident_high_or_critical_findings() {
        let findings = vec![
            sample_finding("a", HardeningSeverity::Medium, 0.95),
            sample_finding("b", HardeningSeverity::High, 0.79),
            sample_finding("c", HardeningSeverity::High, 0.92),
        ];
        assert!(ci_gate_triggered(&findings, CiGateMode::Critical));
    }

    #[test]
    fn test_ci_gate_any_triggers_on_medium_and_above() {
        let findings = vec![
            sample_finding("a", HardeningSeverity::Low, 0.99),
            sample_finding("b", HardeningSeverity::Medium, 0.4),
        ];
        assert!(ci_gate_triggered(&findings, CiGateMode::Any));
    }
}
