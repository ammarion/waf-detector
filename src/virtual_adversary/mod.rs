//! Virtual Adversary (VA) configuration and types.
//!
//! Detection-grade adversarial testing configuration with strict safety bounds.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use url::Url;

use crate::active::{guard_target, ResolvedTarget};
use crate::audit::RunAudit;
use crate::effectiveness::consent::ConsentManager;
use crate::http::HttpClient;
use crate::virtual_adversary::dae::{probe_catalog_for_tier, Probe};
use sha2::{Digest, Sha256};

pub mod dae;
pub mod report_store;

fn parse_probe_class(value: &str) -> Result<dae::ProbeClass> {
    match value.to_lowercase().as_str() {
        "parserambiguity" => Ok(dae::ProbeClass::ParserAmbiguity),
        "protocolmutation" => Ok(dae::ProbeClass::ProtocolMutation),
        "encodingboundary" => Ok(dae::ProbeClass::EncodingBoundary),
        "behavioralthrottle" => Ok(dae::ProbeClass::BehavioralThrottle),
        "responsefingerprint" => Ok(dae::ProbeClass::ResponseFingerprint),
        "semanticdrift" => Ok(dae::ProbeClass::SemanticDrift),
        other => Err(anyhow!("unknown probe class: {other}")),
    }
}

fn parse_probe_channel(value: &str) -> Result<dae::ProbeChannel> {
    match value.to_lowercase().as_str() {
        "path" => Ok(dae::ProbeChannel::Path),
        "query" => Ok(dae::ProbeChannel::Query),
        "header" => Ok(dae::ProbeChannel::Header),
        "body" => Ok(dae::ProbeChannel::Body),
        "method" => Ok(dae::ProbeChannel::Method),
        "cookie" => Ok(dae::ProbeChannel::Cookie),
        other => Err(anyhow!("unknown probe channel: {other}")),
    }
}

fn parse_http_method(value: &str) -> Result<&'static str> {
    match value.to_uppercase().as_str() {
        "GET" => Ok("GET"),
        "POST" => Ok("POST"),
        "PUT" => Ok("PUT"),
        "DELETE" => Ok("DELETE"),
        "PATCH" => Ok("PATCH"),
        "HEAD" => Ok("HEAD"),
        "OPTIONS" => Ok("OPTIONS"),
        other => Err(anyhow!("unsupported http method: {other}")),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Skip DNS validation in evaluate_probe (for hermetic tests).
    #[serde(default)]
    pub skip_dns_validation: bool,
}

impl Default for VirtualAdversaryConfig {
    fn default() -> Self {
        Self {
            tier: 1,
            request_budget: 120,
            request_timeout: Duration::from_secs(15),
            request_delay: Duration::from_millis(750),
            max_variants_per_payload: 4,
            skip_dns_validation: false,
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
    guard_target(consent_manager, target_url).map(|_| ())
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
    pub fn from_response(status_code: u16, headers: HashMap<String, String>, body: &str) -> Self {
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
    pub body_sample_changed: bool,
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
        let body_sample = if body.len() <= BASELINE_SAMPLE_LIMIT {
            body.to_string()
        } else {
            body.chars().take(BASELINE_SAMPLE_LIMIT).collect()
        };
        let body_sample_changed = body_sample != baseline.body_sample;

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
            body_sample_changed,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VaEvidenceKind {
    StatusCode,
    ChallengeHeader,
    BlockedKeyword,
    ChallengeKeyword,
    BaselineDeviation,
    StatusChange,
    HeaderDiff,
    LengthDelta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaEvidence {
    pub kind: VaEvidenceKind,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaProbeEvaluation {
    pub outcome: VaOutcome,
    pub reason: String,
    pub evidence: Vec<VaEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaEvidenceTally {
    pub kind: VaEvidenceKind,
    pub count: usize,
}

fn has_meaningful_body_deviation(diff: &ResponseDiff) -> bool {
    diff.status_changed || diff.significant_length_change || diff.body_sample_changed
}

pub fn classify_outcome(status_code: u16, diff: &ResponseDiff, body: &str) -> VaProbeEvaluation {
    let mut evidence = Vec::new();

    if diff.status_changed {
        evidence.push(VaEvidence {
            kind: VaEvidenceKind::StatusChange,
            detail: format!("status_changed baseline_delta={}", diff.status_changed),
        });
    }

    if diff.length_delta > 0 {
        evidence.push(VaEvidence {
            kind: VaEvidenceKind::LengthDelta,
            detail: format!("length_delta={}", diff.length_delta),
        });
    }

    if !diff.header_differences.is_empty() {
        evidence.push(VaEvidence {
            kind: VaEvidenceKind::HeaderDiff,
            detail: format!("header_diff={}", diff.header_differences.join(",")),
        });
    }

    if status_code == 0 {
        return VaProbeEvaluation {
            outcome: VaOutcome::Error,
            reason: "status=0".to_string(),
            evidence,
        };
    }

    if status_code == 429 || status_code == 403 || status_code == 406 {
        evidence.push(VaEvidence {
            kind: VaEvidenceKind::StatusCode,
            detail: format!("status={status_code}"),
        });
        return VaProbeEvaluation {
            outcome: VaOutcome::Blocked,
            reason: format!("status={status_code}"),
            evidence,
        };
    }

    let challenge_headers = ["cf-ray", "cf-chl-bypass", "x-akamai-transformed"];
    if diff
        .header_differences
        .iter()
        .any(|h| challenge_headers.contains(&h.as_str()))
    {
        evidence.push(VaEvidence {
            kind: VaEvidenceKind::ChallengeHeader,
            detail: "challenge-header".to_string(),
        });
        return VaProbeEvaluation {
            outcome: VaOutcome::Challenge,
            reason: "challenge-header".to_string(),
            evidence,
        };
    }

    let body_lc = body.to_lowercase();
    if has_meaningful_body_deviation(diff)
        && (body_lc.contains("access denied")
            || body_lc.contains("request blocked")
            || body_lc.contains("forbidden"))
    {
        evidence.push(VaEvidence {
            kind: VaEvidenceKind::BlockedKeyword,
            detail: "blocked-keyword".to_string(),
        });
        return VaProbeEvaluation {
            outcome: VaOutcome::Blocked,
            reason: "blocked-keyword".to_string(),
            evidence,
        };
    }

    if has_meaningful_body_deviation(diff)
        && (body_lc.contains("captcha")
            || body_lc.contains("challenge")
            || body_lc.contains("verify"))
    {
        evidence.push(VaEvidence {
            kind: VaEvidenceKind::ChallengeKeyword,
            detail: "challenge-keyword".to_string(),
        });
        return VaProbeEvaluation {
            outcome: VaOutcome::Challenge,
            reason: "challenge-keyword".to_string(),
            evidence,
        };
    }

    if diff.significant_length_change || (diff.status_changed && diff.length_delta > 200) {
        evidence.push(VaEvidence {
            kind: VaEvidenceKind::BaselineDeviation,
            detail: format!(
                "baseline-deviation length_delta={} status_changed={}",
                diff.length_delta, diff.status_changed
            ),
        });
        return VaProbeEvaluation {
            outcome: VaOutcome::Challenge,
            reason: "baseline-deviation".to_string(),
            evidence,
        };
    }

    VaProbeEvaluation {
        outcome: VaOutcome::Allowed,
        reason: "no-anomaly".to_string(),
        evidence,
    }
}

fn score_evidence(evidence: &[VaEvidence]) -> f64 {
    if evidence.is_empty() {
        return 0.0;
    }
    let mut score = 0.0;
    for entry in evidence {
        score += match entry.kind {
            VaEvidenceKind::StatusCode => 1.0,
            VaEvidenceKind::BlockedKeyword => 0.9,
            VaEvidenceKind::ChallengeHeader => 0.8,
            VaEvidenceKind::ChallengeKeyword => 0.7,
            VaEvidenceKind::BaselineDeviation => 0.6,
            VaEvidenceKind::StatusChange => 0.5,
            VaEvidenceKind::HeaderDiff => 0.4,
            VaEvidenceKind::LengthDelta => 0.2,
        };
    }
    (score / evidence.len() as f64).min(1.0)
}

fn compute_evidence_score(results: &[VaResultRecord]) -> f64 {
    if results.is_empty() {
        return 0.0;
    }
    let total: f64 = results
        .iter()
        .map(|record| score_evidence(&record.evidence))
        .sum();
    (total / results.len() as f64).min(1.0)
}

fn summarize_evidence(results: &[VaResultRecord]) -> Vec<VaEvidenceTally> {
    let mut counts: HashMap<VaEvidenceKind, usize> = HashMap::new();
    for record in results {
        for entry in &record.evidence {
            *counts.entry(entry.kind).or_insert(0) += 1;
        }
    }
    let mut tallies: Vec<VaEvidenceTally> = counts
        .into_iter()
        .map(|(kind, count)| VaEvidenceTally { kind, count })
        .collect();
    tallies.sort_by_key(|t| std::cmp::Reverse(t.count));
    tallies
}

/// `passive_waf_confidence` is `None` for every standalone `waf-detect va`
/// run (no passive DetectionResult is ever available there) and `Some(...)`
/// only when called via `--posture --posture-va1`, which already ran
/// passive detection first. When `None`, this function's decision tree is
/// byte-identical to before `PresentNotEnforcing` existed.
pub(crate) fn classify_enforcement(
    summary: &VaResultSummary,
    evidence_score: f64,
    passive_waf_confidence: Option<f64>,
) -> VaEnforcement {
    if summary.total == 0 {
        return VaEnforcement::Inconclusive;
    }

    let blocked_rate = summary.blocked as f64 / summary.total as f64;
    let challenge_rate = summary.challenge as f64 / summary.total as f64;
    let allowed_rate = summary.allowed as f64 / summary.total as f64;

    if blocked_rate >= 0.55 && evidence_score >= 0.6 {
        return VaEnforcement::HardBlock;
    }
    if challenge_rate >= 0.35 && evidence_score >= 0.5 {
        return VaEnforcement::ChallengeGate;
    }
    if blocked_rate + challenge_rate >= 0.4 && evidence_score >= 0.45 {
        return VaEnforcement::SilentFilter;
    }
    if allowed_rate >= 0.8 && evidence_score < 0.35 {
        if passive_waf_confidence.unwrap_or(0.0)
            >= crate::posture::scoring::PASSIVE_WAF_PRESENCE_THRESHOLD
        {
            return VaEnforcement::PresentNotEnforcing;
        }
        return VaEnforcement::NoEnforcement;
    }

    VaEnforcement::Inconclusive
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaResultSummary {
    pub total: usize,
    pub blocked: usize,
    pub challenge: usize,
    pub allowed: usize,
    pub error: usize,
}

impl Default for VaResultSummary {
    fn default() -> Self {
        Self::new()
    }
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
    pub replay_plan: Vec<VaReplayPlanItem>,
    pub summary: VaResultSummary,
    pub enforcement: VaEnforcement,
    pub evidence_score: f64,
    pub evidence_summary: Vec<VaEvidenceTally>,
    pub config: VirtualAdversaryConfig,
    pub results: Vec<VaResultRecord>,
    #[serde(skip, default = "default_instant")]
    pub started_at: std::time::Instant,
    #[serde(skip, default)]
    pub finished_at: Option<std::time::Instant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_bundle: Option<VaReplayBundle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<RunAudit>,
}

fn default_instant() -> std::time::Instant {
    std::time::Instant::now()
}

impl VaRunReport {
    pub fn new(target_url: &str, plan_size: usize, config: VirtualAdversaryConfig) -> Self {
        Self {
            target_url: target_url.to_string(),
            plan_size,
            replay_plan: Vec::new(),
            summary: VaResultSummary::new(),
            enforcement: VaEnforcement::Inconclusive,
            evidence_score: 0.0,
            evidence_summary: Vec::new(),
            config,
            results: Vec::new(),
            started_at: std::time::Instant::now(),
            finished_at: None,
            replay_bundle: None,
            audit: None,
        }
    }

    pub fn finish(&mut self) {
        self.finished_at = Some(std::time::Instant::now());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaEnforcement {
    HardBlock,
    ChallengeGate,
    SilentFilter,
    NoEnforcement,
    /// A WAF was passively detected but 0% of VA1 probes were blocked or
    /// challenged — the WAF is present but not enforcing (monitor/log-only
    /// mode), distinct from no WAF being present at all. Only ever produced
    /// when `classify_enforcement` is called with a passive confidence
    /// value (see `--posture-va1`); standalone `waf-detect va` never
    /// produces this variant.
    PresentNotEnforcing,
    Inconclusive,
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
    pub evidence: Vec<VaEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaReplayPlanItem {
    pub index: usize,
    pub class: String,
    pub channel: String,
    pub description: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// Deterministic replay bundle that captures everything needed to reproduce
/// an exact VA run. Includes a SHA-256 integrity hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaReplayBundle {
    /// Schema version for replay bundle verification
    #[serde(default = "va_replay_bundle_schema_version")]
    pub schema_version: String,
    /// The replay plan items
    pub plan: Vec<VaReplayPlanItem>,
    /// Target URL
    pub target_url: String,
    /// Configuration used for this run
    pub config_fingerprint: String,
    /// Integrity algorithm name
    #[serde(default = "va_replay_bundle_integrity_algorithm")]
    pub integrity_algorithm: String,
    /// SHA-256 hash of the bundle content for integrity verification
    pub integrity_hash: String,
    /// Timestamp when bundle was created
    pub created_at: DateTime<Utc>,
}

impl VaReplayBundle {
    /// Create a replay bundle from a completed VA run report.
    pub fn from_report(report: &VaRunReport) -> Self {
        // Build config fingerprint from the report's config
        let config_fingerprint = format!(
            "tier={},budget={},timeout={}ms,delay={}ms",
            report.config.tier,
            report.config.request_budget,
            report.config.request_timeout.as_millis(),
            report.config.request_delay.as_millis(),
        );

        let created_at = Utc::now();
        let schema_version = va_replay_bundle_schema_version();
        let integrity_algorithm = va_replay_bundle_integrity_algorithm();
        let content_to_hash = replay_bundle_content(
            &schema_version,
            &report.replay_plan,
            &report.target_url,
            &config_fingerprint,
            &created_at,
        );
        let integrity_hash = sha256_hex(&content_to_hash);

        Self {
            schema_version,
            plan: report.replay_plan.clone(),
            target_url: report.target_url.clone(),
            config_fingerprint,
            integrity_algorithm,
            integrity_hash,
            created_at,
        }
    }

    /// Verify the integrity of the bundle.
    pub fn verify_integrity(&self) -> bool {
        if self.schema_version != va_replay_bundle_schema_version() {
            return false;
        }
        if self.integrity_algorithm != va_replay_bundle_integrity_algorithm() {
            return false;
        }
        let content_to_hash = replay_bundle_content(
            &self.schema_version,
            &self.plan,
            &self.target_url,
            &self.config_fingerprint,
            &self.created_at,
        );
        self.integrity_hash == sha256_hex(&content_to_hash)
    }
}

fn va_replay_bundle_schema_version() -> String {
    "va-replay-bundle/v2".to_string()
}

fn va_replay_bundle_integrity_algorithm() -> String {
    "sha256".to_string()
}

fn replay_bundle_content(
    schema_version: &str,
    plan: &[VaReplayPlanItem],
    target_url: &str,
    config_fingerprint: &str,
    created_at: &DateTime<Utc>,
) -> String {
    serde_json::json!({
        "schema_version": schema_version,
        "plan": plan,
        "target_url": target_url,
        "config_fingerprint": config_fingerprint,
        "created_at": created_at,
    })
    .to_string()
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaPayloadEvent {
    pub index: usize,
    pub total: usize,
    pub category: VaPayloadCategory,
    pub payload: String,
    pub outcome: VaOutcome,
    pub reason: String,
    pub evidence: Vec<VaEvidence>,
}

pub fn va_report_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["target_url", "plan_size", "replay_plan", "summary", "enforcement", "evidence_score", "evidence_summary", "config"],
        "properties": {
            "target_url": { "type": "string" },
            "plan_size": { "type": "integer" },
            "replay_plan": { "type": "array" },
            "enforcement": { "type": "string" },
            "evidence_score": { "type": "number" },
            "evidence_summary": { "type": "array" },
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
    fn get_with_payload(
        &self,
        url: &str,
        payload: &VaPayloadVariant,
    ) -> anyhow::Result<VaHttpResponse>;
    fn send(&self, request: &VaHttpRequest) -> anyhow::Result<VaHttpResponse>;
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
        let response = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.client.get(url))
        })?;
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

    fn send(&self, request: &VaHttpRequest) -> anyhow::Result<VaHttpResponse> {
        let response = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                if let Some(ip) = request.resolved_ip {
                    self.client
                        .request_pinned(
                            request.method,
                            &request.url,
                            &request.headers,
                            request.body.as_deref(),
                            ip,
                            None,
                        )
                        .await
                } else {
                    self.client
                        .request(
                            request.method,
                            &request.url,
                            &request.headers,
                            request.body.as_deref(),
                        )
                        .await
                }
            })
        })?;
        Ok(VaHttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaPayloadCategory {
    SqlInjection,
    Xss,
    PathTraversal,
    AdversaryProbe,
    ParserAmbiguity,
    ProtocolMutation,
    EncodingBoundary,
    BehavioralThrottle,
    ResponseFingerprint,
    SemanticDrift,
}

impl From<dae::ProbeClass> for VaPayloadCategory {
    fn from(class: dae::ProbeClass) -> Self {
        match class {
            dae::ProbeClass::ParserAmbiguity => Self::ParserAmbiguity,
            dae::ProbeClass::ProtocolMutation => Self::ProtocolMutation,
            dae::ProbeClass::EncodingBoundary => Self::EncodingBoundary,
            dae::ProbeClass::BehavioralThrottle => Self::BehavioralThrottle,
            dae::ProbeClass::ResponseFingerprint => Self::ResponseFingerprint,
            dae::ProbeClass::SemanticDrift => Self::SemanticDrift,
        }
    }
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

#[derive(Debug, Clone)]
pub struct VaHttpRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    /// Pinned IP address from DNS resolution to prevent TOCTOU attacks.
    /// When set, the HTTP adapter should connect to this IP while preserving
    /// the original Host header.
    pub resolved_ip: Option<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct VaProbePlanItem {
    pub probe: Probe,
    pub request: VaHttpRequest,
    pub display: String,
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

pub fn generate_variants(template: &VaPayloadTemplate, max_variants: u8) -> Vec<VaPayloadVariant> {
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
            .map_err(|err| anyhow!("invalid enforcement test config: {err}"))?;
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

    pub fn with_http_adapter(mut self, http: Box<dyn VaHttpAdapter + Send + Sync>) -> Self {
        self.http = http;
        self
    }

    pub fn plan(&self, target_url: &str) -> Vec<VaProbePlanItem> {
        let probes = probe_catalog_for_tier(self.config.tier).unwrap_or_default();
        let mut plan = Vec::new();

        for probe in probes {
            if let Ok(request) = build_probe_request(&probe, target_url) {
                let display = format!(
                    "{:?}::{:?} {}",
                    probe.class, probe.channel, probe.description
                );
                plan.push(VaProbePlanItem {
                    probe,
                    request,
                    display,
                });
            }
        }

        let max_plan = self.config.request_budget.saturating_sub(1);
        plan.truncate(max_plan as usize);
        plan
    }

    fn build_replay_plan(plan: &[VaProbePlanItem]) -> Vec<VaReplayPlanItem> {
        plan.iter()
            .enumerate()
            .map(|(index, item)| VaReplayPlanItem {
                index: index + 1,
                class: format!("{:?}", item.probe.class),
                channel: format!("{:?}", item.probe.channel),
                description: item.probe.description.to_string(),
                method: item.request.method.to_string(),
                url: item.request.url.clone(),
                headers: item.request.headers.clone(),
                body: item.request.body.clone(),
            })
            .collect()
    }

    fn build_replay_item(target_host: &str, item: &VaReplayPlanItem) -> Result<VaProbePlanItem> {
        let parsed =
            Url::parse(&item.url).or_else(|_| Url::parse(&format!("https://{}", item.url)))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("replay url missing host"))?;
        if host != target_host {
            return Err(anyhow!(
                "replay url host mismatch: expected {target_host}, got {host}"
            ));
        }

        let class = parse_probe_class(&item.class)?;
        let channel = parse_probe_channel(&item.channel)?;
        let method = parse_http_method(&item.method)?;

        let probe = Probe {
            class,
            channel,
            description: "Replay",
            payload: item.description.clone(),
            headers: item.headers.clone(),
            method,
            body: item.body.clone(),
        };
        let request = VaHttpRequest {
            method,
            url: parsed.to_string(),
            headers: item.headers.clone(),
            body: item.body.clone(),
            resolved_ip: None,
        };
        let display = format!(
            "{:?}::{:?} {} {}",
            class, channel, item.method, item.description
        );
        Ok(VaProbePlanItem {
            probe,
            request,
            display,
        })
    }

    fn collect_baseline(&self, target: &ResolvedTarget) -> Result<BaselineRecord> {
        let response = if self.config.skip_dns_validation {
            self.http.get(&target.normalized_url)?
        } else {
            self.http.send(&VaHttpRequest {
                method: "GET",
                url: target.normalized_url.clone(),
                headers: Vec::new(),
                body: None,
                resolved_ip: Some(target.pinned_ip),
            })?
        };
        Ok(BaselineRecord::from_response(
            response.status,
            response.headers,
            &response.body,
        ))
    }

    fn evaluate_probe(
        &self,
        baseline: &BaselineRecord,
        item: &VaProbePlanItem,
        target: &ResolvedTarget,
    ) -> Result<VaProbeEvaluation> {
        let mut pinned_request = item.request.clone();
        if !self.config.skip_dns_validation {
            pinned_request.resolved_ip = Some(target.pinned_ip);
        }

        let response = self.http.send(&pinned_request)?;
        let diff =
            ResponseDiff::compare(baseline, response.status, &response.headers, &response.body);
        let mut evaluation = classify_outcome(response.status, &diff, &response.body);
        evaluation.reason.push_str(&format!(
            " status={} len_delta={} header_diff={}",
            response.status,
            diff.length_delta,
            diff.header_differences.len()
        ));
        Ok(evaluation)
    }

    pub fn run_replay_plan(
        &mut self,
        target_url: &str,
        replay_plan: Vec<VaReplayPlanItem>,
    ) -> Result<VaRunReport> {
        let target = guard_target(&self.consent_manager, target_url)?;
        self.run_replay_plan_with_target(&target, replay_plan)
    }

    pub fn run_replay_plan_with_target(
        &mut self,
        target: &ResolvedTarget,
        replay_plan: Vec<VaReplayPlanItem>,
    ) -> Result<VaRunReport> {
        let started = Instant::now();
        if replay_plan.is_empty() {
            return Err(anyhow!("replay plan is empty"));
        }
        let base = Url::parse(&target.normalized_url)?;
        let target_host = base
            .host_str()
            .ok_or_else(|| anyhow!("target url missing host"))?;

        let required = 1 + replay_plan.len() as u32;
        self.budget.consume(required)?;

        let baseline = self.collect_baseline(target)?;
        let total = replay_plan.len();
        let mut report = VaRunReport::new(&target.normalized_url, total, self.config.clone());
        report.replay_plan = replay_plan.clone();

        for item in replay_plan.into_iter() {
            let plan_item = Self::build_replay_item(target_host, &item)?;
            let evaluation = self.evaluate_probe(&baseline, &plan_item, target)?;
            report.summary.record(evaluation.outcome);
            report.results.push(VaResultRecord {
                payload: plan_item.display,
                category: VaPayloadCategory::from(plan_item.probe.class),
                outcome: evaluation.outcome,
                reason: format!("replay {}", evaluation.reason),
                evidence: evaluation.evidence,
            });
        }

        report.finish();
        report.replay_bundle = Some(VaReplayBundle::from_report(&report));
        crate::perf::record(
            crate::perf::PerfKind::Va,
            started.elapsed().as_millis() as u64,
            crate::perf::PerfMode::Live,
        );
        Ok(report)
    }
    pub fn run_with_events<F, G>(
        &mut self,
        target_url: &str,
        on_progress: F,
        on_event: G,
    ) -> Result<VaRunReport>
    where
        F: FnMut(usize, usize),
        G: FnMut(VaPayloadEvent),
    {
        let target = guard_target(&self.consent_manager, target_url)?;
        self.run_with_events_for_target(&target, on_progress, on_event)
    }

    pub fn run_with_events_for_target<F, G>(
        &mut self,
        target: &ResolvedTarget,
        mut on_progress: F,
        mut on_event: G,
    ) -> Result<VaRunReport>
    where
        F: FnMut(usize, usize),
        G: FnMut(VaPayloadEvent),
    {
        let started = Instant::now();

        let _tier = self.config.tier;
        // Reserve a minimal budget for baseline + one adversarial pass.
        self.budget.consume(2)?;
        let _baseline_wait = self.rate_limiter.record_request();
        let _attack_wait = self.rate_limiter.record_request();

        let baseline = self.collect_baseline(target)?;
        let plan = self.plan(&target.normalized_url);
        let total = plan.len();
        on_progress(0, total);
        let mut report = VaRunReport::new(&target.normalized_url, plan.len(), self.config.clone());
        report.replay_plan = Self::build_replay_plan(&plan);
        for (idx, item) in plan.into_iter().enumerate() {
            let payload_value = item.display.clone();
            let category = VaPayloadCategory::from(item.probe.class);
            let evaluation = self.evaluate_probe(&baseline, &item, target)?;
            report.summary.record(evaluation.outcome);
            report.results.push(VaResultRecord {
                payload: payload_value.clone(),
                category,
                outcome: evaluation.outcome,
                reason: evaluation.reason.clone(),
                evidence: evaluation.evidence.clone(),
            });
            on_event(VaPayloadEvent {
                index: idx + 1,
                total,
                category,
                payload: payload_value,
                outcome: evaluation.outcome,
                reason: evaluation.reason,
                evidence: evaluation.evidence,
            });
            on_progress(idx + 1, total);
        }
        report.evidence_score = compute_evidence_score(&report.results);
        report.evidence_summary = summarize_evidence(&report.results);
        // Standalone VA1 runs (this call site, used by `run_with_events`/
        // `run`/`waf-detect va`) never have passive detection available.
        report.enforcement = classify_enforcement(&report.summary, report.evidence_score, None);
        report.finish();
        report.replay_bundle = Some(VaReplayBundle::from_report(&report));
        crate::perf::record(
            crate::perf::PerfKind::Va,
            started.elapsed().as_millis() as u64,
            crate::perf::PerfMode::Live,
        );
        Ok(report)
    }

    pub fn run_with_progress<F>(&mut self, target_url: &str, on_progress: F) -> Result<VaRunReport>
    where
        F: FnMut(usize, usize),
    {
        self.run_with_events(target_url, on_progress, |_| {})
    }

    pub fn run(&mut self, target_url: &str) -> Result<VaRunReport> {
        self.run_with_events(target_url, |_, _| {}, |_| {})
    }
}

#[cfg(test)]
fn is_ip_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            !ipv4.is_loopback()
                && !ipv4.is_private()
                && !ipv4.is_link_local()
                && !ipv4.is_unspecified()
                && !ipv4.is_broadcast()
        }
        IpAddr::V6(ipv6) => {
            !ipv6.is_loopback()
                && !ipv6.is_unspecified()
                && !ipv6.is_unique_local()
                && !ipv6.is_unicast_link_local()
                && !ipv6.is_multicast()
                // fe80::/10 link-local check (additional guard)
                && (ipv6.segments()[0] & 0xffc0 != 0xfe80)
        }
    }
}

/// Resolve DNS once and validate all IPs are public, returning a pinned IP.
/// This prevents TOCTOU attacks where DNS changes between validation and connection.
#[cfg(test)]
fn resolve_and_validate(url: &str) -> Result<IpAddr> {
    use std::net::ToSocketAddrs;

    let parsed = Url::parse(url).or_else(|_| Url::parse(&format!("https://{url}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("URL missing host"))?;

    // If the host is already an IP literal, validate directly
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_ip_public(&ip) {
            return Err(anyhow!("DNS rebinding guard: {host} is a non-public IP"));
        }
        return Ok(ip);
    }

    let port = parsed.port_or_known_default().unwrap_or(443);
    let addr = format!("{host}:{port}");

    let addrs: Vec<std::net::SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|e| anyhow!("DNS resolution failed for {host}: {e}"))?
        .collect();

    if addrs.is_empty() {
        return Err(anyhow!("DNS resolution returned no addresses for {host}"));
    }

    for a in &addrs {
        if !is_ip_public(&a.ip()) {
            return Err(anyhow!(
                "DNS rebinding guard: {host} resolves to non-public IP {}",
                a.ip()
            ));
        }
    }

    Ok(addrs[0].ip())
}

fn build_probe_request(probe: &Probe, target_url: &str) -> Result<VaHttpRequest> {
    let mut url =
        Url::parse(target_url).or_else(|_| Url::parse(&format!("https://{target_url}")))?;

    match probe.channel {
        dae::ProbeChannel::Path => {
            let path = if probe.payload.starts_with('/') {
                probe.payload.clone()
            } else {
                format!("/{}", probe.payload)
            };
            url.set_path(&path);
        }
        dae::ProbeChannel::Query => {
            url.set_query(Some(&probe.payload));
        }
        _ => {}
    }

    let mut headers = probe.headers.clone();
    if probe.channel == dae::ProbeChannel::Cookie {
        headers.push(("Cookie".to_string(), probe.payload.clone()));
    }

    Ok(VaHttpRequest {
        method: probe.method,
        url: url.to_string(),
        headers,
        body: probe.body.clone(),
        resolved_ip: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use serde::Serialize;
    use std::fs;
    use tempfile::TempDir;

    fn with_temp_home<F>(f: F)
    where
        F: FnOnce(&TempDir),
    {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("WAF_DETECTOR_HOME").ok();
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("WAF_DETECTOR_HOME", temp_dir.path());
        f(&temp_dir);
        if let Some(value) = original_home {
            std::env::set_var("WAF_DETECTOR_HOME", value);
        } else {
            std::env::remove_var("WAF_DETECTOR_HOME");
        }
    }

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

        fn send(&self, _request: &VaHttpRequest) -> anyhow::Result<VaHttpResponse> {
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
        let config = VirtualAdversaryConfig {
            tier: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        let config = VirtualAdversaryConfig {
            tier: 4,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_budget_rejected() {
        let config = VirtualAdversaryConfig {
            request_budget: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[derive(Serialize)]
    struct TestConsentRecord {
        timestamp: DateTime<Utc>,
        terms_version: String,
        authorized_targets: Vec<String>,
        acknowledgment: String,
    }

    fn write_test_consent(temp_dir: impl AsRef<std::path::Path>, targets: Vec<String>) {
        let record = TestConsentRecord {
            timestamp: Utc::now(),
            terms_version: "1.0.0".to_string(),
            authorized_targets: targets,
            acknowledgment: "I AGREE".to_string(),
        };
        let path = temp_dir.as_ref().join(".waf-detector-consent.json");
        let json = serde_json::to_string_pretty(&record).unwrap();
        fs::write(path, json).unwrap();
    }

    #[test]
    fn test_authorized_target_passes() {
        with_temp_home(|temp_dir| {
            write_test_consent(temp_dir, vec!["example.com".to_string()]);

            let consent_manager = ConsentManager::new();
            let result = ensure_consent_and_target(&consent_manager, "https://example.com/path");
            assert!(result.is_ok());
        });
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
        with_temp_home(|temp_dir| {
            write_test_consent(temp_dir, vec!["example.com".to_string()]);

            let config = VirtualAdversaryConfig {
                request_budget: 1,
                skip_dns_validation: true,
                ..Default::default()
            };

            let mut runner = VirtualAdversaryRunner::new(config)
                .unwrap()
                .with_http_adapter(Box::new(StubHttpAdapter));
            let result = runner.run("https://example.com");
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_runner_reports_progress() {
        with_temp_home(|temp_dir| {
            write_test_consent(temp_dir, vec!["example.com".to_string()]);

            let config = VirtualAdversaryConfig {
                request_budget: 6,
                max_variants_per_payload: 1,
                skip_dns_validation: true,
                ..VirtualAdversaryConfig::default()
            };
            let mut runner = VirtualAdversaryRunner::new(config)
                .unwrap()
                .with_http_adapter(Box::new(StubHttpAdapter));

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
        });
    }

    #[test]
    fn test_runner_emits_events() {
        with_temp_home(|temp_dir| {
            write_test_consent(temp_dir, vec!["example.com".to_string()]);

            let config = VirtualAdversaryConfig {
                request_budget: 6,
                max_variants_per_payload: 1,
                skip_dns_validation: true,
                ..VirtualAdversaryConfig::default()
            };
            let mut runner = VirtualAdversaryRunner::new(config)
                .unwrap()
                .with_http_adapter(Box::new(StubHttpAdapter));

            let mut events = Vec::new();
            let report = runner
                .run_with_events(
                    "https://example.com",
                    |_, _| {},
                    |event| {
                        events.push(event);
                    },
                )
                .unwrap();

            assert_eq!(events.len(), report.plan_size);
            assert_eq!(events.first().unwrap().index, 1);
            assert_eq!(events.last().unwrap().index, report.plan_size);
        });
    }

    #[test]
    fn test_runner_allows_valid_run() {
        with_temp_home(|temp_dir| {
            write_test_consent(temp_dir, vec!["example.com".to_string()]);

            let config = VirtualAdversaryConfig {
                request_budget: 2,
                skip_dns_validation: true,
                ..Default::default()
            };

            let mut runner = VirtualAdversaryRunner::new(config)
                .unwrap()
                .with_http_adapter(Box::new(StubHttpAdapter));
            let result = runner.run("https://example.com").unwrap();
            assert!(result.summary.total >= 1);
            assert_eq!(result.summary.blocked, result.summary.total);
            assert_eq!(result.summary.allowed, 0);
        });
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
        assert_eq!(
            record.headers.get("content-type"),
            Some(&"text/html".to_string())
        );
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
    fn test_response_diff_tracks_body_sample_changes() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let diff = ResponseDiff::compare(&baseline, 200, &HashMap::new(), "no");
        assert!(diff.body_sample_changed);
    }

    #[test]
    fn test_classify_outcome_blocked_by_status() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let diff = ResponseDiff::compare(&baseline, 403, &HashMap::new(), "blocked");
        let evaluation = classify_outcome(403, &diff, "blocked");
        assert_eq!(evaluation.outcome, VaOutcome::Blocked);
        assert!(evaluation
            .evidence
            .iter()
            .any(|e| e.kind == VaEvidenceKind::StatusCode));
    }

    #[test]
    fn test_classify_outcome_challenge_by_header() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "123".to_string());
        let diff = ResponseDiff::compare(&baseline, 200, &headers, "ok");
        let evaluation = classify_outcome(200, &diff, "ok");
        assert_eq!(evaluation.outcome, VaOutcome::Challenge);
        assert!(evaluation
            .evidence
            .iter()
            .any(|e| e.kind == VaEvidenceKind::ChallengeHeader));
    }

    #[test]
    fn test_classify_outcome_allowed() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let diff = ResponseDiff::compare(&baseline, 200, &HashMap::new(), "ok");
        let evaluation = classify_outcome(200, &diff, "ok");
        assert_eq!(evaluation.outcome, VaOutcome::Allowed);
    }

    #[test]
    fn test_classify_outcome_challenge_by_body() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let diff = ResponseDiff::compare(&baseline, 200, &HashMap::new(), "captcha required");
        let evaluation = classify_outcome(200, &diff, "captcha required");
        assert_eq!(evaluation.outcome, VaOutcome::Challenge);
        assert!(evaluation
            .evidence
            .iter()
            .any(|e| e.kind == VaEvidenceKind::ChallengeKeyword));
    }

    #[test]
    fn test_classify_outcome_challenge_on_baseline_deviation() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), &"a".repeat(1000));
        let diff = ResponseDiff::compare(&baseline, 500, &HashMap::new(), &"b".repeat(10));
        let evaluation = classify_outcome(500, &diff, "error");
        assert_eq!(evaluation.outcome, VaOutcome::Challenge);
        assert!(evaluation
            .evidence
            .iter()
            .any(|e| e.kind == VaEvidenceKind::BaselineDeviation));
    }

    #[test]
    fn test_classify_outcome_blocked_by_body_keywords() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let diff = ResponseDiff::compare(&baseline, 200, &HashMap::new(), "Access Denied");
        let evaluation = classify_outcome(200, &diff, "Access Denied");
        assert_eq!(evaluation.outcome, VaOutcome::Blocked);
        assert!(evaluation
            .evidence
            .iter()
            .any(|e| e.kind == VaEvidenceKind::BlockedKeyword));
    }

    #[test]
    fn test_classify_outcome_ignores_block_keywords_on_unchanged_body() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "Access Denied");
        let diff = ResponseDiff::compare(&baseline, 200, &HashMap::new(), "Access Denied");
        let evaluation = classify_outcome(200, &diff, "Access Denied");
        assert_eq!(evaluation.outcome, VaOutcome::Allowed);
    }

    #[test]
    fn test_classify_outcome_ignores_challenge_keywords_on_unchanged_body() {
        let baseline = BaselineRecord::from_response(200, HashMap::new(), "verify account");
        let diff = ResponseDiff::compare(&baseline, 200, &HashMap::new(), "verify account");
        let evaluation = classify_outcome(200, &diff, "verify account");
        assert_eq!(evaluation.outcome, VaOutcome::Allowed);
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
        let mut report =
            VaRunReport::new("https://example.com", 5, VirtualAdversaryConfig::default());
        assert_eq!(report.target_url, "https://example.com");
        assert_eq!(report.plan_size, 5);
        assert_eq!(report.enforcement, VaEnforcement::Inconclusive);
        assert_eq!(report.evidence_score, 0.0);
        assert!(report.evidence_summary.is_empty());
        assert!(report.finished_at.is_none());
        report.finish();
        assert!(report.finished_at.is_some());
    }

    #[test]
    fn test_evidence_score_weights() {
        let records = vec![VaResultRecord {
            payload: "probe".to_string(),
            category: VaPayloadCategory::AdversaryProbe,
            outcome: VaOutcome::Blocked,
            reason: "status=403".to_string(),
            evidence: vec![
                VaEvidence {
                    kind: VaEvidenceKind::StatusCode,
                    detail: "status=403".to_string(),
                },
                VaEvidence {
                    kind: VaEvidenceKind::BlockedKeyword,
                    detail: "blocked-keyword".to_string(),
                },
            ],
        }];
        let score = compute_evidence_score(&records);
        assert!(score >= 0.9);
    }

    #[test]
    fn test_enforcement_classification_hard_block() {
        let summary = VaResultSummary {
            total: 10,
            blocked: 6,
            challenge: 1,
            allowed: 3,
            error: 0,
        };
        let enforcement = classify_enforcement(&summary, 0.7, None);
        assert_eq!(enforcement, VaEnforcement::HardBlock);
    }

    #[test]
    fn test_enforcement_classification_no_enforcement() {
        let summary = VaResultSummary {
            total: 10,
            blocked: 1,
            challenge: 1,
            allowed: 8,
            error: 0,
        };
        let enforcement = classify_enforcement(&summary, 0.2, None);
        assert_eq!(enforcement, VaEnforcement::NoEnforcement);
    }

    #[test]
    fn test_enforcement_classification_no_enforcement_with_no_passive_confidence_is_unchanged() {
        // Regression guard: standalone `waf-detect va` never has a passive
        // DetectionResult, so it always passes None here. This must produce
        // the exact same result as before PresentNotEnforcing existed.
        let summary = VaResultSummary {
            total: 10,
            blocked: 0,
            challenge: 0,
            allowed: 10,
            error: 0,
        };
        let enforcement = classify_enforcement(&summary, 0.1, None);
        assert_eq!(enforcement, VaEnforcement::NoEnforcement);
    }

    #[test]
    fn test_enforcement_classification_present_not_enforcing_when_passive_confidence_high() {
        let summary = VaResultSummary {
            total: 10,
            blocked: 0,
            challenge: 0,
            allowed: 10,
            error: 0,
        };
        let enforcement = classify_enforcement(&summary, 0.1, Some(0.9));
        assert_eq!(enforcement, VaEnforcement::PresentNotEnforcing);
    }

    #[test]
    fn test_enforcement_classification_stays_no_enforcement_below_threshold() {
        let summary = VaResultSummary {
            total: 10,
            blocked: 0,
            challenge: 0,
            allowed: 10,
            error: 0,
        };
        // Below PASSIVE_WAF_PRESENCE_THRESHOLD (0.5) -> not confident enough
        // to call this "present", stays NoEnforcement.
        let enforcement = classify_enforcement(&summary, 0.1, Some(0.3));
        assert_eq!(enforcement, VaEnforcement::NoEnforcement);
    }

    #[test]
    fn test_summarize_evidence_counts() {
        let records = vec![
            VaResultRecord {
                payload: "probe1".to_string(),
                category: VaPayloadCategory::AdversaryProbe,
                outcome: VaOutcome::Blocked,
                reason: "status=403".to_string(),
                evidence: vec![
                    VaEvidence {
                        kind: VaEvidenceKind::StatusCode,
                        detail: "status=403".to_string(),
                    },
                    VaEvidence {
                        kind: VaEvidenceKind::HeaderDiff,
                        detail: "header_diff=cf-ray".to_string(),
                    },
                ],
            },
            VaResultRecord {
                payload: "probe2".to_string(),
                category: VaPayloadCategory::AdversaryProbe,
                outcome: VaOutcome::Challenge,
                reason: "challenge-header".to_string(),
                evidence: vec![VaEvidence {
                    kind: VaEvidenceKind::StatusCode,
                    detail: "status=403".to_string(),
                }],
            },
        ];

        let summary = summarize_evidence(&records);
        let status_count = summary
            .iter()
            .find(|entry| entry.kind == VaEvidenceKind::StatusCode)
            .map(|entry| entry.count)
            .unwrap_or(0);
        let header_count = summary
            .iter()
            .find(|entry| entry.kind == VaEvidenceKind::HeaderDiff)
            .map(|entry| entry.count)
            .unwrap_or(0);

        assert_eq!(status_count, 2);
        assert_eq!(header_count, 1);
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
        let plan = runner.plan("https://example.com");
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
            .with_http_adapter(Box::new(StubHttpAdapter));
        let plan = runner.plan("https://example.com");
        assert!(!plan.is_empty());
        assert!(plan.len() >= 4);
    }

    #[test]
    fn test_runner_uses_http_adapter() {
        with_temp_home(|temp_dir| {
            write_test_consent(temp_dir, vec!["example.com".to_string()]);

            let config = VirtualAdversaryConfig {
                request_budget: 2,
                skip_dns_validation: true,
                ..Default::default()
            };
            let mut runner = VirtualAdversaryRunner::new(config)
                .unwrap()
                .with_http_adapter(Box::new(StubHttpAdapter));

            let result = runner.run("https://example.com").unwrap();
            assert_eq!(result.target_url, "https://example.com/");
        });
    }

    #[test]
    fn test_collect_baseline_from_http_adapter() {
        let config = VirtualAdversaryConfig {
            request_budget: 2,
            skip_dns_validation: true,
            ..Default::default()
        };
        let runner = VirtualAdversaryRunner::new(config)
            .unwrap()
            .with_http_adapter(Box::new(StubHttpAdapter));
        let target = crate::active::ResolvedTarget {
            original_url: "https://example.com".to_string(),
            normalized_url: "https://example.com/".to_string(),
            host: "example.com".to_string(),
            port: 443,
            registered_target: crate::effectiveness::consent::ScopeTarget {
                host: "example.com".to_string(),
                class: crate::effectiveness::consent::TargetClass::Public,
            },
            active_target_profile: crate::active::ActiveTargetProfile::Public,
            resolved_ips: vec!["93.184.216.34".parse().unwrap()],
            pinned_ip: "93.184.216.34".parse().unwrap(),
        };

        let baseline = runner.collect_baseline(&target).unwrap();
        assert_eq!(baseline.status_code, 200);
        assert_eq!(baseline.body_sample, "ok");
    }

    #[test]
    fn test_evaluate_payload_classifies_outcome() {
        let config = VirtualAdversaryConfig {
            request_budget: 2,
            skip_dns_validation: true,
            ..Default::default()
        };
        let runner = VirtualAdversaryRunner::new(config)
            .unwrap()
            .with_http_adapter(Box::new(StubHttpAdapter));

        let baseline = BaselineRecord::from_response(200, HashMap::new(), "ok");
        let probe = dae::Probe {
            class: dae::ProbeClass::SemanticDrift,
            channel: dae::ProbeChannel::Query,
            description: "probe",
            payload: "q=drift".to_string(),
            headers: Vec::new(),
            method: "GET",
            body: None,
        };
        let request = build_probe_request(&probe, "https://example.com").unwrap();
        let item = VaProbePlanItem {
            probe,
            request,
            display: "SemanticDrift::Query probe".to_string(),
        };
        let target = crate::active::ResolvedTarget {
            original_url: "https://example.com".to_string(),
            normalized_url: "https://example.com/".to_string(),
            host: "example.com".to_string(),
            port: 443,
            registered_target: crate::effectiveness::consent::ScopeTarget {
                host: "example.com".to_string(),
                class: crate::effectiveness::consent::TargetClass::Public,
            },
            active_target_profile: crate::active::ActiveTargetProfile::Public,
            resolved_ips: vec!["93.184.216.34".parse().unwrap()],
            pinned_ip: "93.184.216.34".parse().unwrap(),
        };

        let evaluation = runner.evaluate_probe(&baseline, &item, &target).unwrap();
        assert_eq!(evaluation.outcome, VaOutcome::Blocked);
    }

    #[test]
    fn test_runner_reports_plan_summary() {
        with_temp_home(|temp_dir| {
            write_test_consent(temp_dir, vec!["example.com".to_string()]);

            let config = VirtualAdversaryConfig {
                tier: 1,
                request_budget: 5,
                max_variants_per_payload: 1,
                skip_dns_validation: true,
                ..Default::default()
            };

            let mut runner = VirtualAdversaryRunner::new(config)
                .unwrap()
                .with_http_adapter(Box::new(StubHttpAdapter));

            let report = runner.run("https://example.com").unwrap();
            assert_eq!(report.summary.total, report.plan_size);
            assert_eq!(report.summary.blocked, report.plan_size);
            assert_eq!(report.results.len(), report.plan_size);
        });
    }

    #[test]
    fn test_va_report_serializes_to_json() {
        let report = VaRunReport::new("https://example.com", 2, VirtualAdversaryConfig::default());
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("plan_size"));
        assert!(json.contains("replay_plan"));
    }

    #[test]
    fn test_va_report_schema_has_required_keys() {
        let schema = va_report_schema();
        let required = schema.get("required").and_then(|v| v.as_array()).unwrap();
        let required_keys: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required_keys.contains(&"target_url"));
        assert!(required_keys.contains(&"plan_size"));
        assert!(required_keys.contains(&"replay_plan"));
        assert!(required_keys.contains(&"summary"));
        assert!(required_keys.contains(&"enforcement"));
        assert!(required_keys.contains(&"evidence_score"));
        assert!(required_keys.contains(&"evidence_summary"));
        assert!(required_keys.contains(&"config"));
    }

    #[test]
    fn test_va_report_replay_plan_matches_plan_size() {
        with_temp_home(|temp_dir| {
            write_test_consent(temp_dir, vec!["93.184.216.34".to_string()]);

            let config = VirtualAdversaryConfig {
                tier: 1,
                request_budget: 8,
                max_variants_per_payload: 1,
                skip_dns_validation: true,
                ..Default::default()
            };
            let mut runner = VirtualAdversaryRunner::new(config)
                .unwrap()
                .with_http_adapter(Box::new(StubHttpAdapter));
            let report = runner.run("https://93.184.216.34").unwrap();
            assert_eq!(report.replay_plan.len(), report.plan_size);
            let first = report.replay_plan.first().unwrap();
            assert!(!first.method.is_empty());
            assert!(first.url.contains("93.184.216.34"));
        });
    }

    #[test]
    fn test_parse_probe_class_channel() {
        assert!(parse_probe_class("SemanticDrift").is_ok());
        assert!(parse_probe_channel("Query").is_ok());
        assert!(parse_probe_class("Unknown").is_err());
        assert!(parse_probe_channel("Nope").is_err());
    }

    #[test]
    fn test_replay_plan_rejects_host_mismatch() {
        with_temp_home(|temp_dir| {
            write_test_consent(temp_dir, vec!["93.184.216.34".to_string()]);
            let config = VirtualAdversaryConfig {
                request_budget: 3,
                skip_dns_validation: true,
                ..Default::default()
            };
            let mut runner = VirtualAdversaryRunner::new(config)
                .unwrap()
                .with_http_adapter(Box::new(StubHttpAdapter));
            let plan = vec![VaReplayPlanItem {
                index: 1,
                class: "SemanticDrift".to_string(),
                channel: "Query".to_string(),
                description: "replay".to_string(),
                method: "GET".to_string(),
                url: "https://evil.example.com/test".to_string(),
                headers: Vec::new(),
                body: None,
            }];
            let result = runner.run_replay_plan("https://93.184.216.34", plan);
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_replay_plan_runs() {
        with_temp_home(|temp_dir| {
            write_test_consent(temp_dir, vec!["93.184.216.34".to_string()]);
            let config = VirtualAdversaryConfig {
                request_budget: 3,
                skip_dns_validation: true,
                ..Default::default()
            };
            let mut runner = VirtualAdversaryRunner::new(config)
                .unwrap()
                .with_http_adapter(Box::new(StubHttpAdapter));
            let plan = vec![VaReplayPlanItem {
                index: 1,
                class: "SemanticDrift".to_string(),
                channel: "Query".to_string(),
                description: "replay".to_string(),
                method: "GET".to_string(),
                url: "https://93.184.216.34/test".to_string(),
                headers: Vec::new(),
                body: None,
            }];
            let report = runner
                .run_replay_plan("https://93.184.216.34", plan)
                .unwrap();
            assert_eq!(report.plan_size, 1);
            assert_eq!(report.results.len(), 1);
        });
    }

    #[test]
    fn test_replay_plan_rejects_private_ip() {
        with_temp_home(|temp_dir| {
            write_test_consent(temp_dir, vec!["127.0.0.1".to_string()]);
            let config = VirtualAdversaryConfig {
                request_budget: 1,
                skip_dns_validation: true,
                ..Default::default()
            };
            let mut runner = VirtualAdversaryRunner::new(config)
                .unwrap()
                .with_http_adapter(Box::new(StubHttpAdapter));
            let plan = vec![VaReplayPlanItem {
                index: 1,
                class: "SemanticDrift".to_string(),
                channel: "Query".to_string(),
                description: "replay".to_string(),
                method: "GET".to_string(),
                url: "https://127.0.0.1/test".to_string(),
                headers: Vec::new(),
                body: None,
            }];
            let result = runner.run_replay_plan("https://127.0.0.1", plan);
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_is_ip_public_rejects_loopback() {
        let ip = "127.0.0.1".parse::<IpAddr>().unwrap();
        assert!(!is_ip_public(&ip));
    }

    #[test]
    fn test_is_ip_public_rejects_private_10() {
        let ip = "10.0.0.1".parse::<IpAddr>().unwrap();
        assert!(!is_ip_public(&ip));
    }

    #[test]
    fn test_is_ip_public_rejects_private_192() {
        let ip = "192.168.1.1".parse::<IpAddr>().unwrap();
        assert!(!is_ip_public(&ip));
    }

    #[test]
    fn test_is_ip_public_rejects_private_172() {
        let ip = "172.16.0.1".parse::<IpAddr>().unwrap();
        assert!(!is_ip_public(&ip));
    }

    #[test]
    fn test_is_ip_public_accepts_public_google() {
        let ip = "8.8.8.8".parse::<IpAddr>().unwrap();
        assert!(is_ip_public(&ip));
    }

    #[test]
    fn test_is_ip_public_accepts_public_cloudflare() {
        let ip = "1.1.1.1".parse::<IpAddr>().unwrap();
        assert!(is_ip_public(&ip));
    }

    #[test]
    fn test_is_ip_public_rejects_ipv6_loopback() {
        let ip = "::1".parse::<IpAddr>().unwrap();
        assert!(!is_ip_public(&ip));
    }

    #[test]
    fn test_is_ip_public_rejects_ipv6_link_local() {
        let ip = "fe80::1".parse::<IpAddr>().unwrap();
        assert!(!is_ip_public(&ip));
    }

    #[test]
    fn test_resolve_and_validate_rejects_localhost() {
        let result = resolve_and_validate("https://localhost/test");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("DNS rebinding guard") || err.contains("non-public IP"));
    }

    #[test]
    fn test_resolve_and_validate_rejects_127() {
        let result = resolve_and_validate("https://127.0.0.1/test");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("DNS rebinding guard") || err.contains("non-public IP"));
    }

    #[test]
    fn test_resolve_and_validate_rejects_private_10() {
        let result = resolve_and_validate("https://10.0.0.1/test");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("DNS rebinding guard") || err.contains("non-public IP"));
    }

    #[test]
    fn replay_bundle_integrity_passes() {
        let report = VaRunReport::new("https://example.com", 2, VirtualAdversaryConfig::default());
        let bundle = VaReplayBundle::from_report(&report);
        assert!(bundle.verify_integrity());
        assert!(!bundle.integrity_hash.is_empty());
        assert_eq!(bundle.target_url, "https://example.com");
    }

    #[test]
    fn replay_bundle_integrity_fails_on_tamper() {
        let report = VaRunReport::new("https://example.com", 2, VirtualAdversaryConfig::default());
        let mut bundle = VaReplayBundle::from_report(&report);
        bundle.target_url = "https://tampered.com".to_string();
        assert!(!bundle.verify_integrity());
    }
}
