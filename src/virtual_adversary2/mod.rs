//! Virtual Adversary 2.0 (VA2)
//!
//! Behavioral WAF profiling with deterministic, replayable campaigns.

pub mod fixture;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use url::Url;

use crate::effectiveness::consent::ConsentManager;
use crate::http::HttpClient;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Va2Phase {
    Baseline,
    ProtocolVariance,
    StateEscalation,
    BehavioralPressure,
    ChallengeInteraction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Va2StepKind {
    Baseline,
    Equivalence,
    StateMutation,
    RateRamp,
    ChallengeProbe,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Va2ProbeChannel {
    Path,
    Query,
    Header,
    Body,
    Method,
}

impl std::fmt::Display for Va2ProbeChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Va2ProbeChannel::Path => write!(f, "path"),
            Va2ProbeChannel::Query => write!(f, "query"),
            Va2ProbeChannel::Header => write!(f, "header"),
            Va2ProbeChannel::Body => write!(f, "body"),
            Va2ProbeChannel::Method => write!(f, "method"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Va2CampaignStep {
    pub id: u32,
    pub phase: Va2Phase,
    pub kind: Va2StepKind,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub delay_ms: u64,
    pub notes: String,
    pub expected_equivalence: Option<u32>,
    /// Which request channel this step perturbs (None for non-probe steps)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<Va2ProbeChannel>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Va2CampaignPlan {
    pub version: String,
    pub seed: u64,
    pub target_url: String,
    pub phases: Vec<Va2Phase>,
    pub budget: u32,
    pub steps: Vec<Va2CampaignStep>,
}

#[derive(Debug, Clone)]
pub struct Va2HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Va2HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

#[async_trait]
pub trait Va2HttpAdapter: Send + Sync {
    async fn send(&self, request: &Va2HttpRequest) -> anyhow::Result<Va2HttpResponse>;
}

pub struct RealVa2HttpAdapter {
    client: HttpClient,
}

impl RealVa2HttpAdapter {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            client: HttpClient::new()?,
        })
    }
}

#[async_trait]
impl Va2HttpAdapter for RealVa2HttpAdapter {
    async fn send(&self, request: &Va2HttpRequest) -> anyhow::Result<Va2HttpResponse> {
        let response = self
            .client
            .request(
                &request.method,
                &request.url,
                &request.headers,
                request.body.as_deref(),
            )
            .await?;
        Ok(Va2HttpResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Va2RunResult {
    pub step_id: u32,
    pub phase: Va2Phase,
    pub kind: Va2StepKind,
    pub status: Option<u16>,
    pub duration_ms: u128,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Va2BaselineSummary {
    pub status: Option<u16>,
    pub header_count: usize,
    pub body_length: usize,
    pub sample: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Va2NormalizationVariance {
    pub baseline_status: Option<u16>,
    pub max_status_delta: u16,
    pub avg_length_delta: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Va2StateSummary {
    pub deviations: usize,
    pub set_cookie: usize,
    pub status_change: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Va2ChallengeKind {
    HardBlock,
    Captcha,
    JsChallenge,
    CookieGate,
}

/// Typed challenge taxonomy for VA2 probe outcomes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    /// JavaScript challenge page (Cloudflare JS challenge, Akamai bot manager)
    JavaScriptChallenge,
    /// CAPTCHA or interactive challenge (reCAPTCHA, hCaptcha, Turnstile)
    CaptchaChallenge,
    /// Cookie-based bot verification gate
    CookieGate,
    /// Rate limit soft block (429 with retry-after)
    RateLimitSoftBlock,
}

/// A detected challenge with confidence score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedChallenge {
    pub challenge_type: ChallengeType,
    /// Confidence that this challenge type is correct (0.0 - 1.0)
    pub confidence: f64,
    /// Evidence description
    pub evidence: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Va2ChallengeProfile {
    pub total: usize,
    pub hard_blocks: usize,
    pub captcha: usize,
    pub js_challenge: usize,
    pub cookie_gate: usize,
    #[serde(default)]
    pub detected_challenges: Vec<DetectedChallenge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Va2ThrottleCurve {
    pub samples: Vec<(u32, u128)>,
    pub slope_ms_per_step: f64,
    pub triggered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Va2DifferentialResult {
    pub step_id: u32,
    pub baseline_step_id: u32,
    pub status_delta: u16,
    pub body_length_pct_change: f64,
    #[serde(default)]
    pub header_mutation_count: usize,
    #[serde(default)]
    pub timing_delta_ms: i128,
    /// WAF discriminated between baseline and this variant
    pub discriminated: bool,
    #[serde(default)]
    pub outcome: Option<PairedControlOutcome>,
    /// Which channel this differential result corresponds to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<Va2ProbeChannel>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Va2ChannelCoverage {
    /// Per-channel discrimination rate (0.0 = no discrimination, 1.0 = all probes discriminated)
    pub channels: HashMap<Va2ProbeChannel, f64>,
    /// Channels where WAF showed zero discrimination
    pub blind_spots: Vec<Va2ProbeChannel>,
    /// Overall multi-channel coverage score (0.0-1.0)
    pub coverage_score: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PairedControlOutcome {
    Detected,
    NotDetected,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedControlSignal {
    pub step_id: u32,
    pub baseline_step_id: u32,
    pub vector: String,
    pub outcome: PairedControlOutcome,
    pub status_delta: u16,
    pub body_length_pct_change: f64,
    pub header_mutation_count: usize,
    pub timing_delta_ms: i128,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PairedControlSummary {
    #[serde(default)]
    pub signals: Vec<PairedControlSignal>,
    #[serde(default)]
    pub coverage_by_vector: HashMap<String, f64>,
    pub executed_pairs: usize,
    pub detected_pairs: usize,
    pub not_detected_pairs: usize,
    pub inconclusive_pairs: usize,
    pub pair_cap: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_stop_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Va2WbfSummary {
    pub normalization_score: f64,
    pub statefulness_score: f64,
    pub challenge_score: f64,
    pub throttle_score: f64,
    pub differential_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Va2PmiScore {
    pub score: f64,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Va2RunReport {
    pub target_url: String,
    pub plan: Va2CampaignPlan,
    pub results: Vec<Va2RunResult>,
    pub baseline: Va2BaselineSummary,
    pub normalization: Option<Va2NormalizationVariance>,
    pub statefulness: Option<Va2StateSummary>,
    pub challenge: Option<Va2ChallengeProfile>,
    pub throttle: Option<Va2ThrottleCurve>,
    pub wbf: Va2WbfSummary,
    pub pmi: Va2PmiScore,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub differential: Vec<Va2DifferentialResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_coverage: Option<Va2ChannelCoverage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_control: Option<PairedControlSummary>,
}

pub struct Va2Runner {
    consent_manager: ConsentManager,
    http: Box<dyn Va2HttpAdapter + Send + Sync>,
}

impl Va2Runner {
    pub fn new() -> Result<Self> {
        Ok(Self {
            consent_manager: ConsentManager::new(),
            http: Box::new(RealVa2HttpAdapter::new()?),
        })
    }

    pub fn with_adapter(adapter: Box<dyn Va2HttpAdapter + Send + Sync>) -> Result<Self> {
        Ok(Self {
            consent_manager: ConsentManager::new(),
            http: adapter,
        })
    }

    pub async fn run_plan(&self, plan: Va2CampaignPlan) -> Result<Va2RunReport> {
        let run_started = Instant::now();
        ensure_va2_consent_and_target(&self.consent_manager, &plan.target_url)?;

        let mut results = Vec::with_capacity(plan.steps.len());
        let mut baseline_samples = Vec::new();
        let mut variance_samples: Vec<(u16, usize)> = Vec::new();
        let mut baseline_responses: HashMap<u32, Va2HttpResponse> = HashMap::new();
        let mut baseline_durations: HashMap<u32, u128> = HashMap::new();
        let mut differential_results: Vec<Va2DifferentialResult> = Vec::new();
        let mut state_summary = Va2StateSummary::default();
        let mut challenge_profile = Va2ChallengeProfile::default();
        let mut throttle_samples: Vec<u128> = Vec::new();
        let mut throttle_step = 0u32;
        let default_pair_cap = (plan.budget as usize).clamp(1usize, 12usize);
        let pair_cap = std::env::var("WAF_DETECTOR_VA2_PAIR_CAP")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(default_pair_cap);
        let mut early_stop_reason: Option<String> = None;
        let mut rate_history: Vec<f64> = Vec::new();
        for step in &plan.steps {
            if step.phase == Va2Phase::ProtocolVariance && step.expected_equivalence.is_some() {
                if differential_results.len() >= pair_cap {
                    results.push(Va2RunResult {
                        step_id: step.id,
                        phase: step.phase,
                        kind: step.kind,
                        status: None,
                        duration_ms: 0,
                        error: Some("skipped: pair cap reached".to_string()),
                    });
                    continue;
                }
                if let Some(reason) = &early_stop_reason {
                    results.push(Va2RunResult {
                        step_id: step.id,
                        phase: step.phase,
                        kind: step.kind,
                        status: None,
                        duration_ms: 0,
                        error: Some(format!("skipped: {reason}")),
                    });
                    continue;
                }
            }
            if step.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(step.delay_ms)).await;
            }
            let request = build_va2_request(&plan.target_url, step)?;
            let started = Instant::now();
            let response = self.http.send(&request).await;
            let duration = started.elapsed().as_millis();
            match response {
                Ok(resp) => {
                    if step.phase == Va2Phase::Baseline {
                        baseline_responses.insert(step.id, resp.clone());
                        baseline_samples.push(resp.clone());
                    }
                    if step.phase == Va2Phase::ProtocolVariance {
                        variance_samples.push((resp.status, resp.body.len()));
                        if step.expected_equivalence.is_none() {
                            // Control step — store for paired comparison
                            baseline_responses.insert(step.id, resp.clone());
                            baseline_durations.insert(step.id, duration);
                        }
                        if let Some(ref_id) = step.expected_equivalence {
                            if let Some(ref_resp) = baseline_responses.get(&ref_id) {
                                differential_results.push(compute_differential(
                                    step.id,
                                    ref_id,
                                    ref_resp,
                                    &resp,
                                    step.channel,
                                    baseline_durations.get(&ref_id).copied().unwrap_or(0),
                                    duration,
                                ));
                                let discriminated = differential_results
                                    .iter()
                                    .filter(|diff| diff.discriminated)
                                    .count();
                                let rate = discriminated as f64 / differential_results.len() as f64;
                                rate_history.push(rate);
                                if differential_results.len() >= 6
                                    && early_stop_reason.is_none()
                                    && has_confidence_converged(&rate_history)
                                {
                                    early_stop_reason = Some(format!(
                                        "confidence converged after {} pairs",
                                        differential_results.len()
                                    ));
                                }
                            }
                        }
                    }
                    if step.phase == Va2Phase::StateEscalation {
                        update_statefulness(&mut state_summary, &resp, baseline_samples.first());
                    }
                    if step.phase == Va2Phase::ChallengeInteraction {
                        update_challenge_profile(&mut challenge_profile, &resp);
                    }
                    if step.phase == Va2Phase::BehavioralPressure {
                        throttle_samples.push(duration);
                        throttle_step = throttle_step.saturating_add(1);
                    }
                    results.push(Va2RunResult {
                        step_id: step.id,
                        phase: step.phase,
                        kind: step.kind,
                        status: Some(resp.status),
                        duration_ms: duration,
                        error: None,
                    });
                }
                Err(err) => results.push(Va2RunResult {
                    step_id: step.id,
                    phase: step.phase,
                    kind: step.kind,
                    status: None,
                    duration_ms: duration,
                    error: Some(err.to_string()),
                }),
            }
        }

        let baseline = summarize_baseline(&baseline_samples);
        let normalization = if variance_samples.is_empty() {
            None
        } else {
            Some(compute_normalization_variance(
                baseline.status,
                &variance_samples,
            ))
        };
        let throttle = if throttle_samples.is_empty() {
            None
        } else {
            Some(compute_throttle_curve(&throttle_samples))
        };
        let wbf = compute_wbf(
            &normalization,
            &state_summary,
            &challenge_profile,
            &throttle,
            &differential_results,
        );
        let pmi = compute_pmi(&wbf);
        let channel_coverage = compute_channel_coverage(&differential_results);
        let paired_control = build_paired_control_summary(
            &differential_results,
            channel_coverage.as_ref(),
            pair_cap,
            early_stop_reason,
        );

        let perf_mode = if std::env::var("WAF_DETECTOR_FIXTURE_MODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            crate::perf::PerfMode::Fixture
        } else {
            crate::perf::PerfMode::Live
        };
        crate::perf::record(
            crate::perf::PerfKind::Va2,
            run_started.elapsed().as_millis() as u64,
            perf_mode,
        );

        Ok(Va2RunReport {
            target_url: plan.target_url.clone(),
            plan,
            results,
            baseline,
            normalization,
            statefulness: if state_summary.deviations == 0 {
                None
            } else {
                Some(state_summary)
            },
            challenge: if challenge_profile.total == 0 {
                None
            } else {
                Some(challenge_profile)
            },
            throttle,
            wbf,
            pmi,
            differential: differential_results,
            channel_coverage,
            paired_control,
        })
    }
}

fn ensure_va2_consent_and_target(consent_manager: &ConsentManager, target_url: &str) -> Result<()> {
    if !consent_manager.has_valid_consent()? {
        return Err(anyhow!(
            "Consent is required before running Virtual Adversary 2.0 tests"
        ));
    }
    if !consent_manager.is_target_allowed(target_url)? {
        return Err(anyhow!(
            "Target is not authorized for Virtual Adversary 2.0 testing"
        ));
    }
    Ok(())
}

fn build_va2_request(target_url: &str, step: &Va2CampaignStep) -> Result<Va2HttpRequest> {
    let mut url = Url::parse(target_url).map_err(|_| {
        anyhow!("Could not parse '{}' as a URL. Make sure it starts with https:// and contains a valid domain.", target_url)
    })?;
    url.set_path(&step.path);
    if let Some(query) = &step.query {
        url.set_query(Some(query));
    } else {
        url.set_query(None);
    }

    let headers = step
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    Ok(Va2HttpRequest {
        method: step.method.clone(),
        url: url.to_string(),
        headers,
        body: step.body.clone(),
    })
}

fn summarize_baseline(samples: &[Va2HttpResponse]) -> Va2BaselineSummary {
    if samples.is_empty() {
        return Va2BaselineSummary::default();
    }
    let first = &samples[0];
    let sample = first.body.chars().take(120).collect::<String>();
    Va2BaselineSummary {
        status: Some(first.status),
        header_count: first.headers.len(),
        body_length: first.body.len(),
        sample,
    }
}

fn compute_normalization_variance(
    baseline_status: Option<u16>,
    samples: &[(u16, usize)],
) -> Va2NormalizationVariance {
    let baseline_code = baseline_status.unwrap_or(200);
    let mut max_delta = 0u16;
    let mut total_len_delta = 0f64;
    for (status, len) in samples {
        let delta = status.abs_diff(baseline_code);
        if delta > max_delta {
            max_delta = delta;
        }
        let baseline_len = samples.first().map(|(_, l)| *l).unwrap_or(0);
        total_len_delta += (*len as f64 - baseline_len as f64).abs();
    }
    let avg_len_delta = if samples.is_empty() {
        0.0
    } else {
        total_len_delta / samples.len() as f64
    };
    Va2NormalizationVariance {
        baseline_status,
        max_status_delta: max_delta,
        avg_length_delta: avg_len_delta,
    }
}

fn compute_differential(
    step_id: u32,
    baseline_id: u32,
    baseline: &Va2HttpResponse,
    variant: &Va2HttpResponse,
    channel: Option<Va2ProbeChannel>,
    baseline_duration_ms: u128,
    variant_duration_ms: u128,
) -> Va2DifferentialResult {
    let status_delta = baseline.status.abs_diff(variant.status);
    let baseline_len = baseline.body.len() as f64;
    let variant_len = variant.body.len() as f64;
    let header_mutation_count = count_header_mutations(&baseline.headers, &variant.headers);
    let timing_delta_ms = variant_duration_ms as i128 - baseline_duration_ms as i128;
    let pct_change = if baseline_len > 0.0 {
        ((variant_len - baseline_len) / baseline_len).abs()
    } else if variant_len > 0.0 {
        1.0
    } else {
        0.0
    };
    // Discrimination: status changed OR body length shifted >15% OR header set changed OR timing shifted.
    let discriminated = status_delta > 0
        || pct_change > 0.15
        || header_mutation_count > 0
        || timing_delta_ms.abs() > 200;
    let outcome = if baseline.status >= 400 && variant.status >= 400 && status_delta == 0 {
        Some(PairedControlOutcome::Inconclusive)
    } else if discriminated {
        Some(PairedControlOutcome::Detected)
    } else {
        Some(PairedControlOutcome::NotDetected)
    };
    Va2DifferentialResult {
        step_id,
        baseline_step_id: baseline_id,
        status_delta,
        body_length_pct_change: pct_change,
        header_mutation_count,
        timing_delta_ms,
        discriminated,
        outcome,
        channel,
    }
}

fn count_header_mutations(
    baseline: &HashMap<String, String>,
    variant: &HashMap<String, String>,
) -> usize {
    let mut count = 0usize;
    for (name, value) in baseline {
        match variant.get(name) {
            Some(other) if other == value => {}
            _ => count += 1,
        }
    }
    for name in variant.keys() {
        if !baseline.contains_key(name) {
            count += 1;
        }
    }
    count
}

fn has_confidence_converged(rate_history: &[f64]) -> bool {
    if rate_history.len() < 6 {
        return false;
    }
    let len = rate_history.len();
    let prev = &rate_history[len - 6..len - 3];
    let recent = &rate_history[len - 3..len];
    let prev_avg = prev.iter().sum::<f64>() / prev.len() as f64;
    let recent_avg = recent.iter().sum::<f64>() / recent.len() as f64;
    (recent_avg - prev_avg).abs() <= 0.05
}

fn build_paired_control_summary(
    differential: &[Va2DifferentialResult],
    channel_coverage: Option<&Va2ChannelCoverage>,
    pair_cap: usize,
    early_stop_reason: Option<String>,
) -> Option<PairedControlSummary> {
    if differential.is_empty() {
        return None;
    }

    let mut signals = Vec::with_capacity(differential.len());
    let mut detected_pairs = 0usize;
    let mut not_detected_pairs = 0usize;
    let mut inconclusive_pairs = 0usize;

    for diff in differential {
        let outcome = diff.outcome.unwrap_or({
            if diff.discriminated {
                PairedControlOutcome::Detected
            } else {
                PairedControlOutcome::NotDetected
            }
        });
        match outcome {
            PairedControlOutcome::Detected => detected_pairs += 1,
            PairedControlOutcome::NotDetected => not_detected_pairs += 1,
            PairedControlOutcome::Inconclusive => inconclusive_pairs += 1,
        }
        signals.push(PairedControlSignal {
            step_id: diff.step_id,
            baseline_step_id: diff.baseline_step_id,
            vector: diff
                .channel
                .map(|ch| ch.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            outcome,
            status_delta: diff.status_delta,
            body_length_pct_change: diff.body_length_pct_change,
            header_mutation_count: diff.header_mutation_count,
            timing_delta_ms: diff.timing_delta_ms,
        });
    }

    let coverage_by_vector = channel_coverage
        .map(|coverage| {
            coverage
                .channels
                .iter()
                .map(|(channel, score)| (channel.to_string(), *score))
                .collect()
        })
        .unwrap_or_default();

    Some(PairedControlSummary {
        signals,
        coverage_by_vector,
        executed_pairs: differential.len(),
        detected_pairs,
        not_detected_pairs,
        inconclusive_pairs,
        pair_cap,
        early_stop_reason,
    })
}

fn compute_channel_coverage(results: &[Va2DifferentialResult]) -> Option<Va2ChannelCoverage> {
    let mut per_channel: HashMap<Va2ProbeChannel, (usize, usize)> = HashMap::new();
    for r in results {
        if let Some(ch) = r.channel {
            let entry = per_channel.entry(ch).or_insert((0, 0));
            entry.0 += 1; // total
            if r.discriminated {
                entry.1 += 1; // discriminated
            }
        }
    }
    if per_channel.is_empty() {
        return None;
    }
    let mut channels = HashMap::new();
    let mut blind_spots = Vec::new();
    for (ch, (total, disc)) in &per_channel {
        let rate = if *total > 0 {
            *disc as f64 / *total as f64
        } else {
            0.0
        };
        channels.insert(*ch, rate);
        if rate == 0.0 {
            blind_spots.push(*ch);
        }
    }
    blind_spots.sort_by_key(|c| format!("{c:?}"));
    let coverage_score = if channels.is_empty() {
        0.0
    } else {
        channels.values().sum::<f64>() / channels.len() as f64
    };
    Some(Va2ChannelCoverage {
        channels,
        blind_spots,
        coverage_score,
    })
}

fn update_statefulness(
    summary: &mut Va2StateSummary,
    response: &Va2HttpResponse,
    baseline: Option<&Va2HttpResponse>,
) {
    let mut deviated = false;
    if response.headers.contains_key("set-cookie") {
        summary.set_cookie += 1;
        deviated = true;
    }
    if let Some(base) = baseline {
        if response.status != base.status {
            summary.status_change += 1;
            deviated = true;
        }
    }
    if deviated {
        summary.deviations += 1;
    }
}

/// Classify response into challenge types with confidence scores.
fn classify_challenge(response: &Va2HttpResponse) -> Vec<DetectedChallenge> {
    let mut challenges = Vec::new();
    let body_lower = response.body.to_lowercase();

    // Rate limit soft block
    if response.status == 429 {
        let confidence = if response.headers.contains_key("retry-after") {
            0.95
        } else {
            0.80
        };
        challenges.push(DetectedChallenge {
            challenge_type: ChallengeType::RateLimitSoftBlock,
            confidence,
            evidence: format!(
                "HTTP 429 status{}",
                if response.headers.contains_key("retry-after") {
                    " with Retry-After header"
                } else {
                    ""
                }
            ),
        });
    }

    // Hard blocks (401, 403) - could be a block, not a challenge - don't add to challenge list
    // Just note: these are handled in the existing hard_blocks counter

    // CAPTCHA detection
    if body_lower.contains("captcha")
        || body_lower.contains("recaptcha")
        || body_lower.contains("hcaptcha")
        || body_lower.contains("turnstile")
    {
        let confidence = if body_lower.contains("recaptcha") || body_lower.contains("hcaptcha") {
            0.90
        } else {
            0.75
        };
        challenges.push(DetectedChallenge {
            challenge_type: ChallengeType::CaptchaChallenge,
            confidence,
            evidence: "CAPTCHA keywords detected in response body".to_string(),
        });
    }

    // JavaScript challenge detection
    if body_lower.contains("javascript") && body_lower.contains("challenge") {
        challenges.push(DetectedChallenge {
            challenge_type: ChallengeType::JavaScriptChallenge,
            confidence: 0.80,
            evidence: "JavaScript challenge keywords in response body".to_string(),
        });
    } else if response.status == 503
        && (body_lower.contains("checking your browser") || body_lower.contains("just a moment"))
    {
        challenges.push(DetectedChallenge {
            challenge_type: ChallengeType::JavaScriptChallenge,
            confidence: 0.90,
            evidence: "503 with browser-check page pattern".to_string(),
        });
    }

    // Cookie gate detection
    if response.headers.contains_key("set-cookie") && body_lower.contains("challenge") {
        challenges.push(DetectedChallenge {
            challenge_type: ChallengeType::CookieGate,
            confidence: 0.70,
            evidence: "Set-Cookie header with challenge keyword in body".to_string(),
        });
    }

    challenges
}

fn update_challenge_profile(profile: &mut Va2ChallengeProfile, response: &Va2HttpResponse) {
    let mut matched = false;
    let body_lower = response.body.to_lowercase();
    if response.status == 401 || response.status == 403 || response.status == 429 {
        profile.hard_blocks += 1;
        matched = true;
    }
    if body_lower.contains("captcha") {
        profile.captcha += 1;
        matched = true;
    }
    if body_lower.contains("javascript") && body_lower.contains("challenge") {
        profile.js_challenge += 1;
        matched = true;
    }
    if response.headers.contains_key("set-cookie") && body_lower.contains("challenge") {
        profile.cookie_gate += 1;
        matched = true;
    }
    if matched {
        profile.total += 1;
    }

    // Add typed challenge classification
    let detected = classify_challenge(response);
    profile.detected_challenges.extend(detected);
}

fn compute_throttle_curve(samples: &[u128]) -> Va2ThrottleCurve {
    let mut curve = Va2ThrottleCurve::default();
    let mut total_slope = 0f64;
    let mut last = None;
    for (idx, value) in samples.iter().enumerate() {
        curve.samples.push((idx as u32, *value));
        if let Some(prev) = last {
            total_slope += (*value as f64) - (prev as f64);
        }
        last = Some(*value);
    }
    let steps = samples.len().saturating_sub(1) as f64;
    curve.slope_ms_per_step = if steps > 0.0 {
        total_slope / steps
    } else {
        0.0
    };
    curve.triggered = curve.slope_ms_per_step > 50.0;
    curve
}

fn compute_wbf(
    normalization: &Option<Va2NormalizationVariance>,
    statefulness: &Va2StateSummary,
    challenge: &Va2ChallengeProfile,
    throttle: &Option<Va2ThrottleCurve>,
    differential: &[Va2DifferentialResult],
) -> Va2WbfSummary {
    let normalization_score = normalization
        .as_ref()
        .map(|n| (n.max_status_delta as f64 / 50.0).min(1.0))
        .unwrap_or(0.0);
    let statefulness_score = (statefulness.deviations as f64 / 3.0).min(1.0);
    let challenge_score = if challenge.total == 0 {
        0.0
    } else {
        (challenge.hard_blocks as f64 / challenge.total as f64).min(1.0)
    };
    let throttle_score = throttle
        .as_ref()
        .map(|t| if t.triggered { 1.0 } else { 0.2 })
        .unwrap_or(0.0);
    let differential_score = if differential.is_empty() {
        0.0
    } else {
        let disc = differential.iter().filter(|d| d.discriminated).count();
        (disc as f64 / differential.len() as f64).min(1.0)
    };
    Va2WbfSummary {
        normalization_score,
        statefulness_score,
        challenge_score,
        throttle_score,
        differential_score,
    }
}

fn compute_pmi(wbf: &Va2WbfSummary) -> Va2PmiScore {
    let raw = (wbf.normalization_score * 0.20)
        + (wbf.statefulness_score * 0.20)
        + (wbf.challenge_score * 0.25)
        + (wbf.throttle_score * 0.15)
        + (wbf.differential_score * 0.20);
    let score = (raw * 100.0).round();
    let label = if score >= 80.0 {
        "strong"
    } else if score >= 55.0 {
        "moderate"
    } else {
        "weak"
    };
    Va2PmiScore {
        score,
        label: label.to_string(),
    }
}

impl Va2CampaignPlan {
    pub fn validate(&self) -> Result<()> {
        if self.phases.is_empty() {
            return Err(anyhow!("va2 campaign requires at least one phase"));
        }
        if self.steps.is_empty() {
            return Err(anyhow!("va2 campaign requires at least one step"));
        }
        if self.steps.len() as u32 > self.budget {
            return Err(anyhow!(
                "va2 campaign exceeds budget: {} > {}",
                self.steps.len(),
                self.budget
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Va2CampaignConfig {
    pub seed: u64,
    pub budget: u32,
}

impl Default for Va2CampaignConfig {
    fn default() -> Self {
        Self {
            seed: 1337,
            budget: 60,
        }
    }
}

pub fn build_va2_campaign_plan(
    target_url: &str,
    phases: &[Va2Phase],
    config: Va2CampaignConfig,
) -> Result<Va2CampaignPlan> {
    let parsed = Url::parse(target_url).map_err(|_| {
        anyhow!("Could not parse '{}' as a URL. Make sure it starts with https:// and contains a valid domain.", target_url)
    })?;
    if parsed.host_str().is_none() {
        return Err(anyhow!("URL must include a domain name (e.g. https://example.com)."));
    }
    if phases.is_empty() {
        return Err(anyhow!("va2 campaign requires at least one phase"));
    }
    if config.budget == 0 {
        return Err(anyhow!("va2 campaign budget must be greater than 0"));
    }

    let mut rng = StdRng::seed_from_u64(config.seed);
    let mut steps = Vec::new();
    let mut next_id = 1u32;

    for phase in phases {
        match phase {
            Va2Phase::Baseline => {
                for _ in 0..3 {
                    steps.push(Va2CampaignStep {
                        id: next_id,
                        phase: *phase,
                        kind: Va2StepKind::Baseline,
                        method: "GET".to_string(),
                        path: "/".to_string(),
                        query: None,
                        headers: HashMap::new(),
                        body: None,
                        delay_ms: 350,
                        notes: "baseline request".to_string(),
                        expected_equivalence: None,
                        channel: None,
                    });
                    next_id += 1;
                }
            }
            Va2Phase::ProtocolVariance => {
                let variants = ["/", "/./", "/%2e/", "/%2F", "/index.html"];
                for idx in 0..3 {
                    let path = variants[rng.gen_range(0..variants.len())];
                    steps.push(Va2CampaignStep {
                        id: next_id,
                        phase: *phase,
                        kind: Va2StepKind::Equivalence,
                        method: "GET".to_string(),
                        path: path.to_string(),
                        query: Some(format!("va2=eq{idx}")),
                        headers: HashMap::new(),
                        body: None,
                        delay_ms: 400,
                        notes: "equivalent path variance".to_string(),
                        expected_equivalence: Some(1),
                        channel: None,
                    });
                    next_id += 1;
                }

                // Multi-channel paired-control probes.
                // Each pair: benign control, then suspicious variant referencing it.
                struct PairedProbe {
                    channel: Va2ProbeChannel,
                    benign_note: &'static str,
                    benign_method: &'static str,
                    benign_path: &'static str,
                    benign_query: Option<&'static str>,
                    benign_headers: &'static [(&'static str, &'static str)],
                    benign_body: Option<&'static str>,
                    attack_note: &'static str,
                    attack_method: &'static str,
                    attack_path: &'static str,
                    attack_query: Option<&'static str>,
                    attack_headers: &'static [(&'static str, &'static str)],
                    attack_body: Option<&'static str>,
                }

                let paired_probes = [
                    // Existing query-channel probes
                    PairedProbe {
                        channel: Va2ProbeChannel::Query,
                        benign_note: "sqli-control",
                        benign_method: "GET",
                        benign_path: "/",
                        benign_query: Some("search=test"),
                        benign_headers: &[],
                        benign_body: None,
                        attack_note: "sqli-probe",
                        attack_method: "GET",
                        attack_path: "/",
                        attack_query: Some("search=1'+OR+'1'='1"),
                        attack_headers: &[],
                        attack_body: None,
                    },
                    PairedProbe {
                        channel: Va2ProbeChannel::Query,
                        benign_note: "xss-control",
                        benign_method: "GET",
                        benign_path: "/",
                        benign_query: Some("q=hello"),
                        benign_headers: &[],
                        benign_body: None,
                        attack_note: "xss-probe",
                        attack_method: "GET",
                        attack_path: "/",
                        attack_query: Some("q=<script>alert(1)</script>"),
                        attack_headers: &[],
                        attack_body: None,
                    },
                    // Path-channel probe
                    PairedProbe {
                        channel: Va2ProbeChannel::Path,
                        benign_note: "pt-control",
                        benign_method: "GET",
                        benign_path: "/api/v1/status",
                        benign_query: None,
                        benign_headers: &[],
                        benign_body: None,
                        attack_note: "pt-probe",
                        attack_method: "GET",
                        attack_path: "/../../etc/passwd",
                        attack_query: None,
                        attack_headers: &[],
                        attack_body: None,
                    },
                    // Query-channel probes
                    PairedProbe {
                        channel: Va2ProbeChannel::Query,
                        benign_note: "cmdi-control",
                        benign_method: "GET",
                        benign_path: "/",
                        benign_query: Some("cmd=list"),
                        benign_headers: &[],
                        benign_body: None,
                        attack_note: "cmdi-probe",
                        attack_method: "GET",
                        attack_path: "/",
                        attack_query: Some("cmd=;cat+/etc/passwd"),
                        attack_headers: &[],
                        attack_body: None,
                    },
                    PairedProbe {
                        channel: Va2ProbeChannel::Query,
                        benign_note: "proto-control",
                        benign_method: "GET",
                        benign_path: "/",
                        benign_query: Some("format=json"),
                        benign_headers: &[],
                        benign_body: None,
                        attack_note: "proto-probe",
                        attack_method: "GET",
                        attack_path: "/",
                        attack_query: Some("format=../../etc/passwd%00.json"),
                        attack_headers: &[],
                        attack_body: None,
                    },
                    // Header-channel probes
                    PairedProbe {
                        channel: Va2ProbeChannel::Header,
                        benign_note: "hdr-xss-control",
                        benign_method: "GET",
                        benign_path: "/",
                        benign_query: Some("va2=hdr1"),
                        benign_headers: &[("Referer", "https://example.com")],
                        benign_body: None,
                        attack_note: "hdr-xss-probe",
                        attack_method: "GET",
                        attack_path: "/",
                        attack_query: Some("va2=hdr1"),
                        attack_headers: &[("Referer", "<script>alert(1)</script>")],
                        attack_body: None,
                    },
                    PairedProbe {
                        channel: Va2ProbeChannel::Header,
                        benign_note: "hdr-sqli-control",
                        benign_method: "GET",
                        benign_path: "/",
                        benign_query: Some("va2=hdr2"),
                        benign_headers: &[("X-Search", "test")],
                        benign_body: None,
                        attack_note: "hdr-sqli-probe",
                        attack_method: "GET",
                        attack_path: "/",
                        attack_query: Some("va2=hdr2"),
                        attack_headers: &[("X-Search", "1' OR '1'='1")],
                        attack_body: None,
                    },
                    // Body-channel probe
                    PairedProbe {
                        channel: Va2ProbeChannel::Body,
                        benign_note: "body-sqli-control",
                        benign_method: "POST",
                        benign_path: "/",
                        benign_query: Some("va2=body1"),
                        benign_headers: &[("Content-Type", "application/x-www-form-urlencoded")],
                        benign_body: Some("search=test"),
                        attack_note: "body-sqli-probe",
                        attack_method: "POST",
                        attack_path: "/",
                        attack_query: Some("va2=body1"),
                        attack_headers: &[("Content-Type", "application/x-www-form-urlencoded")],
                        attack_body: Some("search=1'+OR+'1'='1"),
                    },
                    // Method-channel probe
                    PairedProbe {
                        channel: Va2ProbeChannel::Method,
                        benign_note: "method-control",
                        benign_method: "OPTIONS",
                        benign_path: "/api/v1/status",
                        benign_query: None,
                        benign_headers: &[],
                        benign_body: None,
                        attack_note: "method-probe",
                        attack_method: "DELETE",
                        attack_path: "/api/v1/status",
                        attack_query: None,
                        attack_headers: &[],
                        attack_body: None,
                    },
                ];

                for pair in &paired_probes {
                    let control_id = next_id;
                    let benign_headers: HashMap<String, String> = pair
                        .benign_headers
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();
                    steps.push(Va2CampaignStep {
                        id: next_id,
                        phase: *phase,
                        kind: Va2StepKind::Equivalence,
                        method: pair.benign_method.to_string(),
                        path: pair.benign_path.to_string(),
                        query: pair.benign_query.map(String::from),
                        headers: benign_headers,
                        body: pair.benign_body.map(String::from),
                        delay_ms: 400,
                        notes: format!("paired-control: {}", pair.benign_note),
                        expected_equivalence: None,
                        channel: Some(pair.channel),
                    });
                    next_id += 1;
                    let attack_headers: HashMap<String, String> = pair
                        .attack_headers
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();
                    steps.push(Va2CampaignStep {
                        id: next_id,
                        phase: *phase,
                        kind: Va2StepKind::Equivalence,
                        method: pair.attack_method.to_string(),
                        path: pair.attack_path.to_string(),
                        query: pair.attack_query.map(String::from),
                        headers: attack_headers,
                        body: pair.attack_body.map(String::from),
                        delay_ms: 400,
                        notes: format!("paired-control: {}", pair.attack_note),
                        expected_equivalence: Some(control_id),
                        channel: Some(pair.channel),
                    });
                    next_id += 1;
                }
            }
            Va2Phase::StateEscalation => {
                let mut headers = HashMap::new();
                headers.insert("X-VA2-STATE".to_string(), "missing-cookie".to_string());
                steps.push(Va2CampaignStep {
                    id: next_id,
                    phase: *phase,
                    kind: Va2StepKind::StateMutation,
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    query: Some("state=probe".to_string()),
                    headers,
                    body: None,
                    delay_ms: 450,
                    notes: "state mutation probe".to_string(),
                    expected_equivalence: None,
                    channel: None,
                });
                next_id += 1;
            }
            Va2Phase::BehavioralPressure => {
                for idx in 0..3 {
                    steps.push(Va2CampaignStep {
                        id: next_id,
                        phase: *phase,
                        kind: Va2StepKind::RateRamp,
                        method: "GET".to_string(),
                        path: "/".to_string(),
                        query: Some(format!("ramp={idx}")),
                        headers: HashMap::new(),
                        body: None,
                        delay_ms: 150,
                        notes: "rate ramp step".to_string(),
                        expected_equivalence: None,
                        channel: None,
                    });
                    next_id += 1;
                }
            }
            Va2Phase::ChallengeInteraction => {
                let mut headers = HashMap::new();
                headers.insert(
                    "X-VA2-CHALLENGE".to_string(),
                    "accept-challenge".to_string(),
                );
                steps.push(Va2CampaignStep {
                    id: next_id,
                    phase: *phase,
                    kind: Va2StepKind::ChallengeProbe,
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    query: Some("challenge=probe".to_string()),
                    headers,
                    body: None,
                    delay_ms: 500,
                    notes: "challenge interaction probe".to_string(),
                    expected_equivalence: None,
                    channel: None,
                });
                next_id += 1;
            }
        }
    }

    if steps.len() as u32 > config.budget {
        steps.truncate(config.budget as usize);
    }

    let plan = Va2CampaignPlan {
        version: "va2-0.1".to_string(),
        seed: config.seed,
        target_url: target_url.to_string(),
        phases: phases.to_vec(),
        budget: config.budget,
        steps,
    };

    plan.validate()?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::TempDir;

    #[allow(clippy::await_holding_lock)] // Intentional: env lock must span the entire test body
    async fn with_temp_home<F, Fut>(f: F)
    where
        F: FnOnce(TempDir) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("WAF_DETECTOR_HOME").ok();
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("WAF_DETECTOR_HOME", temp_dir.path());
        f(temp_dir).await;
        if let Some(value) = original_home {
            std::env::set_var("WAF_DETECTOR_HOME", value);
        } else {
            std::env::remove_var("WAF_DETECTOR_HOME");
        }
    }

    #[derive(Default)]
    struct StubAdapter;

    #[async_trait]
    impl Va2HttpAdapter for StubAdapter {
        async fn send(&self, request: &Va2HttpRequest) -> anyhow::Result<Va2HttpResponse> {
            let url = &request.url;

            // Check for DELETE method → 405
            if request.method == "DELETE" {
                return Ok(Va2HttpResponse {
                    status: 405,
                    headers: HashMap::new(),
                    body: "method not allowed".to_string(),
                });
            }

            // Detect attack patterns in URL for paired-probe differential testing
            let url_attack = url.contains("OR")
                || url.contains("script")
                || url.contains("passwd")
                || url.contains("cat+");

            // Detect attack patterns in headers
            let header_attack = request.headers.iter().any(|(_, v)| {
                v.contains("OR")
                    || v.contains("script")
                    || v.contains("passwd")
                    || v.contains("cat+")
            });

            // Detect attack patterns in body
            let body_attack = request
                .body
                .as_ref()
                .map(|b| {
                    b.contains("OR")
                        || b.contains("script")
                        || b.contains("passwd")
                        || b.contains("cat+")
                })
                .unwrap_or(false);

            let is_attack = url_attack || header_attack || body_attack;

            let (status, body) = if is_attack {
                (403, "access denied".to_string())
            } else if url.contains("protocol") {
                (418, "teapot".to_string())
            } else if url.contains("state") {
                (401, "state escalation".to_string())
            } else if url.contains("challenge") {
                (403, "javascript challenge captcha".to_string())
            } else if url.contains("error") {
                (500, "server error".to_string())
            } else {
                (200, "baseline ok".to_string())
            };
            let mut headers = HashMap::new();
            if url.contains("state") || url.contains("challenge") {
                headers.insert("set-cookie".to_string(), "va2=1".to_string());
            }
            Ok(Va2HttpResponse {
                status,
                headers,
                body,
            })
        }
    }

    fn write_consent(temp_dir: &TempDir, targets: &[&str]) {
        let consent_path = temp_dir.path().join(".waf-detector-consent.json");
        let record = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "terms_version": "1.0.0",
            "authorized_targets": targets,
            "acknowledgment": "I AGREE"
        });
        std::fs::write(
            &consent_path,
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn test_va2_plan_requires_phases() {
        let err = build_va2_campaign_plan("https://example.com", &[], Va2CampaignConfig::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("at least one phase"));
    }

    #[test]
    fn test_va2_plan_deterministic() {
        let phases = vec![Va2Phase::Baseline, Va2Phase::ProtocolVariance];
        let config = Va2CampaignConfig {
            seed: 4242,
            budget: 20,
        };
        let plan_a = build_va2_campaign_plan("https://example.com", &phases, config).unwrap();
        let plan_b = build_va2_campaign_plan("https://example.com", &phases, config).unwrap();
        assert_eq!(plan_a, plan_b);
    }

    #[test]
    fn test_va2_plan_budget_enforced() {
        let phases = vec![
            Va2Phase::Baseline,
            Va2Phase::ProtocolVariance,
            Va2Phase::BehavioralPressure,
        ];
        let config = Va2CampaignConfig { seed: 7, budget: 3 };
        let plan = build_va2_campaign_plan("https://example.com", &phases, config).unwrap();
        assert!(plan.steps.len() <= 3);
    }

    #[test]
    fn test_va2_plan_serializes() {
        let phases = vec![Va2Phase::Baseline];
        let plan =
            build_va2_campaign_plan("https://example.com", &phases, Va2CampaignConfig::default())
                .unwrap();
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("va2-0.1"));
    }

    #[tokio::test]
    async fn test_va2_runner_requires_consent() {
        with_temp_home(|_temp| async move {
            let phases = vec![Va2Phase::Baseline];
            let plan = build_va2_campaign_plan(
                "https://example.com",
                &phases,
                Va2CampaignConfig::default(),
            )
            .unwrap();
            let runner = Va2Runner::with_adapter(Box::new(StubAdapter)).unwrap();
            let err = runner.run_plan(plan).await.unwrap_err().to_string();
            assert!(err.contains("Consent is required"));
        })
        .await;
    }

    #[tokio::test]
    async fn test_va2_runner_executes_plan() {
        with_temp_home(|temp| async move {
            write_consent(&temp, &["example.com"]);
            let phases = vec![
                Va2Phase::Baseline,
                Va2Phase::ProtocolVariance,
                Va2Phase::StateEscalation,
                Va2Phase::ChallengeInteraction,
                Va2Phase::BehavioralPressure,
            ];
            let mut plan = build_va2_campaign_plan(
                "https://example.com",
                &phases,
                Va2CampaignConfig {
                    seed: 1,
                    budget: 40,
                },
            )
            .unwrap();
            for step in &mut plan.steps {
                step.delay_ms = 0;
                if step.phase == Va2Phase::ProtocolVariance {
                    step.path = "/protocol-variance".to_string();
                } else if step.phase == Va2Phase::StateEscalation {
                    step.path = "/state".to_string();
                } else if step.phase == Va2Phase::ChallengeInteraction {
                    step.path = "/challenge".to_string();
                } else if step.phase == Va2Phase::BehavioralPressure {
                    step.path = "/pressure".to_string();
                }
            }
            let runner = Va2Runner::with_adapter(Box::new(StubAdapter)).unwrap();
            let report = runner.run_plan(plan).await.unwrap();
            assert!(!report.results.is_empty());
            assert_eq!(report.results.len(), report.plan.steps.len());
            assert_eq!(report.baseline.status, Some(200));
            assert!(report.normalization.is_some());
            assert!(report.statefulness.is_some());
            assert!(report.challenge.is_some());
            assert!(report.throttle.is_some());
            assert!(report.pmi.score >= 0.0);
            assert!(!report.pmi.label.is_empty());
        })
        .await;
    }

    #[test]
    fn test_va2_baseline_summary_defaults() {
        let summary = summarize_baseline(&[]);
        assert!(summary.status.is_none());
        assert_eq!(summary.header_count, 0);
        assert_eq!(summary.body_length, 0);
        assert!(summary.sample.is_empty());
    }

    #[test]
    fn test_va2_normalization_variance_calculation() {
        let variance = compute_normalization_variance(Some(200), &[(200, 10), (418, 30)]);
        assert!(variance.max_status_delta >= 18);
        assert!(variance.avg_length_delta >= 0.0);
    }

    #[test]
    fn test_va2_challenge_profile_detects_captcha() {
        let mut profile = Va2ChallengeProfile::default();
        let response = Va2HttpResponse {
            status: 403,
            headers: {
                let mut headers = HashMap::new();
                headers.insert("set-cookie".to_string(), "va2=1".to_string());
                headers
            },
            body: "captcha javascript challenge".to_string(),
        };
        update_challenge_profile(&mut profile, &response);
        assert!(profile.total >= 1);
        assert!(profile.captcha >= 1);
        assert!(profile.js_challenge >= 1);
        assert!(profile.cookie_gate >= 1);
    }

    #[test]
    fn test_va2_throttle_curve_detects_increase() {
        let curve = compute_throttle_curve(&[10, 80, 140]);
        assert!(curve.slope_ms_per_step > 0.0);
        assert!(curve.triggered);
    }

    #[test]
    fn test_va2_pmi_labeling() {
        let wbf = Va2WbfSummary {
            normalization_score: 1.0,
            statefulness_score: 1.0,
            challenge_score: 1.0,
            throttle_score: 1.0,
            differential_score: 1.0,
        };
        let pmi = compute_pmi(&wbf);
        assert_eq!(pmi.label, "strong");
    }

    #[test]
    fn test_classify_challenge_rate_limit() {
        let mut headers = HashMap::new();
        headers.insert("retry-after".to_string(), "60".to_string());
        let response = Va2HttpResponse {
            status: 429,
            headers,
            body: "Too many requests".to_string(),
        };
        let challenges = classify_challenge(&response);
        assert_eq!(challenges.len(), 1);
        assert_eq!(
            challenges[0].challenge_type,
            ChallengeType::RateLimitSoftBlock
        );
        assert_eq!(challenges[0].confidence, 0.95);
        assert!(challenges[0].evidence.contains("Retry-After"));
    }

    #[test]
    fn test_classify_challenge_captcha() {
        let response = Va2HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: "Please solve this recaptcha to continue".to_string(),
        };
        let challenges = classify_challenge(&response);
        assert_eq!(challenges.len(), 1);
        assert_eq!(
            challenges[0].challenge_type,
            ChallengeType::CaptchaChallenge
        );
        assert_eq!(challenges[0].confidence, 0.90);
        assert!(challenges[0].evidence.contains("CAPTCHA"));
    }

    #[test]
    fn test_classify_challenge_javascript() {
        let response = Va2HttpResponse {
            status: 503,
            headers: HashMap::new(),
            body: "Checking your browser before accessing...".to_string(),
        };
        let challenges = classify_challenge(&response);
        assert_eq!(challenges.len(), 1);
        assert_eq!(
            challenges[0].challenge_type,
            ChallengeType::JavaScriptChallenge
        );
        assert_eq!(challenges[0].confidence, 0.90);
        assert!(challenges[0].evidence.contains("browser-check"));
    }

    #[test]
    fn test_classify_challenge_cookie_gate() {
        let mut headers = HashMap::new();
        headers.insert("set-cookie".to_string(), "session=abc123".to_string());
        let response = Va2HttpResponse {
            status: 200,
            headers,
            body: "Please complete this challenge".to_string(),
        };
        let challenges = classify_challenge(&response);
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].challenge_type, ChallengeType::CookieGate);
        assert_eq!(challenges[0].confidence, 0.70);
        assert!(challenges[0].evidence.contains("Set-Cookie"));
    }

    #[test]
    fn test_update_challenge_profile_with_detected_challenges() {
        let mut profile = Va2ChallengeProfile::default();
        let mut headers = HashMap::new();
        headers.insert("retry-after".to_string(), "60".to_string());
        let response = Va2HttpResponse {
            status: 429,
            headers,
            body: "Rate limited".to_string(),
        };
        update_challenge_profile(&mut profile, &response);
        assert_eq!(profile.hard_blocks, 1);
        assert_eq!(profile.total, 1);
        assert_eq!(profile.detected_challenges.len(), 1);
        assert_eq!(
            profile.detected_challenges[0].challenge_type,
            ChallengeType::RateLimitSoftBlock
        );
        assert_eq!(profile.detected_challenges[0].confidence, 0.95);
    }

    #[test]
    fn test_va2_differential_no_discrimination() {
        let baseline = Va2HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: "baseline ok".to_string(),
        };
        let variant = Va2HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: "baseline ok".to_string(),
        };
        let result = compute_differential(2, 1, &baseline, &variant, None, 100, 105);
        assert_eq!(result.step_id, 2);
        assert_eq!(result.baseline_step_id, 1);
        assert_eq!(result.status_delta, 0);
        assert!(result.body_length_pct_change < 0.01);
        assert!(!result.discriminated);
    }

    #[test]
    fn test_va2_differential_detects_discrimination() {
        let baseline = Va2HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: "baseline ok".to_string(),
        };
        let variant = Va2HttpResponse {
            status: 403,
            headers: HashMap::new(),
            body: "access denied".to_string(),
        };
        let result = compute_differential(
            2,
            1,
            &baseline,
            &variant,
            Some(Va2ProbeChannel::Query),
            80,
            200,
        );
        assert_eq!(result.status_delta, 203);
        assert!(result.discriminated);
        assert_eq!(result.channel, Some(Va2ProbeChannel::Query));
    }

    #[test]
    fn test_va2_wbf_includes_differential() {
        let diff_results = vec![
            Va2DifferentialResult {
                step_id: 2,
                baseline_step_id: 1,
                status_delta: 203,
                body_length_pct_change: 0.5,
                header_mutation_count: 0,
                timing_delta_ms: 0,
                discriminated: true,
                outcome: Some(PairedControlOutcome::Detected),
                channel: Some(Va2ProbeChannel::Query),
            },
            Va2DifferentialResult {
                step_id: 4,
                baseline_step_id: 3,
                status_delta: 0,
                body_length_pct_change: 0.0,
                header_mutation_count: 0,
                timing_delta_ms: 0,
                discriminated: false,
                outcome: Some(PairedControlOutcome::NotDetected),
                channel: Some(Va2ProbeChannel::Header),
            },
        ];
        let wbf = compute_wbf(
            &None,
            &Va2StateSummary::default(),
            &Va2ChallengeProfile::default(),
            &None,
            &diff_results,
        );
        // 1 out of 2 discriminated = 0.5
        assert!((wbf.differential_score - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_va2_paired_probes_in_plan() {
        let phases = vec![Va2Phase::Baseline, Va2Phase::ProtocolVariance];
        let config = Va2CampaignConfig {
            seed: 1,
            budget: 60,
        };
        let plan = build_va2_campaign_plan("https://example.com", &phases, config).unwrap();
        // Should have baseline (3) + path variance (3) + paired probes (9 pairs = 18) = 24 steps
        assert_eq!(plan.steps.len(), 24);
        // Check paired probes have correct expected_equivalence references
        let paired_steps: Vec<_> = plan
            .steps
            .iter()
            .filter(|s| s.notes.starts_with("paired-control:"))
            .collect();
        assert_eq!(paired_steps.len(), 18);
        // Every second paired step should reference the one before it
        for chunk in paired_steps.chunks(2) {
            assert!(chunk[0].expected_equivalence.is_none());
            assert_eq!(chunk[1].expected_equivalence, Some(chunk[0].id));
        }
    }

    #[tokio::test]
    async fn test_va2_differential_scoring_with_stub() {
        with_temp_home(|temp| async move {
            write_consent(&temp, &["example.com"]);
            let phases = vec![Va2Phase::Baseline, Va2Phase::ProtocolVariance];
            let mut plan = build_va2_campaign_plan(
                "https://example.com",
                &phases,
                Va2CampaignConfig {
                    seed: 1,
                    budget: 60,
                },
            )
            .unwrap();
            for step in &mut plan.steps {
                step.delay_ms = 0;
            }
            let runner = Va2Runner::with_adapter(Box::new(StubAdapter)).unwrap();
            let report = runner.run_plan(plan).await.unwrap();
            // StubAdapter returns 403 for attack URLs (containing OR, script, passwd, cat+)
            // so differential results should show discrimination
            assert!(!report.differential.is_empty());
            let discriminated = report
                .differential
                .iter()
                .filter(|d| d.discriminated)
                .count();
            assert!(discriminated > 0, "expected some discriminated results");
            assert!(report.wbf.differential_score > 0.0);
        })
        .await;
    }

    #[test]
    fn test_va2_multichannel_probes_in_plan() {
        let phases = vec![Va2Phase::Baseline, Va2Phase::ProtocolVariance];
        let config = Va2CampaignConfig {
            seed: 1,
            budget: 60,
        };
        let plan = build_va2_campaign_plan("https://example.com", &phases, config).unwrap();
        let paired_steps: Vec<_> = plan
            .steps
            .iter()
            .filter(|s| s.notes.starts_with("paired-control:"))
            .collect();
        // Verify all 5 channel types are represented
        let channels: std::collections::HashSet<_> =
            paired_steps.iter().filter_map(|s| s.channel).collect();
        assert!(channels.contains(&Va2ProbeChannel::Query));
        assert!(channels.contains(&Va2ProbeChannel::Path));
        assert!(channels.contains(&Va2ProbeChannel::Header));
        assert!(channels.contains(&Va2ProbeChannel::Body));
        assert!(channels.contains(&Va2ProbeChannel::Method));
        assert_eq!(channels.len(), 5);
        // All paired steps should have a channel tag
        assert!(paired_steps.iter().all(|s| s.channel.is_some()));
    }

    #[tokio::test]
    async fn test_va2_header_channel_discrimination() {
        with_temp_home(|temp| async move {
            write_consent(&temp, &["example.com"]);
            let phases = vec![Va2Phase::Baseline, Va2Phase::ProtocolVariance];
            let mut plan = build_va2_campaign_plan(
                "https://example.com",
                &phases,
                Va2CampaignConfig {
                    seed: 1,
                    budget: 60,
                },
            )
            .unwrap();
            for step in &mut plan.steps {
                step.delay_ms = 0;
            }
            let runner = Va2Runner::with_adapter(Box::new(StubAdapter)).unwrap();
            let report = runner.run_plan(plan).await.unwrap();
            // StubAdapter blocks header-based attacks (containing OR, script)
            let header_disc: Vec<_> = report
                .differential
                .iter()
                .filter(|d| d.channel == Some(Va2ProbeChannel::Header) && d.discriminated)
                .collect();
            assert!(
                !header_disc.is_empty(),
                "expected header channel discrimination"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_va2_body_channel_discrimination() {
        with_temp_home(|temp| async move {
            write_consent(&temp, &["example.com"]);
            let phases = vec![Va2Phase::Baseline, Va2Phase::ProtocolVariance];
            let mut plan = build_va2_campaign_plan(
                "https://example.com",
                &phases,
                Va2CampaignConfig {
                    seed: 1,
                    budget: 60,
                },
            )
            .unwrap();
            for step in &mut plan.steps {
                step.delay_ms = 0;
            }
            let runner = Va2Runner::with_adapter(Box::new(StubAdapter)).unwrap();
            let report = runner.run_plan(plan).await.unwrap();
            let body_disc: Vec<_> = report
                .differential
                .iter()
                .filter(|d| d.channel == Some(Va2ProbeChannel::Body) && d.discriminated)
                .collect();
            assert!(
                !body_disc.is_empty(),
                "expected body channel discrimination"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn test_va2_method_channel_discrimination() {
        with_temp_home(|temp| async move {
            write_consent(&temp, &["example.com"]);
            let phases = vec![Va2Phase::Baseline, Va2Phase::ProtocolVariance];
            let mut plan = build_va2_campaign_plan(
                "https://example.com",
                &phases,
                Va2CampaignConfig {
                    seed: 1,
                    budget: 60,
                },
            )
            .unwrap();
            for step in &mut plan.steps {
                step.delay_ms = 0;
            }
            let runner = Va2Runner::with_adapter(Box::new(StubAdapter)).unwrap();
            let report = runner.run_plan(plan).await.unwrap();
            // StubAdapter returns 405 for DELETE, 200 for OPTIONS → discrimination
            let method_disc: Vec<_> = report
                .differential
                .iter()
                .filter(|d| d.channel == Some(Va2ProbeChannel::Method) && d.discriminated)
                .collect();
            assert!(
                !method_disc.is_empty(),
                "expected method channel discrimination"
            );
        })
        .await;
    }

    #[test]
    fn test_va2_channel_coverage_computation() {
        let results = vec![
            Va2DifferentialResult {
                step_id: 2,
                baseline_step_id: 1,
                status_delta: 203,
                body_length_pct_change: 0.5,
                header_mutation_count: 0,
                timing_delta_ms: 0,
                discriminated: true,
                outcome: Some(PairedControlOutcome::Detected),
                channel: Some(Va2ProbeChannel::Query),
            },
            Va2DifferentialResult {
                step_id: 4,
                baseline_step_id: 3,
                status_delta: 0,
                body_length_pct_change: 0.0,
                header_mutation_count: 0,
                timing_delta_ms: 0,
                discriminated: false,
                outcome: Some(PairedControlOutcome::NotDetected),
                channel: Some(Va2ProbeChannel::Header),
            },
            Va2DifferentialResult {
                step_id: 6,
                baseline_step_id: 5,
                status_delta: 200,
                body_length_pct_change: 0.8,
                header_mutation_count: 0,
                timing_delta_ms: 0,
                discriminated: true,
                outcome: Some(PairedControlOutcome::Detected),
                channel: Some(Va2ProbeChannel::Header),
            },
        ];
        let coverage = compute_channel_coverage(&results).unwrap();
        // Query: 1/1 = 1.0, Header: 1/2 = 0.5
        assert!((coverage.channels[&Va2ProbeChannel::Query] - 1.0).abs() < 0.01);
        assert!((coverage.channels[&Va2ProbeChannel::Header] - 0.5).abs() < 0.01);
        assert!(coverage.blind_spots.is_empty());
        // Coverage = (1.0 + 0.5) / 2 = 0.75
        assert!((coverage.coverage_score - 0.75).abs() < 0.01);
    }

    #[test]
    fn test_va2_channel_coverage_all_blocked() {
        let results = vec![
            Va2DifferentialResult {
                step_id: 2,
                baseline_step_id: 1,
                status_delta: 203,
                body_length_pct_change: 0.5,
                header_mutation_count: 0,
                timing_delta_ms: 0,
                discriminated: true,
                outcome: Some(PairedControlOutcome::Detected),
                channel: Some(Va2ProbeChannel::Query),
            },
            Va2DifferentialResult {
                step_id: 4,
                baseline_step_id: 3,
                status_delta: 200,
                body_length_pct_change: 0.8,
                header_mutation_count: 0,
                timing_delta_ms: 0,
                discriminated: true,
                outcome: Some(PairedControlOutcome::Detected),
                channel: Some(Va2ProbeChannel::Header),
            },
            Va2DifferentialResult {
                step_id: 6,
                baseline_step_id: 5,
                status_delta: 100,
                body_length_pct_change: 0.9,
                header_mutation_count: 0,
                timing_delta_ms: 0,
                discriminated: true,
                outcome: Some(PairedControlOutcome::Detected),
                channel: Some(Va2ProbeChannel::Body),
            },
        ];
        let coverage = compute_channel_coverage(&results).unwrap();
        assert!(coverage.blind_spots.is_empty());
        assert!((coverage.coverage_score - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_va2_channel_coverage_no_waf() {
        let results = vec![
            Va2DifferentialResult {
                step_id: 2,
                baseline_step_id: 1,
                status_delta: 0,
                body_length_pct_change: 0.0,
                header_mutation_count: 0,
                timing_delta_ms: 0,
                discriminated: false,
                outcome: Some(PairedControlOutcome::NotDetected),
                channel: Some(Va2ProbeChannel::Query),
            },
            Va2DifferentialResult {
                step_id: 4,
                baseline_step_id: 3,
                status_delta: 0,
                body_length_pct_change: 0.0,
                header_mutation_count: 0,
                timing_delta_ms: 0,
                discriminated: false,
                outcome: Some(PairedControlOutcome::NotDetected),
                channel: Some(Va2ProbeChannel::Header),
            },
            Va2DifferentialResult {
                step_id: 6,
                baseline_step_id: 5,
                status_delta: 0,
                body_length_pct_change: 0.0,
                header_mutation_count: 0,
                timing_delta_ms: 0,
                discriminated: false,
                outcome: Some(PairedControlOutcome::NotDetected),
                channel: Some(Va2ProbeChannel::Body),
            },
        ];
        let coverage = compute_channel_coverage(&results).unwrap();
        assert_eq!(coverage.blind_spots.len(), 3);
        assert!((coverage.coverage_score - 0.0).abs() < 0.01);
    }
}
