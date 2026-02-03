//! Virtual Adversary 2.0 (VA2)
//!
//! Behavioral WAF profiling with deterministic, replayable campaigns.

use anyhow::{anyhow, Result};
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

pub trait Va2HttpAdapter {
    fn send(&self, request: &Va2HttpRequest) -> anyhow::Result<Va2HttpResponse>;
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

impl Va2HttpAdapter for RealVa2HttpAdapter {
    fn send(&self, request: &Va2HttpRequest) -> anyhow::Result<Va2HttpResponse> {
        let response = futures::executor::block_on(self.client.request(
            &request.method,
            &request.url,
            &request.headers,
            request.body.as_deref(),
        ))?;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Va2ChallengeProfile {
    pub total: usize,
    pub hard_blocks: usize,
    pub captcha: usize,
    pub js_challenge: usize,
    pub cookie_gate: usize,
}

impl Default for Va2ChallengeProfile {
    fn default() -> Self {
        Self {
            total: 0,
            hard_blocks: 0,
            captcha: 0,
            js_challenge: 0,
            cookie_gate: 0,
        }
    }
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

    pub fn run_plan(&self, plan: Va2CampaignPlan) -> Result<Va2RunReport> {
        ensure_va2_consent_and_target(&self.consent_manager, &plan.target_url)?;

        let mut results = Vec::with_capacity(plan.steps.len());
        let mut baseline_samples = Vec::new();
        let mut variance_samples: Vec<(u16, usize)> = Vec::new();
        let mut state_summary = Va2StateSummary::default();
        let mut challenge_profile = Va2ChallengeProfile::default();
        for step in &plan.steps {
            if step.delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(step.delay_ms));
            }
            let request = build_va2_request(&plan.target_url, step)?;
            let started = Instant::now();
            let response = self.http.send(&request);
            let duration = started.elapsed().as_millis();
            match response {
                Ok(resp) => {
                    if step.phase == Va2Phase::Baseline {
                        baseline_samples.push(resp.clone());
                    }
                    if step.phase == Va2Phase::ProtocolVariance {
                        variance_samples.push((resp.status, resp.body.len()));
                    }
                    if step.phase == Va2Phase::StateEscalation {
                        update_statefulness(&mut state_summary, &resp, baseline_samples.first());
                    }
                    if step.phase == Va2Phase::ChallengeInteraction {
                        update_challenge_profile(&mut challenge_profile, &resp);
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
        })
    }
}

fn ensure_va2_consent_and_target(
    consent_manager: &ConsentManager,
    target_url: &str,
) -> Result<()> {
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
    let mut url = Url::parse(target_url).map_err(|err| anyhow!("invalid target url: {err}"))?;
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
        let delta = if *status > baseline_code {
            *status - baseline_code
        } else {
            baseline_code - *status
        };
        if delta > max_delta {
            max_delta = delta;
        }
        let baseline_len = samples.first().map(|(_, l)| *l).unwrap_or(0);
        total_len_delta += (len.saturating_sub(baseline_len)) as f64;
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
    let parsed = Url::parse(target_url).map_err(|err| anyhow!("invalid target url: {err}"))?;
    if parsed.host_str().is_none() {
        return Err(anyhow!("target url must include host"));
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
                    });
                    next_id += 1;
                }
            }
            Va2Phase::ProtocolVariance => {
                let variants = [
                    "/",
                    "/./",
                    "/%2e/",
                    "/%2F",
                    "/index.html",
                ];
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
    struct StubAdapter;

    impl Va2HttpAdapter for StubAdapter {
        fn send(&self, request: &Va2HttpRequest) -> anyhow::Result<Va2HttpResponse> {
            let (status, body) = if request.url.contains("protocol") {
                (418, "teapot".to_string())
            } else if request.url.contains("state") {
                (401, "state escalation".to_string())
            } else if request.url.contains("challenge") {
                (403, "javascript challenge captcha".to_string())
            } else if request.url.contains("error") {
                (500, "server error".to_string())
            } else {
                (200, "baseline ok".to_string())
            };
            let mut headers = HashMap::new();
            if request.url.contains("state") || request.url.contains("challenge") {
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
        std::fs::write(&consent_path, serde_json::to_string_pretty(&record).unwrap()).unwrap();
    }

    #[test]
    fn test_va2_plan_requires_phases() {
        let err = build_va2_campaign_plan(
            "https://example.com",
            &[],
            Va2CampaignConfig::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("at least one phase"));
    }

    #[test]
    fn test_va2_plan_deterministic() {
        let phases = vec![Va2Phase::Baseline, Va2Phase::ProtocolVariance];
        let config = Va2CampaignConfig { seed: 4242, budget: 20 };
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
        let plan = build_va2_campaign_plan(
            "https://example.com",
            &phases,
            Va2CampaignConfig::default(),
        )
        .unwrap();
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("va2-0.1"));
    }

    #[test]
    fn test_va2_runner_requires_consent() {
        with_temp_home(|_temp| {
            let phases = vec![Va2Phase::Baseline];
            let plan = build_va2_campaign_plan(
                "https://example.com",
                &phases,
                Va2CampaignConfig::default(),
            )
            .unwrap();
            let runner = Va2Runner::with_adapter(Box::new(StubAdapter::default())).unwrap();
            let err = runner.run_plan(plan).unwrap_err().to_string();
            assert!(err.contains("Consent is required"));
        });
    }

    #[test]
    fn test_va2_runner_executes_plan() {
        with_temp_home(|temp| {
            write_consent(temp, &["example.com"]);
            let phases = vec![
                Va2Phase::Baseline,
                Va2Phase::ProtocolVariance,
                Va2Phase::StateEscalation,
                Va2Phase::ChallengeInteraction,
            ];
            let mut plan = build_va2_campaign_plan(
                "https://example.com",
                &phases,
                Va2CampaignConfig { seed: 1, budget: 10 },
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
                }
            }
            let runner = Va2Runner::with_adapter(Box::new(StubAdapter::default())).unwrap();
            let report = runner.run_plan(plan).unwrap();
            assert!(!report.results.is_empty());
            assert_eq!(report.results.len(), report.plan.steps.len());
            assert_eq!(report.baseline.status, Some(200));
            assert!(report.normalization.is_some());
            assert!(report.statefulness.is_some());
            assert!(report.challenge.is_some());
        });
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
}
