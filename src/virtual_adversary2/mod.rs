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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Va2RunReport {
    pub target_url: String,
    pub plan: Va2CampaignPlan,
    pub results: Vec<Va2RunResult>,
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
        for step in &plan.steps {
            if step.delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(step.delay_ms));
            }
            let request = build_va2_request(&plan.target_url, step)?;
            let started = Instant::now();
            let response = self.http.send(&request);
            let duration = started.elapsed().as_millis();
            match response {
                Ok(resp) => results.push(Va2RunResult {
                    step_id: step.id,
                    phase: step.phase,
                    kind: step.kind,
                    status: Some(resp.status),
                    duration_ms: duration,
                    error: None,
                }),
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

        Ok(Va2RunReport {
            target_url: plan.target_url.clone(),
            plan,
            results,
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
            Ok(Va2HttpResponse {
                status: if request.url.contains("error") { 500 } else { 200 },
                headers: HashMap::new(),
                body: String::new(),
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
            let phases = vec![Va2Phase::Baseline, Va2Phase::ProtocolVariance];
            let mut plan = build_va2_campaign_plan(
                "https://example.com",
                &phases,
                Va2CampaignConfig { seed: 1, budget: 5 },
            )
            .unwrap();
            for step in &mut plan.steps {
                step.delay_ms = 0;
            }
            let runner = Va2Runner::with_adapter(Box::new(StubAdapter::default())).unwrap();
            let report = runner.run_plan(plan).unwrap();
            assert!(!report.results.is_empty());
            assert_eq!(report.results.len(), report.plan.steps.len());
        });
    }
}
