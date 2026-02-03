//! Virtual Adversary 2.0 (VA2)
//!
//! Behavioral WAF profiling with deterministic, replayable campaigns.

use anyhow::{anyhow, Result};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

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
}
