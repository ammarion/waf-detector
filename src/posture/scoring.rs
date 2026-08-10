//! Shared scoring helpers for posture reporting.
//!
//! Extracted so `compose_posture_summary()` (src/posture/mod.rs, reachable
//! via `--posture-summary`) and `PostureBuilder::compute()` (reachable via
//! the default `--posture` command) share one implementation of "how likely
//! is a WAF present but not enforcing" instead of two divergent formulas.

/// Confidence threshold above which passive detection counts as "a WAF is
/// present" for monitor-mode classification and VA1 reclassification. No
/// prior art for a threshold like this in this codebase — isolated here so
/// it's a one-line change to tune later.
pub const PASSIVE_WAF_PRESENCE_THRESHOLD: f64 = 0.5;

/// Blended estimate of how likely the target is actively enforcing
/// (blocking/challenging), from whichever of VA1/VA2 evidence is available.
/// Same formula `compose_posture_summary` used inline before this extraction.
pub fn active_enforcement_likelihood(
    va1: Option<&crate::virtual_adversary::VaRunReport>,
    va2: Option<&crate::virtual_adversary2::Va2RunReport>,
) -> f64 {
    let (differential_score, challenge_score) = va2
        .map(|r| (r.wbf.differential_score, r.wbf.challenge_score))
        .unwrap_or((0.0, 0.0));
    let blocked_ratio = va1
        .map(|r| {
            if r.summary.total > 0 {
                r.summary.blocked as f64 / r.summary.total as f64
            } else {
                0.0
            }
        })
        .unwrap_or(0.0);
    ((differential_score * 0.55) + (challenge_score * 0.25) + (blocked_ratio * 0.20))
        .clamp(0.0, 1.0)
}

/// P(WAF present but not enforcing) = P(WAF present) * P(not enforcing).
pub fn monitor_mode_likelihood(
    detection_confidence: f64,
    active_enforcement_likelihood: f64,
) -> f64 {
    (detection_confidence * (1.0 - active_enforcement_likelihood)).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtual_adversary::{VaResultSummary, VaRunReport, VirtualAdversaryConfig};
    use crate::virtual_adversary2::{
        Va2BaselineSummary, Va2CampaignPlan, Va2Phase, Va2PmiScore, Va2RunReport, Va2WbfSummary,
    };

    fn va1_with_blocked_ratio(blocked: usize, total: usize) -> VaRunReport {
        let mut report = VaRunReport::new(
            "https://example.com",
            total,
            VirtualAdversaryConfig::default(),
        );
        report.summary = VaResultSummary {
            total,
            blocked,
            challenge: 0,
            allowed: total - blocked,
            error: 0,
        };
        report
    }

    fn va2_with_scores(differential_score: f64, challenge_score: f64) -> Va2RunReport {
        Va2RunReport {
            target_url: "https://example.com".to_string(),
            plan: Va2CampaignPlan {
                version: "va2-0.1".to_string(),
                seed: 1,
                target_url: "https://example.com".to_string(),
                phases: vec![Va2Phase::Baseline],
                budget: 10,
                steps: vec![],
            },
            results: vec![],
            baseline: Va2BaselineSummary::default(),
            normalization: None,
            statefulness: None,
            challenge: None,
            throttle: None,
            wbf: Va2WbfSummary {
                differential_score,
                challenge_score,
                ..Default::default()
            },
            pmi: Va2PmiScore {
                score: 0.0,
                label: "weak".to_string(),
            },
            differential: vec![],
            channel_coverage: None,
            paired_control: None,
            audit: None,
        }
    }

    #[test]
    fn test_active_enforcement_likelihood_no_data() {
        assert_eq!(active_enforcement_likelihood(None, None), 0.0);
    }

    #[test]
    fn test_active_enforcement_likelihood_from_va1_only() {
        let va1 = va1_with_blocked_ratio(10, 10);
        // blocked_ratio=1.0, weight 0.20, no VA2 contribution
        let score = active_enforcement_likelihood(Some(&va1), None);
        assert!((score - 0.20).abs() < 0.001, "expected 0.20, got {score}");
    }

    #[test]
    fn test_active_enforcement_likelihood_from_va2_only() {
        let va2 = va2_with_scores(1.0, 1.0);
        // differential 1.0 * 0.55 + challenge 1.0 * 0.25 = 0.80
        let score = active_enforcement_likelihood(None, Some(&va2));
        assert!((score - 0.80).abs() < 0.001, "expected 0.80, got {score}");
    }

    #[test]
    fn test_active_enforcement_likelihood_clamped_and_blended() {
        let va1 = va1_with_blocked_ratio(10, 10);
        let va2 = va2_with_scores(1.0, 1.0);
        // 0.55 + 0.25 + 0.20 = 1.00, clamp is a no-op here but exercised
        let score = active_enforcement_likelihood(Some(&va1), Some(&va2));
        assert!((score - 1.0).abs() < 0.001, "expected 1.0, got {score}");
    }

    #[test]
    fn test_monitor_mode_likelihood_high_when_present_not_enforcing() {
        // High detection confidence, zero enforcement evidence -> high monitor-mode likelihood
        let score = monitor_mode_likelihood(0.9, 0.0);
        assert!((score - 0.9).abs() < 0.001, "expected 0.9, got {score}");
    }

    #[test]
    fn test_monitor_mode_likelihood_low_when_enforcing() {
        // High detection confidence AND high enforcement evidence -> low monitor-mode likelihood
        let score = monitor_mode_likelihood(0.9, 0.8);
        assert!((score - 0.18).abs() < 0.001, "expected 0.18, got {score}");
    }

    #[test]
    fn test_monitor_mode_likelihood_zero_when_no_waf() {
        // No passive detection at all -> can't claim monitor mode regardless of enforcement
        let score = monitor_mode_likelihood(0.0, 0.0);
        assert_eq!(score, 0.0);
    }
}
