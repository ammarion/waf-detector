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
///
/// VA1's contribution counts both blocked AND challenged requests as
/// enforcement evidence, not blocked alone: a target that challenges every
/// probe (`VaEnforcement::ChallengeGate`) is actively enforcing, and treating
/// it as zero enforcement made it read as monitor mode. This matches VA1's own
/// `classify_enforcement`, whose `ChallengeGate`/`SilentFilter` branches also
/// treat challenges as enforcement evidence (e.g. `blocked_rate +
/// challenge_rate >= 0.4` for `SilentFilter`).
pub fn active_enforcement_likelihood(
    va1: Option<&crate::virtual_adversary::VaRunReport>,
    va2: Option<&crate::virtual_adversary2::Va2RunReport>,
) -> f64 {
    let (differential_score, challenge_score) = va2
        .map(|r| (r.wbf.differential_score, r.wbf.challenge_score))
        .unwrap_or((0.0, 0.0));
    let enforcement_ratio = va1
        .map(|r| {
            if r.summary.total > 0 {
                (r.summary.blocked + r.summary.challenge) as f64 / r.summary.total as f64
            } else {
                0.0
            }
        })
        .unwrap_or(0.0);
    ((differential_score * 0.55) + (challenge_score * 0.25) + (enforcement_ratio * 0.20))
        .clamp(0.0, 1.0)
}

/// Like `active_enforcement_likelihood`, but renormalized over only the
/// evidence sources that actually ran. The raw weighted blend (0.55/0.25/0.20
/// for VA2 differential/challenge/VA1 enforcement-ratio) assumes all three
/// signals are available; when only VA1 or only VA2 ran, its ceiling is
/// capped at that source's raw weight (e.g. VA1 alone tops out at 0.20 even
/// at 100% blocked-or-challenged), producing an artificially low score. Used by
/// `PostureBuilder::compute()`, which can be fed VA1 alone (via
/// `--posture-va1` with no `--posture-va2`) — a combination the original
/// formula was never exercised against. `compose_posture_summary` keeps
/// calling the raw, unnormalized `active_enforcement_likelihood` above — it
/// is always called with `va1: None` today, so renormalizing there would be
/// a behavior change with no corresponding real input to justify it, and
/// its existing tests must stay byte-identical.
pub fn active_enforcement_likelihood_normalized(
    va1: Option<&crate::virtual_adversary::VaRunReport>,
    va2: Option<&crate::virtual_adversary2::Va2RunReport>,
) -> f64 {
    let raw = active_enforcement_likelihood(va1, va2);
    let available_weight =
        (if va2.is_some() { 0.80 } else { 0.0 }) + (if va1.is_some() { 0.20 } else { 0.0 });
    if available_weight > 0.0 {
        (raw / available_weight).clamp(0.0, 1.0)
    } else {
        0.0
    }
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

    #[test]
    fn test_active_enforcement_likelihood_normalized_va1_only_high_block_rate() {
        let va1 = va1_with_blocked_ratio(10, 10);
        // Without normalization this would be 0.20 (VA1's raw weight ceiling) --
        // the exact bug this function fixes. Normalized over the only evidence
        // source that ran (VA1, weight 0.20), a 100% block rate must read as
        // maximal enforcement.
        let score = active_enforcement_likelihood_normalized(Some(&va1), None);
        assert!((score - 1.0).abs() < 0.001, "expected 1.0, got {score}");
    }

    #[test]
    fn test_active_enforcement_likelihood_normalized_va2_only_partial_scores() {
        let va2 = va2_with_scores(0.5, 0.5);
        // raw = 0.5*0.55 + 0.5*0.25 = 0.4; available_weight (va2 only) = 0.80;
        // normalized = 0.4 / 0.80 = 0.5
        let score = active_enforcement_likelihood_normalized(None, Some(&va2));
        assert!((score - 0.5).abs() < 0.001, "expected 0.5, got {score}");
    }

    #[test]
    fn test_active_enforcement_likelihood_normalized_both_present_matches_raw() {
        // When both sources ran, available_weight = 1.0, so normalization is a
        // no-op and this must match the raw (unnormalized) function exactly.
        let va1 = va1_with_blocked_ratio(10, 10);
        let va2 = va2_with_scores(1.0, 1.0);
        let raw = active_enforcement_likelihood(Some(&va1), Some(&va2));
        let normalized = active_enforcement_likelihood_normalized(Some(&va1), Some(&va2));
        assert!(
            (raw - normalized).abs() < 0.001,
            "raw={raw}, normalized={normalized}"
        );
    }

    #[test]
    fn test_active_enforcement_likelihood_normalized_no_evidence() {
        assert_eq!(active_enforcement_likelihood_normalized(None, None), 0.0);
    }

    #[test]
    fn test_active_enforcement_likelihood_counts_challenge_not_just_blocked() {
        // A target that challenges (not outright blocks) every VA1 probe is
        // still actively enforcing -- this must NOT read as near-zero
        // enforcement the way a pure blocked_ratio calculation would.
        let mut report =
            VaRunReport::new("https://example.com", 10, VirtualAdversaryConfig::default());
        report.summary = VaResultSummary {
            total: 10,
            blocked: 0,
            challenge: 10,
            allowed: 0,
            error: 0,
        };
        let score = active_enforcement_likelihood(Some(&report), None);
        // enforcement_ratio = (0 + 10)/10 = 1.0, weight 0.20, no VA2 contribution
        assert!((score - 0.20).abs() < 0.001, "expected 0.20, got {score}");
    }

    #[test]
    fn test_active_enforcement_likelihood_normalized_va1_only_all_challenged() {
        let mut report =
            VaRunReport::new("https://example.com", 10, VirtualAdversaryConfig::default());
        report.summary = VaResultSummary {
            total: 10,
            blocked: 0,
            challenge: 10,
            allowed: 0,
            error: 0,
        };
        // Regression test for the bug found during --posture-va1 live
        // verification: a target that's 100% challenged (VaEnforcement::
        // ChallengeGate) must normalize to high enforcement likelihood, not
        // be treated as if nothing happened because none of the requests
        // were outright *blocked*.
        let score = active_enforcement_likelihood_normalized(Some(&report), None);
        assert!((score - 1.0).abs() < 0.001, "expected 1.0, got {score}");
    }
}
