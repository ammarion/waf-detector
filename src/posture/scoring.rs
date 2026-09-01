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
    // `enforcement_differential_score`, not `differential_score`. The latter
    // counts every paired probe the WAF discriminated against, including ones
    // it inspected and then *allowed* -- which is what a monitor-mode WAF
    // does. Feeding that into an "is it enforcing" term made monitor-mode
    // inspection read as enforcement, and `monitor_mode_likelihood`'s
    // `(1 - enforcement)` factor then suppressed the very verdict the
    // inspection evidence supports.
    let (differential_score, challenge_score) = va2
        .map(|r| (r.wbf.enforcement_differential_score, r.wbf.challenge_score))
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

/// Ceiling on how much behavioral inspection evidence can contribute to "a WAF
/// is present". Below a vendor-header match, which identifies a specific
/// product rather than merely establishing that something is inspecting.
///
/// This applies to evidence drawn from VA2's length-matched pairs only, whose
/// two sides are interchangeable to the origin. That is what rules out the
/// confounder: an application that reflects, sanitizes, or 404s on
/// attack-shaped input produces a benign/attack differential with no WAF
/// involved, and VA2's path/query pairs cannot tell the two apart.
const ORIGIN_EQUIVALENT_INSPECTION_CEILING: f64 = 0.80;

/// Ceiling on how much a latency-only signal can contribute to "a WAF is
/// present". Above the single-channel content ceiling, because the latency
/// score already requires agreement across at least six pairs, but below the
/// multi-channel one: response timing is the signal most exposed to the
/// network between the scanner and the target.
const LATENCY_INSPECTION_CEILING: f64 = 0.65;

/// How likely it is that *something is inspecting traffic*, derived purely
/// from behavior and independent of any vendor signature.
///
/// This exists because passive detection only fires when a product leaves an
/// identifying header, cookie, or certificate behind. A WAF that strips its
/// headers -- or simply doesn't advertise -- scores 0.0 passively, and since
/// `monitor_mode_likelihood` is a product, a 0.0 presence term makes it
/// mathematically impossible to ever report monitor mode for exactly the
/// targets where the question matters most.
///
/// A monitor-mode WAF still inspects. Inspection is observable even when the
/// verdict is "allow": the paired benign/attack probes come back with
/// different headers, different body lengths, or a consistent latency penalty
/// while both still return a non-error status.
pub fn inspection_presence_likelihood(
    va2: Option<&crate::virtual_adversary2::Va2RunReport>,
) -> f64 {
    let Some(report) = va2 else {
        return 0.0;
    };

    // Route 1: on requests the origin cannot distinguish, the response
    // *content* still differed -- an extra header, a rewritten value, a
    // different body length -- while both were allowed through.
    let content_evidence =
        report.wbf.inspection_differential_score * ORIGIN_EQUIVALENT_INSPECTION_CEILING;

    // Route 2: nothing about the response differed except how long it took.
    let latency_evidence = report.wbf.inspection_latency_score * LATENCY_INSPECTION_CEILING;

    // `max`, matching `waf_presence_likelihood`: either observation is on its
    // own a sufficient argument that something inspected the request.
    content_evidence.max(latency_evidence).clamp(0.0, 1.0)
}

/// P(a WAF is present), taking the stronger of the two independent routes to
/// that conclusion: a passive vendor signature, or vendor-agnostic evidence
/// that something is inspecting traffic. `max` rather than a blend because
/// these are alternative sufficient arguments, not partial ones -- a
/// confirmed CloudFlare header is not made less true by the absence of a
/// behavioral differential, and vice versa.
pub fn waf_presence_likelihood(
    passive_detection_confidence: f64,
    va2: Option<&crate::virtual_adversary2::Va2RunReport>,
) -> f64 {
    passive_detection_confidence
        .max(inspection_presence_likelihood(va2))
        .clamp(0.0, 1.0)
}

/// P(WAF present but not enforcing) = P(WAF present) * P(not enforcing).
pub fn monitor_mode_likelihood(
    detection_confidence: f64,
    active_enforcement_likelihood: f64,
) -> f64 {
    (detection_confidence * (1.0 - active_enforcement_likelihood)).clamp(0.0, 1.0)
}

/// Below this, a monitor-mode estimate is a zero rather than a reading.
pub const MONITOR_MODE_ZERO_EPSILON: f64 = 0.01;

/// The sentence appended to a posture summary when monitor mode measured
/// zero, recording why that is not the same as "no monitor-mode WAF here".
pub const MONITOR_MODE_ZERO_CAVEAT: &str =
    "A zero monitor-mode reading does not rule out monitor mode: an inline engine that \
     inspects in microseconds and alters nothing leaves no remote trace (measured against \
     ModSecurity DetectionOnly and AWS WAF Count -- see docs/MONITOR_MODE_VALIDATION.md).";

/// Active-enforcement likelihood, or `None` when neither an enforcement test
/// nor a behavioral campaign ran.
///
/// Same defect as [`monitor_mode_likelihood_measured`]: with no probe the
/// blend has nothing to blend and returns 0.0, which on the wire is
/// indistinguishable from "we attacked this target and it never blocked".
/// Those are opposite conclusions about a WAF.
///
/// The caller keeps the raw `f64` for scoring arithmetic -- an absent probe
/// contributes no enforcement credit, exactly as before. This changes only
/// what is *reported*.
pub fn active_enforcement_likelihood_measured(
    has_enforcement_evidence: bool,
    has_behavioral_evidence: bool,
    raw: f64,
) -> Option<f64> {
    if !has_enforcement_evidence && !has_behavioral_evidence {
        return None;
    }
    Some(raw)
}

/// Monitor-mode likelihood, or `None` when nothing was run that could have
/// observed it.
///
/// Both terms of the product come from an enforcement test or a behavioral
/// campaign. With neither, the result is 0.0 by absence of data rather than
/// by observation -- and a bare `0.0` on the wire reads to any consumer as
/// "this target is not in monitor mode", which is a claim the run never
/// made. `None` says "not determined" instead.
///
/// This predicate previously lived only in the CLI's print gate, so the text
/// output was honest while `--posture-json` was not.
pub fn monitor_mode_likelihood_measured(
    has_enforcement_evidence: bool,
    has_behavioral_evidence: bool,
    waf_presence_likelihood: f64,
    active_enforcement_likelihood: f64,
) -> Option<f64> {
    if !has_enforcement_evidence && !has_behavioral_evidence {
        return None;
    }
    Some(monitor_mode_likelihood(
        waf_presence_likelihood,
        active_enforcement_likelihood,
    ))
}

/// True when a monitor-mode estimate is present and measured zero -- the case
/// that needs `MONITOR_MODE_ZERO_CAVEAT` attached.
pub fn monitor_mode_is_measured_zero(likelihood: Option<f64>) -> bool {
    likelihood.is_some_and(|v| v < MONITOR_MODE_ZERO_EPSILON)
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
                // Both set: an enforcement differential is by definition also a
                // discrimination, and these fixtures describe an *enforcing*
                // WAF, which is what the enforcement term now reads.
                differential_score,
                enforcement_differential_score: differential_score,
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

    /// A VA2 report whose paired probes were inspected-and-allowed (never
    /// blocked), spread across `channels`. This is the monitor-mode shape.
    /// A VA2 report whose paired probes were inspected-and-allowed, never
    /// blocked. `origin_equivalent` selects whether those pairs were the
    /// length-matched kind (whose two sides the origin cannot tell apart) or
    /// the path/query kind (whose two sides it can). This is the monitor-mode
    /// shape.
    fn va2_inspected_not_blocked(pairs: usize, origin_equivalent: bool) -> Va2RunReport {
        use crate::virtual_adversary2::Va2DifferentialResult;
        let mut report = va2_with_scores(0.0, 0.0);
        report.differential = (0..pairs)
            .map(|i| Va2DifferentialResult {
                step_id: (i as u32 * 2) + 2,
                baseline_step_id: (i as u32 * 2) + 1,
                discriminated: true,
                inspection_signal: true,
                enforcement_signal: false,
                latency_matched: origin_equivalent,
                ..Default::default()
            })
            .collect();
        report.wbf.differential_score = 1.0;
        // Mirrors compute_wbf: the inspection rate is only ever computed over
        // origin-equivalent pairs.
        report.wbf.inspection_differential_score = if origin_equivalent { 1.0 } else { 0.0 };
        report.wbf.enforcement_differential_score = 0.0;
        report
    }

    #[test]
    fn test_inspection_presence_zero_without_va2() {
        assert_eq!(inspection_presence_likelihood(None), 0.0);
    }

    #[test]
    fn test_inspection_presence_zero_when_nothing_was_inspected() {
        // The bare-origin case: paired probes ran and found no differential.
        let va2 = va2_with_scores(0.0, 0.0);
        assert_eq!(inspection_presence_likelihood(Some(&va2)), 0.0);
    }

    #[test]
    fn test_inspection_presence_ignores_non_equivalent_pairs() {
        // The bare-origin false positive, as a test. A static file server with
        // nothing in front of it discriminated on 6 of 6 path/query pairs
        // simply because `/api/v1/status` and `/../../etc/passwd` are different
        // requests. That must contribute nothing to "a WAF is present".
        let va2 = va2_inspected_not_blocked(6, false);
        assert_eq!(inspection_presence_likelihood(Some(&va2)), 0.0);
    }

    #[test]
    fn test_inspection_presence_from_origin_equivalent_pairs_clears_threshold() {
        // The same discrimination rate, but on pairs the origin cannot tell
        // apart -- so an intermediary is the only thing left to explain it.
        let va2 = va2_inspected_not_blocked(6, true);
        let presence = inspection_presence_likelihood(Some(&va2));
        assert!(
            presence >= PASSIVE_WAF_PRESENCE_THRESHOLD,
            "inspection on origin-equivalent probes should read as a WAF being present, got {presence}"
        );
    }

    #[test]
    fn test_waf_presence_takes_the_stronger_argument() {
        let va2 = va2_inspected_not_blocked(6, true);
        // A strong vendor signature is not weakened by behavioral evidence...
        assert!((waf_presence_likelihood(0.95, Some(&va2)) - 0.95).abs() < 0.001);
        // ...and behavior carries presence when the vendor signature is absent.
        assert!(waf_presence_likelihood(0.0, Some(&va2)) > 0.5);
    }

    #[test]
    fn test_inspected_but_never_blocked_is_not_counted_as_enforcement() {
        let va2 = va2_inspected_not_blocked(6, true);
        assert_eq!(
            active_enforcement_likelihood(None, Some(&va2)),
            0.0,
            "probes that were inspected and allowed are not enforcement evidence"
        );
    }

    #[test]
    fn test_header_stripping_monitor_mode_waf_is_reportable() {
        // The case the whole feature exists for: a WAF that leaves no passive
        // signature at all (detection_confidence 0.0), inspects traffic across
        // channels, and blocks nothing. Before the presence term existed this
        // was mathematically pinned at 0.0 -- monitor_mode_likelihood is a
        // product, and its first factor was vendor-signature confidence.
        let va2 = va2_inspected_not_blocked(6, true);
        let presence = waf_presence_likelihood(0.0, Some(&va2));
        let enforcement = active_enforcement_likelihood_normalized(None, Some(&va2));
        let monitor = monitor_mode_likelihood(presence, enforcement);
        assert!(
            monitor > 0.5,
            "expected a header-stripping monitor-mode WAF to be reported, got \
             monitor={monitor} (presence={presence}, enforcement={enforcement})"
        );
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
    fn test_enforcement_measured_distinguishes_never_probed_from_never_blocked() {
        // Never probed.
        assert_eq!(
            active_enforcement_likelihood_measured(false, false, 0.0),
            None
        );
        // Probed, and it never blocked -- the opposite conclusion, and the
        // same `0.0` before this change.
        assert_eq!(
            active_enforcement_likelihood_measured(true, false, 0.0),
            Some(0.0)
        );
        assert_ne!(
            active_enforcement_likelihood_measured(false, false, 0.0),
            active_enforcement_likelihood_measured(true, false, 0.0)
        );
    }

    #[test]
    fn test_enforcement_measured_passes_the_raw_value_through() {
        assert_eq!(
            active_enforcement_likelihood_measured(false, true, 0.42),
            Some(0.42)
        );
    }

    #[test]
    fn test_monitor_mode_measured_is_none_without_any_probe_evidence() {
        // Even a maximally confident passive signature says nothing about
        // enforcement, so there is no monitor-mode reading to report.
        assert_eq!(
            monitor_mode_likelihood_measured(false, false, 1.0, 0.0),
            None
        );
    }

    #[test]
    fn test_monitor_mode_measured_is_some_when_either_probe_ran() {
        assert_eq!(
            monitor_mode_likelihood_measured(true, false, 0.9, 0.0),
            Some(0.9)
        );
        assert_eq!(
            monitor_mode_likelihood_measured(false, true, 0.9, 0.0),
            Some(0.9)
        );
    }

    #[test]
    fn test_measured_zero_is_distinguishable_from_not_determined() {
        let not_determined = monitor_mode_likelihood_measured(false, false, 0.0, 0.0);
        let measured_zero = monitor_mode_likelihood_measured(true, true, 0.9, 1.0);

        assert_eq!(not_determined, None);
        assert_eq!(measured_zero, Some(0.0));
        // The whole point: these were both `0.0` before and are now distinct.
        assert_ne!(not_determined, measured_zero);

        assert!(!monitor_mode_is_measured_zero(not_determined));
        assert!(monitor_mode_is_measured_zero(measured_zero));
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
