# Monitor-Mode WAF Detection Signal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `waf-detect` a distinct, high-confidence signal for "a WAF is present but not enforcing" (monitor/log-only mode), instead of conflating it with "no WAF at all" in VA1's enforcement classification and the default `--posture` report.

**Architecture:** Extract the existing (but VA2-only, feature-gated) monitor-mode math in `compose_posture_summary()` into a shared `src/posture/scoring.rs` module. Reuse it in two places: (1) a new `VaEnforcement::PresentNotEnforcing` variant, produced by reclassifying VA1's result against passive detection confidence — only reachable through a new `--posture-va1` flag, since standalone `waf-detect va` never runs passive detection; (2) two new additive fields on `PostureReport` so the default `--posture` command (not just the gated `--posture-summary`) shows the monitor-mode likelihood.

**Tech Stack:** Rust, clap (CLI args), serde (JSON), existing in-file `#[cfg(test)]` unit-test pattern (no new hermetic HTTP fixture infra needed — this is pure classification logic operating on already-computed summaries/reports).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-07-monitor-mode-detection-signal-design.md`.
- **Do not change `PostureBuilder::compute()`'s existing `risk_score`/`grade` formula.** The four existing tests `test_posture_detection_only`, `test_posture_with_va2`, `test_posture_grade_thresholds`, `test_posture_with_channel_coverage` (`src/posture/mod.rs`) must pass **unedited** — this is the discriminating check that the new fields stayed additive.
- **`compose_posture_summary()`'s existing tests must also pass unedited**: `test_compose_posture_summary_with_low_signal_caveats`, `test_compose_posture_summary_coverage_projection`.
- `VaEnforcement::PresentNotEnforcing` is a new enum variant — an intentional breaking change to exhaustive matches/JSON consumers of `VaEnforcement`. Confirmed via repo-wide grep: exactly one exhaustive match exists (`src/posture/mod.rs:233-239`), no external consumers in this repo.
- `WafModeDetector` (`src/engine/waf_mode_detector.rs`) is explicitly out of scope — confirmed zero callers of `DetectionEngine::detect_with_mode_analysis` anywhere in `src/`/`tests/`/`benches/`. Do not touch it in this plan.
- Standalone `waf-detect va`/`va2` must not gain new network calls or behavior changes. `classify_enforcement`'s new parameter must default to `None` at its existing call site, provably preserving current behavior.
- Branch-protected `main` — this work happens on `feature/monitor-mode-detection-signal` (already created).
- Pre-commit per project convention: `cargo fmt && cargo clippy -- -D warnings && cargo test --all` before the final commit of each task that touches compiling code.

---

## File Structure

| File | Change |
|---|---|
| `src/posture/scoring.rs` | **Create.** Pure functions: `PASSIVE_WAF_PRESENCE_THRESHOLD`, `active_enforcement_likelihood()`, `monitor_mode_likelihood()`. |
| `src/posture/mod.rs` | Modify: add `pub mod scoring;`, refactor `compose_posture_summary()` to call `scoring::*`, add `PresentNotEnforcing` match arm in `with_va1`, add `active_enforcement_likelihood`/`monitor_mode_likelihood` fields to `PostureReport`/`PostureBuilder`. |
| `src/virtual_adversary/mod.rs` | Modify: add `VaEnforcement::PresentNotEnforcing` variant, change `classify_enforcement` to `pub(crate) fn classify_enforcement(summary, evidence_score, passive_waf_confidence: Option<f64>)`, update its one call site and its two existing unit tests, add two new unit tests. Add `PartialEq` to `VirtualAdversaryConfig`'s derive. |
| `src/cli/mod.rs` | Modify: add `--posture-va1` `Arg`, add it to `completion_global_options()`, add the `--posture-va1` handling block in the `--posture` handler, print `monitor_mode_likelihood` in the human-readable posture output. |
| `tests/va_cli_test.rs` | Modify: add a `--posture-va1` flag-parsing test and a `VirtualAdversaryConfig::default()`-matches-flagless-CLI guard test. |

No new test-infrastructure files are needed — all new tests follow the existing in-file `#[cfg(test)] mod tests` pattern already used in every file being touched.

---

### Task 1: Shared scoring module

**Files:**
- Create: `src/posture/scoring.rs`
- Modify: `src/posture/mod.rs:1-10` (add `pub mod scoring;`)

**Interfaces:**
- Produces: `pub const scoring::PASSIVE_WAF_PRESENCE_THRESHOLD: f64`; `pub fn scoring::active_enforcement_likelihood(va1: Option<&crate::virtual_adversary::VaRunReport>, va2: Option<&crate::virtual_adversary2::Va2RunReport>) -> f64`; `pub fn scoring::monitor_mode_likelihood(detection_confidence: f64, active_enforcement_likelihood: f64) -> f64`.

- [ ] **Step 1: Write the failing tests**

Create `src/posture/scoring.rs` with only the test module (no implementation yet), so it fails to compile / fails to find the functions:

```rust
//! Shared scoring helpers for posture reporting.
//!
//! Extracted so `compose_posture_summary()` (src/posture/mod.rs, reachable
//! via `--posture-summary`) and `PostureBuilder::compute()` (reachable via
//! the default `--posture` command) share one implementation of "how likely
//! is a WAF present but not enforcing" instead of two divergent formulas.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtual_adversary::{VaResultSummary, VaRunReport, VirtualAdversaryConfig};
    use crate::virtual_adversary2::{Va2BaselineSummary, Va2CampaignPlan, Va2PmiScore, Va2Phase, Va2RunReport, Va2WbfSummary};

    fn va1_with_blocked_ratio(blocked: usize, total: usize) -> VaRunReport {
        let mut report = VaRunReport::new("https://example.com", total, VirtualAdversaryConfig::default());
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
```

- [ ] **Step 2: Run tests to verify they fail to compile**

Run: `cargo test --lib posture::scoring`
Expected: compile error — `cannot find function 'active_enforcement_likelihood' in this scope` (and similarly for `monitor_mode_likelihood`).

- [ ] **Step 3: Write the implementation**

Add above the `#[cfg(test)]` block in `src/posture/scoring.rs`:

```rust
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
    ((differential_score * 0.55) + (challenge_score * 0.25) + (blocked_ratio * 0.20)).clamp(0.0, 1.0)
}

/// P(WAF present but not enforcing) = P(WAF present) * P(not enforcing).
pub fn monitor_mode_likelihood(detection_confidence: f64, active_enforcement_likelihood: f64) -> f64 {
    (detection_confidence * (1.0 - active_enforcement_likelihood)).clamp(0.0, 1.0)
}
```

In `src/posture/mod.rs`, add the module declaration near the top (after the existing `use` block, before `pub enum PostureGrade`):

```rust
pub mod scoring;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib posture::scoring`
Expected: 7 tests pass (`test_active_enforcement_likelihood_no_data`, `test_active_enforcement_likelihood_from_va1_only`, `test_active_enforcement_likelihood_from_va2_only`, `test_active_enforcement_likelihood_clamped_and_blended`, `test_monitor_mode_likelihood_high_when_present_not_enforcing`, `test_monitor_mode_likelihood_low_when_enforcing`, `test_monitor_mode_likelihood_zero_when_no_waf`).

- [ ] **Step 5: Commit**

```bash
git add src/posture/scoring.rs src/posture/mod.rs
git commit -m "feat: add shared posture scoring module for monitor-mode likelihood"
```

---

### Task 2: Refactor `compose_posture_summary()` to use the shared scoring module

**Files:**
- Modify: `src/posture/mod.rs:84-171` (the `compose_posture_summary` function body)

**Interfaces:**
- Consumes: `scoring::active_enforcement_likelihood()`, `scoring::monitor_mode_likelihood()` from Task 1.
- Produces: no change to `compose_posture_summary`'s public signature or `crate::PostureSummary`'s fields — output must be byte-identical to before this refactor.

- [ ] **Step 1: Run the existing tests to capture the current baseline**

Run: `cargo test --lib posture::tests::test_compose_posture_summary_with_low_signal_caveats posture::tests::test_compose_posture_summary_coverage_projection`
Expected: both PASS (this is the pre-refactor baseline — confirms these tests exist and pass before you touch anything).

- [ ] **Step 2: Replace the inline formulas with calls to the shared module**

In `src/posture/mod.rs`, inside `compose_posture_summary`, replace:

```rust
    let (differential_score, challenge_score, pair_count, coverage_score) = va2
        .map(|report| {
            if let Some(coverage) = &report.channel_coverage {
                for (channel, score) in &coverage.channels {
                    coverage_by_vector.insert(channel.to_string(), *score);
                }
            }
            let pairs = report
                .paired_control
                .as_ref()
                .map(|p| p.executed_pairs)
                .unwrap_or(report.differential.len());
            (
                report.wbf.differential_score,
                report.wbf.challenge_score,
                pairs,
                report
                    .channel_coverage
                    .as_ref()
                    .map(|c| c.coverage_score)
                    .unwrap_or(0.0),
            )
        })
        .unwrap_or((0.0, 0.0, 0, 0.0));

    let blocked_ratio = va1
        .map(|report| {
            let total = report.summary.total as f64;
            if total > 0.0 {
                report.summary.blocked as f64 / total
            } else {
                0.0
            }
        })
        .unwrap_or(0.0);

    let active_enforcement_likelihood =
        ((differential_score * 0.55) + (challenge_score * 0.25) + (blocked_ratio * 0.20))
            .clamp(0.0, 1.0);

    let monitor_mode_likelihood =
        (detection_confidence * (1.0 - active_enforcement_likelihood)).clamp(0.0, 1.0);
```

with:

```rust
    let (pair_count, coverage_score) = va2
        .map(|report| {
            if let Some(coverage) = &report.channel_coverage {
                for (channel, score) in &coverage.channels {
                    coverage_by_vector.insert(channel.to_string(), *score);
                }
            }
            let pairs = report
                .paired_control
                .as_ref()
                .map(|p| p.executed_pairs)
                .unwrap_or(report.differential.len());
            (
                pairs,
                report
                    .channel_coverage
                    .as_ref()
                    .map(|c| c.coverage_score)
                    .unwrap_or(0.0),
            )
        })
        .unwrap_or((0, 0.0));

    let active_enforcement_likelihood = scoring::active_enforcement_likelihood(va1, va2);
    let monitor_mode_likelihood =
        scoring::monitor_mode_likelihood(detection_confidence, active_enforcement_likelihood);
```

(`differential_score`/`challenge_score`/`blocked_ratio` locals are removed entirely — nothing else in the function used them outside the two computations just replaced; `pair_count`/`coverage_score` are still needed below for `caveats` and `overall_posture_score`, so they're kept.)

- [ ] **Step 3: Run the existing tests to confirm byte-identical output**

Run: `cargo test --lib posture::tests::test_compose_posture_summary_with_low_signal_caveats posture::tests::test_compose_posture_summary_coverage_projection`
Expected: both PASS, unedited, with no assertion changes. If either fails, the refactor changed behavior — stop and diff the formula against Task 1's `scoring.rs` implementation before proceeding.

- [ ] **Step 4: Run the full posture module test suite**

Run: `cargo test --lib posture::`
Expected: all tests in `src/posture/mod.rs` and `src/posture/scoring.rs` PASS.

- [ ] **Step 5: Commit**

```bash
git add src/posture/mod.rs
git commit -m "refactor: compose_posture_summary delegates to shared scoring module"
```

---

### Task 3: Add `VaEnforcement::PresentNotEnforcing` variant

**Files:**
- Modify: `src/virtual_adversary/mod.rs` (enum definition, ~line 595-602)
- Modify: `src/posture/mod.rs:233-239` (the one exhaustive match on `VaEnforcement`)

**Interfaces:**
- Produces: `VaEnforcement::PresentNotEnforcing` (new variant, `Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize` — same derives as its siblings).
- Consumed by: Task 4 (`classify_enforcement` will produce it), Task 5/6 (posture output will display it).

- [ ] **Step 1: Add the variant (this is a compile-breaking change until Step 2)**

In `src/virtual_adversary/mod.rs`, change:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaEnforcement {
    HardBlock,
    ChallengeGate,
    SilentFilter,
    NoEnforcement,
    Inconclusive,
}
```

to:

```rust
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
```

- [ ] **Step 2: Run the build to find the compile error**

Run: `cargo check --lib`
Expected: FAIL — `non-exhaustive patterns: 'VaEnforcement::PresentNotEnforcing' not covered` pointing at `src/posture/mod.rs:233`.

- [ ] **Step 3: Fix the exhaustive match**

In `src/posture/mod.rs`, inside `PostureBuilder::with_va1`, change:

```rust
        self.enforcement_score = match report.enforcement {
            VaEnforcement::HardBlock => confidence,
            VaEnforcement::ChallengeGate => confidence * 0.8,
            VaEnforcement::SilentFilter => confidence * 0.5,
            VaEnforcement::NoEnforcement => 0.0,
            VaEnforcement::Inconclusive => confidence * 0.3,
        };
```

to:

```rust
        self.enforcement_score = match report.enforcement {
            VaEnforcement::HardBlock => confidence,
            VaEnforcement::ChallengeGate => confidence * 0.8,
            VaEnforcement::SilentFilter => confidence * 0.5,
            VaEnforcement::NoEnforcement => 0.0,
            // Same score as NoEnforcement — this variant changes the label,
            // not the enforcement-strength math. See spec section 2 / Global
            // Constraints: no new risk-scoring logic for this variant.
            VaEnforcement::PresentNotEnforcing => 0.0,
            VaEnforcement::Inconclusive => confidence * 0.3,
        };
```

- [ ] **Step 4: Run the build and full test suite to confirm nothing else broke**

Run: `cargo check --lib && cargo test --lib`
Expected: builds clean; all existing tests PASS unedited (no test currently constructs `VaEnforcement::PresentNotEnforcing`, so nothing new to assert yet — this task only proves the codebase still compiles and existing behavior is untouched).

- [ ] **Step 5: Commit**

```bash
git add src/virtual_adversary/mod.rs src/posture/mod.rs
git commit -m "feat: add VaEnforcement::PresentNotEnforcing variant"
```

---

### Task 4: Passive-confidence-aware reclassification in `classify_enforcement`

**Files:**
- Modify: `src/virtual_adversary/mod.rs:465-488` (`classify_enforcement` function)
- Modify: `src/virtual_adversary/mod.rs:1239` (its one production call site)
- Modify: `src/virtual_adversary/mod.rs:1829-1852` (its two existing unit tests — add the new parameter)

**Interfaces:**
- Consumes: `VaEnforcement::PresentNotEnforcing` (Task 3), `scoring::PASSIVE_WAF_PRESENCE_THRESHOLD` (Task 1).
- Produces: `pub(crate) fn classify_enforcement(summary: &VaResultSummary, evidence_score: f64, passive_waf_confidence: Option<f64>) -> VaEnforcement` — visibility raised from private to `pub(crate)` so `src/cli/mod.rs` (Task 6) can call it directly for reclassification.

- [ ] **Step 1: Update the two existing tests' call sites (still expected to pass — regression baseline)**

In `src/virtual_adversary/mod.rs`, change:

```rust
    #[test]
    fn test_enforcement_classification_hard_block() {
        let summary = VaResultSummary {
            total: 10,
            blocked: 6,
            challenge: 1,
            allowed: 3,
            error: 0,
        };
        let enforcement = classify_enforcement(&summary, 0.7);
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
        let enforcement = classify_enforcement(&summary, 0.2);
        assert_eq!(enforcement, VaEnforcement::NoEnforcement);
    }
```

to:

```rust
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
```

- [ ] **Step 2: Run tests to verify they fail (wrong arity)**

Run: `cargo test --lib virtual_adversary::tests::test_enforcement_classification`
Expected: compile error — `this function takes 3 arguments but 2 arguments were supplied` (from the two updated call sites, before the implementation is updated) or `takes 2 arguments but 3 were supplied` (from the three new tests, against the old 2-arg signature) — either way, a compile failure confirming the tests are exercising the not-yet-changed signature.

- [ ] **Step 3: Update `classify_enforcement`'s implementation**

In `src/virtual_adversary/mod.rs`, change:

```rust
fn classify_enforcement(summary: &VaResultSummary, evidence_score: f64) -> VaEnforcement {
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
        return VaEnforcement::NoEnforcement;
    }

    VaEnforcement::Inconclusive
}
```

to:

```rust
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
        if passive_waf_confidence.unwrap_or(0.0) >= crate::posture::scoring::PASSIVE_WAF_PRESENCE_THRESHOLD {
            return VaEnforcement::PresentNotEnforcing;
        }
        return VaEnforcement::NoEnforcement;
    }

    VaEnforcement::Inconclusive
}
```

- [ ] **Step 4: Update the one production call site**

In `src/virtual_adversary/mod.rs:1239`, change:

```rust
        report.enforcement = classify_enforcement(&report.summary, report.evidence_score);
```

to:

```rust
        // Standalone VA1 runs (this call site, used by `run_with_events`/
        // `run`/`waf-detect va`) never have passive detection available.
        report.enforcement = classify_enforcement(&report.summary, report.evidence_score, None);
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib virtual_adversary::`
Expected: all tests in `src/virtual_adversary/mod.rs` PASS, including the 3 new ones and the 2 updated ones.

- [ ] **Step 6: Run the full test suite to confirm no other regressions**

Run: `cargo test --all`
Expected: all tests PASS (this is the point where a stray exhaustive match elsewhere, if the earlier grep missed one, would surface).

- [ ] **Step 7: Commit**

```bash
git add src/virtual_adversary/mod.rs
git commit -m "feat: classify_enforcement reclassifies to PresentNotEnforcing given passive WAF confidence"
```

---

### Task 5: Additive `PostureReport` fields for the default `--posture` command

**Files:**
- Modify: `src/posture/mod.rs` (`PostureReport` struct, `PostureBuilder` struct, `with_va1`, `with_va2`, `compute`)

**Interfaces:**
- Consumes: `scoring::active_enforcement_likelihood()`, `scoring::monitor_mode_likelihood()` (Task 1).
- Produces: `PostureReport.active_enforcement_likelihood: f64`, `PostureReport.monitor_mode_likelihood: f64` — new fields, additive, do not affect `risk_score`/`grade`.

- [ ] **Step 1: Write the failing test**

In `src/posture/mod.rs`'s `#[cfg(test)] mod tests`, add:

```rust
    #[test]
    fn test_posture_monitor_mode_likelihood_high_when_waf_present_and_not_blocking() {
        let det = mock_detection_result(0.9);
        let va1 = VaRunReport {
            target_url: "https://example.com".to_string(),
            plan_size: 10,
            replay_plan: vec![],
            summary: VaResultSummary {
                total: 10,
                blocked: 0,
                challenge: 0,
                allowed: 10,
                error: 0,
            },
            enforcement: VaEnforcement::PresentNotEnforcing,
            evidence_score: 0.1,
            evidence_summary: vec![],
            config: VirtualAdversaryConfig::default(),
            results: vec![],
            started_at: std::time::Instant::now(),
            finished_at: None,
            replay_bundle: None,
            audit: None,
        };
        let report = PostureBuilder::new("https://example.com")
            .with_detection(&det)
            .with_va1(&va1)
            .compute();

        // Additive fields reflect "WAF present, not enforcing":
        assert!(report.monitor_mode_likelihood > 0.7, "got {}", report.monitor_mode_likelihood);
        assert!(report.active_enforcement_likelihood < 0.3, "got {}", report.active_enforcement_likelihood);

        // Discriminating check: grade/risk_score math is UNTOUCHED.
        // enforcement_score for PresentNotEnforcing is 0.0 (same as
        // NoEnforcement, per Task 3) -> base = 100 - (20*0.9) - (20*0.0) = 82.
        assert!(report.risk_score > 81.0 && report.risk_score < 83.0, "got {}", report.risk_score);
        assert_eq!(report.grade, PostureGrade::F);
    }

    #[test]
    fn test_posture_monitor_mode_likelihood_zero_with_no_detection() {
        let report = PostureBuilder::new("https://example.com").compute();
        assert_eq!(report.monitor_mode_likelihood, 0.0);
        assert_eq!(report.active_enforcement_likelihood, 0.0);
    }
```

Add the two required imports (`VaResultSummary`, `VirtualAdversaryConfig`) to the test module's existing `use crate::virtual_adversary::{VaEnforcement, VaRunReport};`-style import if not already present — check the top of `mod tests` in `src/posture/mod.rs` first, since `VaResultSummary`/`VirtualAdversaryConfig` are already imported there for `test_posture_grade_thresholds` (line ~452).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib posture::tests::test_posture_monitor_mode_likelihood`
Expected: compile error — `no field 'monitor_mode_likelihood' on type 'PostureReport'`.

- [ ] **Step 3: Add the fields and wire them up**

In `src/posture/mod.rs`, change the `PostureReport` struct:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureReport {
    pub target_url: String,
    pub timestamp: DateTime<Utc>,
    pub grade: PostureGrade,
    pub risk_score: f64,
    pub detection: Option<DetectionPosture>,
    pub behavioral: Option<BehavioralPosture>,
    pub enforcement: Option<EnforcementPosture>,
    pub summary: String,
    /// Blended estimate that the target is actively enforcing (blocking/
    /// challenging), from whichever of VA1/VA2 ran. Additive: does not
    /// affect `risk_score`/`grade`.
    pub active_enforcement_likelihood: f64,
    /// P(WAF present but not enforcing) = detection confidence * (1 -
    /// active_enforcement_likelihood). Additive: does not affect
    /// `risk_score`/`grade`.
    pub monitor_mode_likelihood: f64,
}
```

Change `PostureBuilder` to retain the reports it's given (needed so `compute()` can call the shared scoring functions, which take `Option<&VaRunReport>`/`Option<&Va2RunReport>`):

```rust
pub struct PostureBuilder {
    target_url: String,
    detection: Option<DetectionPosture>,
    detection_confidence: f64,
    behavioral: Option<BehavioralPosture>,
    pmi_normalized: f64,
    channel_coverage_score: f64,
    enforcement: Option<EnforcementPosture>,
    enforcement_score: f64,
    va1_report: Option<VaRunReport>,
    va2_report: Option<Va2RunReport>,
}
```

In `PostureBuilder::new`, add the two new fields initialized to `None`:

```rust
            enforcement: None,
            enforcement_score: 0.0,
            va1_report: None,
            va2_report: None,
        }
    }
```

In `with_va2`, add at the end (before the trailing `self`):

```rust
        self.va2_report = Some(report.clone());
        self
    }
```

In `with_va1`, add at the end (before the trailing `self`):

```rust
        self.va1_report = Some(report.clone());
        self
    }
```

In `compute()`, add before constructing the final `PostureReport { ... }` literal:

```rust
        let active_enforcement_likelihood =
            scoring::active_enforcement_likelihood(self.va1_report.as_ref(), self.va2_report.as_ref());
        let monitor_mode_likelihood =
            scoring::monitor_mode_likelihood(self.detection_confidence, active_enforcement_likelihood);
```

and add the two fields to the `PostureReport { ... }` literal:

```rust
        PostureReport {
            target_url: self.target_url,
            timestamp: Utc::now(),
            grade,
            risk_score,
            detection: self.detection,
            behavioral: self.behavioral,
            enforcement: self.enforcement,
            summary,
            active_enforcement_likelihood,
            monitor_mode_likelihood,
        }
```

Confirmed: `VaRunReport` (`virtual_adversary/mod.rs:546`) and `Va2RunReport` (`virtual_adversary2/mod.rs:318`) both already derive `Clone` — `.clone()` above needs no further derive changes.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib posture::`
Expected: all tests PASS, including the 2 new ones AND the 4 existing grade/risk_score tests (`test_posture_detection_only`, `test_posture_with_va2`, `test_posture_grade_thresholds`, `test_posture_with_channel_coverage`) unedited — this is the discriminating check from Global Constraints.

- [ ] **Step 5: Run the full test suite**

Run: `cargo test --all`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add src/posture/mod.rs
git commit -m "feat: add monitor_mode_likelihood and active_enforcement_likelihood to PostureReport"
```

---

### Task 6: `--posture-va1` CLI flag

**Files:**
- Modify: `src/virtual_adversary/mod.rs` (add `PartialEq` to `VirtualAdversaryConfig`'s derive)
- Modify: `src/cli/mod.rs` (new `Arg`, completion list entry, handler block, output line)
- Modify: `tests/va_cli_test.rs` (new tests)

**Interfaces:**
- Consumes: `classify_enforcement` (now `pub(crate)`, Task 4), `PostureBuilder::with_va1` (existing), `resolve_authorized_target`/`AuditSession`/`VirtualAdversaryRunner` (existing, already imported in `cli/mod.rs` — used by the standalone `va` handler and the `--posture-va2` block).

- [ ] **Step 1: Add `PartialEq` to `VirtualAdversaryConfig` (needed for the guard test in Step 6)**

In `src/virtual_adversary/mod.rs`, change:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualAdversaryConfig {
```

to:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VirtualAdversaryConfig {
```

Run: `cargo check --lib`
Expected: builds clean (`u8`, `u32`, `std::time::Duration`, `bool` all implement `PartialEq`).

- [ ] **Step 2: Write the failing CLI tests**

Confirmed from the existing file: the builder function is `waf_detector::cli::build_simple_cli()` (already imported at `tests/va_cli_test.rs:3`), it is the ROOT `Command` — `--posture`/`--posture-va2` are top-level args on it (parsed directly off the root `matches`, same as `test_va_cli_defaults` parses `--va`'s top-level args) — while `tier`/`budget`/etc. (unprefixed arg ids) belong to the nested `va` **subcommand** (`build_va_subcommand()`, registered via `.subcommand(build_va_subcommand())`), reached only through `matches.subcommand_matches("va")`. `run_va_subcommand` (`cli/mod.rs:1330-1347`) reads exactly those subcommand-scoped ids. Add to `tests/va_cli_test.rs`:

```rust
#[test]
fn test_posture_va1_requires_posture() {
    let cmd = build_simple_cli();
    let result = cmd.try_get_matches_from(["waf-detect", "--posture-va1"]);
    assert!(result.is_err(), "expected --posture-va1 without --posture to fail");
}

#[test]
fn test_posture_va1_parses_with_posture() {
    let cmd = build_simple_cli();
    let matches = cmd
        .try_get_matches_from(["waf-detect", "--posture", "https://example.com", "--posture-va1"])
        .expect("--posture-va1 with --posture should parse");
    assert!(matches.get_flag("posture-va1"));
}

#[test]
fn test_virtual_adversary_config_default_matches_flagless_va_subcommand() {
    // Guards the fact documented in the design spec: VirtualAdversaryConfig::default()
    // is only coincidentally identical to flagless `waf-detect va <url>` today (three
    // independently-maintained literal sets — clap's .default_value(...) strings,
    // run_va_subcommand's .unwrap_or(&N) fallbacks, and the Default impl). If this
    // test ever fails, --posture-va1's use of VirtualAdversaryConfig::default() has
    // silently drifted from documented `va` defaults.
    let cmd = build_simple_cli();
    let matches = cmd
        .try_get_matches_from(["waf-detect", "va", "https://example.com"])
        .expect("flagless va subcommand should parse");
    let sub_matches = matches
        .subcommand_matches("va")
        .expect("va subcommand matches should be present");
    let cli_config = waf_detector::virtual_adversary::VirtualAdversaryConfig {
        tier: *sub_matches.get_one::<u8>("tier").unwrap_or(&1),
        request_budget: *sub_matches.get_one::<u32>("budget").unwrap_or(&120),
        request_timeout: std::time::Duration::from_secs(
            *sub_matches.get_one::<u64>("timeout").unwrap_or(&15),
        ),
        request_delay: std::time::Duration::from_millis(
            *sub_matches.get_one::<u64>("delay").unwrap_or(&750),
        ),
        max_variants_per_payload: *sub_matches.get_one::<u8>("variants").unwrap_or(&4),
        skip_dns_validation: false,
    };
    assert_eq!(
        cli_config,
        waf_detector::virtual_adversary::VirtualAdversaryConfig::default()
    );
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --test va_cli_test test_posture_va1 test_virtual_adversary_config_default`
Expected: FAIL — `unknown argument '--posture-va1'` (arg doesn't exist yet) for the first two, and the third should currently PASS already (it's asserting today's actual behavior, not a new feature) — if it fails, that's a genuine discovery that the coincidental-identity claim in the spec no longer holds and must be resolved before continuing (do not silently change the assertion to match; report it).

- [ ] **Step 4: Add the `--posture-va1` Arg definition**

In `src/cli/mod.rs`, immediately after the `posture-va2` arg block (~line 3496-3502):

```rust
        .arg(
            Arg::new("posture-va2")
                .long("posture-va2")
                .help("Include behavioral analysis in posture report")
                .action(clap::ArgAction::SetTrue)
                .requires("posture"),
        )
        .arg(
            Arg::new("posture-va1")
                .long("posture-va1")
                .help("Include enforcement testing (VA1) in posture report")
                .action(clap::ArgAction::SetTrue)
                .requires("posture"),
        )
```

- [ ] **Step 5: Add `--posture-va1` to the shell-completion list**

In `src/cli/mod.rs`'s `completion_global_options()` (~line 226-229), change:

```rust
        "--posture",
        "--posture-summary",
        "--posture-va2",
        "--posture-json",
```

to:

```rust
        "--posture",
        "--posture-summary",
        "--posture-va2",
        "--posture-va1",
        "--posture-json",
```

- [ ] **Step 6: Add the `--posture-va1` handler block**

In `src/cli/mod.rs`'s `--posture` handler, immediately after the `--posture-va2` block and before `let posture = builder.compute();` (~line 743-745):

```rust
            if matches.get_flag("posture-va2") {
                // ...unchanged...
                builder = builder.with_va2(&report);
            }

            if matches.get_flag("posture-va1") {
                let config = VirtualAdversaryConfig::default();
                let target = resolve_authorized_target(&normalized)?;
                let mut audit = AuditSession::new("posture_va1", &target, true)?;
                let mut runner = VirtualAdversaryRunner::new(config)?;
                let mut report = match runner.run_with_events_for_target(&target, |_, _| {}, |_| {}) {
                    Ok(report) => report,
                    Err(err) => {
                        audit.record_failed(&err.to_string())?;
                        return Err(err);
                    }
                };
                audit.record_completed()?;
                report.audit = Some(audit.snapshot());
                let waf_confidence = detection_result.waf_confidence().unwrap_or(0.0);
                report.enforcement = crate::virtual_adversary::classify_enforcement(
                    &report.summary,
                    report.evidence_score,
                    Some(waf_confidence),
                );
                builder = builder.with_va1(&report);
            }

            let posture = builder.compute();
```

(This mirrors the `--posture-va2` block's structure and safety gates: `resolve_authorized_target` and `AuditSession` are the same guards standalone `waf-detect va` applies, at `cli/mod.rs:1362-1370`. `classify_enforcement` needs to be `pub(crate)`, done in Task 4 Step 3 — if it's still private when this step runs, `cargo check` will report a visibility error here.)

- [ ] **Step 7: Print `monitor_mode_likelihood` in the human-readable posture output**

In the same handler, change:

```rust
                if let Some(enf) = &posture.enforcement {
                    println!(
                        "  Enforce:    {} ({:.0}%)",
                        enf.enforcement,
                        enf.confidence_score * 100.0
                    );
                }
                println!("  Summary:    {}", posture.summary);
```

to:

```rust
                if let Some(enf) = &posture.enforcement {
                    println!(
                        "  Enforce:    {} ({:.0}%)",
                        enf.enforcement,
                        enf.confidence_score * 100.0
                    );
                }
                if posture.monitor_mode_likelihood > 0.01 {
                    println!(
                        "  Monitor-mode likelihood: {:.0}%",
                        posture.monitor_mode_likelihood * 100.0
                    );
                }
                println!("  Summary:    {}", posture.summary);
```

- [ ] **Step 8: Run the CLI tests to verify they pass**

Run: `cargo test --test va_cli_test test_posture_va1 test_virtual_adversary_config_default`
Expected: all PASS.

- [ ] **Step 9: Run the full test suite**

Run: `cargo test --all`
Expected: all PASS.

- [ ] **Step 10: Format, lint, and commit**

```bash
cargo fmt
cargo clippy -- -D warnings
git add src/virtual_adversary/mod.rs src/cli/mod.rs tests/va_cli_test.rs
git commit -m "feat: add --posture-va1 flag wiring VA1 into the default posture command"
```

---

### Task 7: Full regression + functional acceptance

**Files:** none (verification only).

- [ ] **Step 1: Full workspace test run**

Run: `cargo test --all`
Expected: all tests PASS, zero failures, zero ignored-but-expected-to-run tests skipped.

- [ ] **Step 2: Lint and format check**

Run: `cargo fmt --check && cargo clippy -- -D warnings`
Expected: no diffs, no warnings.

- [ ] **Step 3: Build the release binary**

Run: `cargo build --release`
Expected: builds clean.

- [ ] **Step 4: Functional acceptance — real invocation path**

Per this project's testing standard, unit tests above do not close this out. Run the actual CLI against real targets:

```bash
./target/release/waf-detect --posture <known-monitor-mode-target> --posture-va1 --posture-json
```

Expected: `enforcement: "PresentNotEnforcing"` in the `EnforcementPosture`, and `monitor_mode_likelihood` materially higher than `active_enforcement_likelihood` in the JSON output.

```bash
./target/release/waf-detect --posture <no-waf-target> --posture-va1 --posture-json
```

Expected: `enforcement: "NoEnforcement"`, `monitor_mode_likelihood` near 0.

**If no known monitor-mode target is available to test against**, do not substitute unit-test output for this step. Report it explicitly as Pending: "Unit and CLI-parsing tests pass (Ran); PresentNotEnforcing reclassification and monitor_mode_likelihood computation are exercised in isolation (Proves: the logic is correct given its inputs); the real end-to-end `--posture-va1` run against a live monitor-mode WAF is Pending — no such target was available during implementation."

- [ ] **Step 5: Final commit and summary**

```bash
git log --oneline feature/monitor-mode-detection-signal ^main
```

Confirm the branch contains exactly the 6 feature commits from Tasks 1-6 plus this task's verification (no code changes to commit for Task 7 itself, unless Step 4 surfaced a bug — if it did, fix it, add a regression test, and commit before declaring this done).
