# Monitor-mode WAF detection signal — design

Date: 2026-08-07
Status: Approved for planning

## Problem

`waf-detect` needs to give a high-confidence signal that a WAF is *present* even
when it is not blocking (log-only / monitor mode). Today, three places in the
codebase produce a classification that conflates "WAF present, not enforcing"
with "no WAF at all", because they never cross-reference passive detection
confidence against active/behavioral enforcement evidence:

- `VaEnforcement::NoEnforcement` (`src/virtual_adversary/mod.rs`, VA1) fires
  identically whether a WAF exists and passes every probe, or no WAF exists.
- `PostureBuilder::compute()` (`src/posture/mod.rs`, the default `--posture`
  command) computes a grade from `detection_confidence` and `enforcement_score`
  but never derives a "monitor mode likely" verdict from the combination.
- `compose_posture_summary()` (same file, only reachable via the separate,
  env-var-gated `--posture-summary` flag) *does* compute this — it's called
  `monitor_mode_likelihood` — but it's VA2-only, not exposed by default, and
  not wired to VA1.

This gap is an existing, explicitly tracked project TODO
(`DEVELOPMENT.md:123-124`: "Monitor-mode detection — infer WAF presence from
subtle behavioral signals when nothing is blocked" and "Posture CLI with
VA1"). This spec closes both.

## Non-goals

- **Not touching risk scoring.** `PostureBuilder::compute()`'s `risk_score`
  and letter `grade` keep their current, byte-identical formula. Specifically:
  `with_va2()` does not and will not feed into `enforcement_score` — that
  divergence from `compose_posture_summary()`'s blended formula is real (see
  Appendix: Known divergence, not fixed here) but changing it would silently
  move grades for every existing `--posture --posture-va2` user. Out of scope.
- **Not fixing `WafModeDetector`** (`src/engine/waf_mode_detector.rs`,
  `DetectionEngine::detect_with_mode_analysis`). Confirmed by repo-wide grep:
  this function has **zero callers** anywhere in `src/`, `tests/`, or
  `benches/`. It is unreachable dead code today — no CLI path invokes it, so
  nothing it computes is ever shown to a user. Fixing its internal
  classification logic without also wiring it to a display surface would be
  work with no observable effect. Flagged as a separate follow-up decision
  (wire it up, or fold its payload-probing approach into
  `payload/waf_smoke_test.rs`'s already-live `determine_waf_mode`, or remove
  it) — not part of this plan.
- **Not adding passive detection to standalone `waf-detect va`/`va2`.**
  Confirmed: neither subcommand handler (`cli/mod.rs:1330-1387`,
  `1389-1425`) calls `DetectionEngine::detect()` today. Adding one would mean
  new network requests and latency for every existing `va`/`va2` user by
  default. The new classification is reachable only through the new
  `--posture --posture-va1` composition, which already fetches passive
  detection first.

## Scope

Three additive changes, all backward compatible except item 2 (see below):

1. **New shared scoring module** `src/posture/scoring.rs` — pure functions,
   no side effects, used by both posture entry points.
2. **New `VaEnforcement::PresentNotEnforcing` variant** (VA1) — a breaking
   change to the enum, intentional (confirmed with the requester): any JSON
   consumer or exhaustive Rust `match` on `VaEnforcement` needs to account
   for the new variant. Repo-wide grep found exactly one exhaustive match
   (`posture/mod.rs:233-239`) and no external consumers in this repo.
3. **New `--posture-va1` CLI flag** wiring VA1 into the default `--posture`
   command, closing the `DEVELOPMENT.md:124` TODO.

## Design

### 1. Shared scoring module (`src/posture/scoring.rs`)

```rust
/// Confidence threshold above which passive detection counts as "a WAF is
/// present" for monitor-mode classification. No prior art in this codebase
/// for a threshold like this (confirmed: no existing has_waf()-style
/// confidence gate) — 0.5 is a defensible default and isolated here so it's
/// trivial to tune later.
pub const PASSIVE_WAF_PRESENCE_THRESHOLD: f64 = 0.5;

/// How likely the target is actively enforcing (blocking/challenging),
/// blended from whichever of VA1/VA2 evidence is available. Same formula
/// `compose_posture_summary` already uses today, extracted so both posture
/// entry points share one implementation.
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
pub fn monitor_mode_likelihood(detection_confidence: f64, active_enforcement_likelihood: f64) -> f64 {
    (detection_confidence * (1.0 - active_enforcement_likelihood)).clamp(0.0, 1.0)
}
```

`compose_posture_summary()` is refactored to call these two functions instead
of its inline copy — output is byte-identical (same formula, same inputs),
confirmed by the existing `test_compose_posture_summary_with_low_signal_caveats`
and `test_compose_posture_summary_coverage_projection` tests passing unedited.

`PostureBuilder::compute()` gains two **new, additive** fields on
`PostureReport`:

```rust
pub struct PostureReport {
    // ...existing fields, unchanged...
    pub active_enforcement_likelihood: f64,   // new
    pub monitor_mode_likelihood: f64,         // new
}
```

Computed at the end of `compute()` from data the builder already tracks
(`self.detection` for `waf_confidence`, plus new private fields
`va1_report: Option<&VaRunReport>` / `va2_report: Option<&Va2RunReport>`
retained by `with_va1`/`with_va2` so `scoring::active_enforcement_likelihood`
can be called — currently the builder only keeps derived scalars, not the
reports themselves, so `with_va1`/`with_va2` need to additionally stash a
clone or reference). These two new fields do **not** feed into
`enforcement_score`, `risk_score`, or `grade` — confirmed against
`test_posture_grade_thresholds` (`posture/mod.rs:434-482`), which must pass
unedited (this is the discriminating check for "did this stay additive").

### 2. VA1 — `VaEnforcement::PresentNotEnforcing`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaEnforcement {
    HardBlock,
    ChallengeGate,
    SilentFilter,
    NoEnforcement,
    PresentNotEnforcing, // new
    Inconclusive,
}
```

`classify_enforcement` (`virtual_adversary/mod.rs:465-488`) gains a new
parameter:

```rust
fn classify_enforcement(
    summary: &VaResultSummary,
    evidence_score: f64,
    passive_waf_confidence: Option<f64>,
) -> VaEnforcement {
    // ...existing logic unchanged...
    // where it currently returns NoEnforcement, instead:
    let base = /* existing NoEnforcement-producing branch */;
    if base == VaEnforcement::NoEnforcement {
        if passive_waf_confidence.unwrap_or(0.0) >= scoring::PASSIVE_WAF_PRESENCE_THRESHOLD {
            return VaEnforcement::PresentNotEnforcing;
        }
    }
    base
}
```

This is a **reclassification**, not plumbing through the runner. The single
existing call site (`virtual_adversary/mod.rs:1239`, inside
`run_with_events_for_target`) passes `None` — standalone `waf-detect va`
output is provably unchanged (the new branch is unreachable with `None`).
`VirtualAdversaryRunner`'s struct and public API (`run`, `run_with_progress`,
`run_with_events`) are untouched — no signature churn beyond the one
private function.

The new `--posture-va1` CLI block (below) runs VA1 normally, then calls
`classify_enforcement(&report.summary, report.evidence_score, Some(waf_confidence))`
a second time and overwrites `report.enforcement` before passing the report
to `PostureBuilder::with_va1`. `waf_confidence` comes from
`detection_result.waf_confidence().unwrap_or(0.0)` — **gated on
`waf_confidence()`, not `detected()`**, because `detected()` is
`has_waf() || has_cdn()` and a CDN-only provider (e.g. Vercel, which is
`provider_type() = CDN`) would otherwise falsely count as "WAF present."

The one exhaustive match on `VaEnforcement` in the whole repo
(`posture/mod.rs:233-239`, inside `with_va1`) gets one new arm:

```rust
VaEnforcement::PresentNotEnforcing => 0.0, // same as NoEnforcement — no new risk-scoring logic
```

This matches the explicit decision made when scoping this design: the new
variant is a labeling fix, not a scoring change.

### 3. `--posture-va1` CLI flag

Mirrors `--posture-va2` (`cli/mod.rs:3496-3502`) exactly in structure:

```rust
.arg(
    Arg::new("posture-va1")
        .long("posture-va1")
        .help("Include enforcement testing (VA1) in posture report")
        .action(clap::ArgAction::SetTrue)
        .requires("posture"),
)
```

Inserted into the `--posture` handler (`cli/mod.rs:717-778`) as a new block
alongside the existing `--posture-va2` block (722-743):

```rust
if matches.get_flag("posture-va1") {
    let config = VirtualAdversaryConfig::default(); // same defaults as standalone `va` with no tuning flags
    let _audit = AuditSession::new("posture_va1", &target, true)?;
    let resolved = resolve_authorized_target(&normalized)?; // same guard standalone `va` uses
    let runner = VirtualAdversaryRunner::new(config)?;
    let mut report = runner.run_with_events_for_target(&resolved, /* ...no-op progress... */).await?;
    let waf_confidence = detection_result.waf_confidence().unwrap_or(0.0);
    report.enforcement = classify_enforcement(&report.summary, report.evidence_score, Some(waf_confidence));
    builder = builder.with_va1(&report);
}
```

`VirtualAdversaryConfig::default()` is used deliberately — the posture-embedded
run does not expose VA1's tuning flags (`--tier`, `--budget`, `--delay`,
`--variants`); a user who needs those runs standalone `waf-detect va` and
feeds the result through `--posture` some other way (out of scope here; no
such composition exists today or is being added). Verified: `Default`
(`tier: 1, request_budget: 120, request_timeout: 15s, request_delay: 750ms,
max_variants_per_payload: 4, skip_dns_validation: false`,
`virtual_adversary/mod.rs:78-89`) is numerically identical, today, to what
flagless `waf-detect va <url>` actually runs (`cli/mod.rs:1336-1347`) — but
that identity is coincidental, not enforced by shared code (the CLI path
builds the struct field-by-field from independent `.unwrap_or(&N)` literals
that happen to match clap's `.default_value(...)` strings, which happen to
match the `Default` impl). Add a unit test asserting
`VirtualAdversaryConfig::default()` equality against the flagless-CLI-parsed
config so future drift in any one of the three places fails loudly instead
of silently diverging `--posture-va1`'s behavior from documented `va`
defaults. `resolve_authorized_target`
and the `AuditSession` tag mirror the guards standalone `va` already applies
(`cli/mod.rs:1362-1370`), so `--posture-va1` doesn't skip existing safety
gates. `classify_enforcement` and `VaEnforcement` need `pub(crate)`
visibility for the CLI module to call/construct against (currently private
to `virtual_adversary`; confirm minimal visibility bump during implementation).

## Data model summary

| Type | Change |
|---|---|
| `VaEnforcement` | +1 variant: `PresentNotEnforcing` (breaking for exhaustive matches/JSON consumers — none found in this repo) |
| `classify_enforcement` | +1 parameter: `passive_waf_confidence: Option<f64>` (private fn, one call site updated, one new call site added) |
| `PostureReport` | +2 fields: `active_enforcement_likelihood: f64`, `monitor_mode_likelihood: f64` (additive, backward compatible) |
| `PostureBuilder` | `with_va1`/`with_va2` retain the report reference so `compute()` can call the shared scoring fns |
| CLI | +1 flag: `--posture-va1` (`.requires("posture")`, mirrors `--posture-va2`) |
| New module | `src/posture/scoring.rs`: `PASSIVE_WAF_PRESENCE_THRESHOLD`, `active_enforcement_likelihood()`, `monitor_mode_likelihood()` |

## Testing

Unit tests (matching existing in-file patterns — hand-built structs, no new
hermetic HTTP fixture infra needed):

- `classify_enforcement`: existing `test_enforcement_classification_no_enforcement`
  (`virtual_adversary/mod.rs:1841-1852`) must pass unedited with the new
  `None` parameter at its call site. New test: same `VaResultSummary` input,
  `Some(0.8)` passive confidence → `PresentNotEnforcing`. New test: `Some(0.2)`
  (below threshold) → stays `NoEnforcement`.
- `posture::scoring`: unit tests for `active_enforcement_likelihood` and
  `monitor_mode_likelihood` in isolation (pure functions, trivial to test).
- `posture::mod::tests`: **`test_posture_grade_thresholds`,
  `test_posture_detection_only`, `test_posture_with_va2`,
  `test_posture_with_channel_coverage` must pass unedited** — this is the
  discriminating check that the new fields stayed additive and didn't touch
  `risk_score`/`grade`. New test: detection present + VA1 with 0% blocked →
  `monitor_mode_likelihood` high, `active_enforcement_likelihood` low, while
  `risk_score`/`grade` match what the same inputs produce today.
- `compose_posture_summary`: existing tests
  (`test_compose_posture_summary_with_low_signal_caveats`,
  `test_compose_posture_summary_coverage_projection`) must pass unedited
  after the extraction refactor.
- CLI: new test in `tests/va_cli_test.rs` for `--posture-va1` flag parsing
  and `.requires("posture")` enforcement, mirroring whatever pattern covers
  `--posture-va2` there today. New test:
  `VirtualAdversaryConfig::default()` equals the config built from
  flagless `va` arg matches (guards the coincidental-identity fact above).

### Functional acceptance (required — unit tests alone do not close this)

Per this project's testing standard, the deliverable is not "done" until run
through the real CLI invocation path:

- `waf-detect --posture <url> --posture-va1 --posture-json` against a real
  target with a passively-detectable WAF confirmed to be in monitor/log-only
  mode (0% block rate on VA1 probes) → expect `enforcement: "PresentNotEnforcing"`
  and `monitor_mode_likelihood` materially above `active_enforcement_likelihood`.
- Negative control: same command against a target with no WAF → expect
  `enforcement: "NoEnforcement"` and `monitor_mode_likelihood` near 0.
- If no real monitor-mode target is available for testing, this is stated as
  **Pending** explicitly rather than substituted with unit-test output.

## Appendix: known divergence, not fixed here

`compose_posture_summary()`'s `active_enforcement_likelihood` blends VA2
differential/challenge scores *and* VA1 blocked-ratio. `PostureBuilder`'s
existing `enforcement_score` (which drives `risk_score`/`grade`) only reflects
VA1's enforcement variant — `with_va2()` never touches it. Confirmed by
`test_posture_grade_thresholds`'s own comment: "base = 100 - 20 - 30... still
C without VA1." This means a WAF that passes every VA2 differential/challenge
probe currently gets no grade penalty unless VA1 also runs and blocks nothing.
This is a real accuracy gap but changing it moves grades for existing
`--posture --posture-va2` users without their asking for a scoring change —
flagged as a follow-up decision, not bundled into this plan.
