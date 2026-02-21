# MEMORY.md — WAF Detector Working Memory

## Project State

### Current Version
- Main branch: post-PR #26 merge
- Last significant commit: `VA2 paired probes, hermetic fixtures, and posture summary`
- Test count: 363 passing, 0 failed

### Architecture Snapshot
```
src/
├── posture/mod.rs              # NEW: Unified posture report (A-F grade, risk 0-100)
├── virtual_adversary2/
│   ├── mod.rs                  # VA2 behavioral profiling (differential attribution added)
│   └── fixture.rs              # NEW: Hermetic replay adapter for deterministic testing
├── virtual_adversary/mod.rs    # VA1 enforcement testing
├── effectiveness/              # WAF effectiveness testing (consent-gated)
├── cli/mod.rs                  # CLI entry — includes --posture, --va2, --va flags
├── lib.rs                      # Core traits, modules
├── engine/                     # Detection engine
├── providers/                  # WAF/CDN detection (12 providers)
└── web/                        # Axum web server
```

### Key Types and Relationships
- `DetectionResult` (lib.rs) — passive WAF/CDN detection, always available
- `Va2RunReport` (virtual_adversary2/mod.rs) — behavioral profiling, consent-required
  - `Va2WbfSummary` — 5 scores: normalization, statefulness, challenge, throttle, **differential**
  - `Va2PmiScore` — weighted aggregate (0.20/0.20/0.25/0.15/0.20)
  - `Va2DifferentialResult` — per-probe discrimination tracking
- `VaRunReport` (virtual_adversary/mod.rs) — VA1 enforcement testing, consent-required
- `PostureReport` (posture/mod.rs) — aggregates all three into grade + risk score

### Golden Fixtures (tests/fixtures/)
- `cloudflare_waf.json` — blocks SQLi/XSS/path-traversal/cmdi with 403
- `permissive_no_waf.json` — 200 for everything, no protection
- `akamai_challenge.json` — JS challenge (503) on SQLi, hard block (403) on others

## Operational Notes

### Test Budget Sensitivity
The VA2 ProtocolVariance phase now generates 13 steps (3 path-equivalence + 10 paired probes). Tests using all 5 phases need budget >= 25 to avoid truncation before StateEscalation/Challenge/Pressure phases. The `test_va2_runner_executes_plan` test uses budget=30 for this reason.

### Fixture Key Matching
`FixtureAdapter` percent-decodes both path and query before key lookup. Fixture JSON files should use human-readable keys (e.g., `search=1'+OR+'1'='1`) not URL-encoded forms. The `url` crate's WHATWG parser encodes single quotes to `%27`.

### StubAdapter Attack Detection
The test `StubAdapter` returns 403 for URLs containing: `OR`, `script`, `passwd`, `cat+`. This matches the 5 paired-probe attack categories. Be aware of this when writing new tests — any URL containing those substrings will get 403 instead of the phase-based routing.

### PMI Weight History
- Original weights: norm=0.25, state=0.25, challenge=0.30, throttle=0.20 (4 signals)
- Current weights: norm=0.20, state=0.20, challenge=0.25, throttle=0.15, differential=0.20 (5 signals)

### Pre-existing Unstaged Changes
After PR #26, these files have uncommitted modifications from before this session:
- `.github/workflows/benchmark.yml`, `.gitignore`, `src/cli/benchmark.rs`
- `src/engine/mod.rs`, `src/registry/mod.rs`, `src/virtual_adversary/mod.rs`

## Known Gaps / Future Work
1. **Probabilistic enforcement model** — replace linear PMI weights with posterior distribution + confidence intervals
2. **Bypass distance metric** — count transformations needed before WAF response normalizes
3. **Multi-channel perturbation** — extend paired probes to headers/body/method/session (currently path/query only)
4. **Monitor-mode detection** — infer WAF presence from subtle behavioral signals when nothing is blocked
5. **Posture CLI with VA1** — `--posture` currently supports `--posture-va2` but not VA1 integration (would need `--posture-va1` flag + runner invocation)

## GitHub
- Remote: `ammarion/waf-detector` (personal account)
- Active gh account: `ammarion`
- PR convention: feature branches off main, merge via `gh pr merge`
