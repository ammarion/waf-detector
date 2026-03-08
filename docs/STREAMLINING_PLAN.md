# Streamlining Plan

Full plan to streamline the waf-detector codebase while keeping agent skills in sync. Follow AGENTS.md: when the CLI or code surface changes, update the relevant WORKFLOW.md in the same commit.

## Skills Integration Rules

- **Same-commit updates**: Any change that affects CLI flags, subcommands, output format, or consent flow must update the relevant `agent-skills/*/WORKFLOW.md` in the same commit.
- **Validate after each phase**: Run `python3 agent-skills/check_wrappers.py` and `agent-skills/validate-build/WORKFLOW.md` before considering a phase complete.
- **Workflow touchpoints**:
  - `waf-assess` — detection, smoke, effectiveness, va, va2, posture, origin-probe, consent
  - `cli-doctor` — doctor, completions
  - `security-audit` — module paths, risky patterns
  - `validate-build` — fmt, clippy, test, release build

---

## Phase 0: Skills Foundation

**Goal**: Add new skills and strengthen discovery so agents can participate in streamlining.

### 0.1 Add codebase-explore skill

| Artifact | Action |
|----------|--------|
| `agent-skills/codebase-explore/WORKFLOW.md` | Create workflow: how to explore the codebase, map modules, find duplication, identify streamlining opportunities |
| `check_wrappers.py` | Add `codebase-explore` to SKILLS |
| `.claude/skills/codebase-explore.md` | Create thin wrapper |
| `.codex/skills/codebase-explore/SKILL.md` | Create thin wrapper |
| `AGENTS.md` | Add mapping: "Codebase exploration, architecture review, streamlining opportunities: `agent-skills/codebase-explore/WORKFLOW.md`" |

**Description**: "Use when the user wants to understand the codebase, find streamlining opportunities, explore architecture, or map module dependencies."

### 0.2 Add provider-dev skill

| Artifact | Action |
|----------|--------|
| `agent-skills/provider-dev/WORKFLOW.md` | Create workflow: add new provider (create file, implement DetectionProvider, register in SimpleCliApp::new, add tests). Reference CLAUDE.md provider pattern. |
| `check_wrappers.py` | Add `provider-dev` to SKILLS |
| `.claude/skills/provider-dev.md` | Create thin wrapper |
| `.codex/skills/provider-dev/SKILL.md` | Create thin wrapper |
| `AGENTS.md` | Add mapping: "Adding a new WAF/CDN provider: `agent-skills/provider-dev/WORKFLOW.md`" |

**Description**: "Use when adding a new WAF/CDN provider or extending detection logic."

### 0.3 Add "when to use" table to AGENTS.md

Add a quick-reference table mapping user intent to skills (optional but helpful for routing).

### Gate

```bash
python3 agent-skills/check_wrappers.py
cargo test -q
```

---

## Phase 1: Quick Wins

**Goal**: Remove dead code, fix docs, eliminate placeholders. No CLI surface changes.

### 1.1 Remove orphan provider modules

| File | Action |
|------|--------|
| `src/providers/waf_detection.rs` | Delete (not in mod.rs, not compiled, unused) |
| `src/providers/signature_based.rs` | Delete (stub only, not used) |

**Skills impact**: None. `security-audit` references `dae.rs` and `waffled_techniques.rs`, not these files.

### 1.2 Remove unused lib OutputFormat

| File | Action |
|------|--------|
| `src/lib.rs` | Remove `OutputFormat` enum and its `FromStr` impl (lines ~492–508). CLI uses its own. |

**Skills impact**: None. Workflows reference CLI behavior, not lib types.

### 1.3 Fix placeholder files

| File | Action |
|------|--------|
| `src/cli/commands.rs` | Delete, or move subcommand implementations here. Prefer delete if CLI split (Phase 6) will create `cli/subcommands.rs`. |
| `src/cli/output.rs` | Keep as placeholder; Phase 3 will populate it with `emit_results` and format logic. |

**Skills impact**: None.

### 1.4 Update TUI documentation

| File | Action |
|------|--------|
| `README.md` | Remove TUI references (table row, examples with `--tui`) |
| `DEVELOPMENT.md` | Remove TUI column from command table |
| `CLAUDE.md` | Remove "interactive TUI mode", "ratatui", `--tui` references; state CLI-only |

**Skills impact**: None. Workflows do not mention TUI.

### Gate

```bash
cargo build --release
cargo test -q
```

---

## Phase 2: Unification

**Goal**: Consolidate duplicate enums and the consent pattern.

### 2.1 Unify OutputFormat

| File | Action |
|------|--------|
| `src/cli/mod.rs` | Keep CLI `OutputFormat` as single source. Ensure it has Json, Ndjson, Yaml, Compact, Table. |
| `src/lib.rs` | Already cleaned in Phase 1. |

**Skills impact**: None. Workflows use `--json`, `--ndjson`, etc.; no enum names in docs.

### 2.2 Centralize consent guard

| File | Action |
|------|--------|
| `src/active.rs` or `src/effectiveness/consent.rs` | Add `run_with_consent<F, T>(scope, url, f) -> Result<T>` that creates ConsentManager, calls guard_target, then runs `f`. |
| `src/cli/mod.rs` | Replace ~12 consent blocks with `run_with_consent` |
| `src/effectiveness/mod.rs` | Replace consent block |
| `src/virtual_adversary/mod.rs` | Replace 4 consent blocks |
| `src/virtual_adversary2/mod.rs` | Replace 3 consent blocks |
| `src/payload/waf_smoke_test.rs` | Replace consent block |
| `src/payload/mod.rs` | Replace consent block |
| `src/hardening/regression.rs` | Replace 4 consent blocks |
| `src/hardening/orchestrator.rs` | Replace consent block |

**Skills impact**: None. Consent flow and commands stay the same; only implementation consolidates.

### Gate

```bash
cargo test -q
# Run a consent-gated flow manually to verify
```

---

## Phase 3: Shared Output Formatting

**Goal**: Extract duplicate format logic from scan_single and scan_batch.

### 3.1 Extract emit_results

| File | Action |
|------|--------|
| `src/cli/output.rs` | Implement `emit_results<T: Serialize>(results: &[T], format: &OutputFormat, matches: &ArgMatches) -> Result<()>` with Json/Ndjson/Yaml/Compact/Table branches |
| `src/cli/mod.rs` | Replace format branches in `scan_single` and `scan_batch` with calls to `emit_results` |

**Skills impact**: None. Output formats and flags unchanged.

### Gate

```bash
cargo test -q
# Verify scan --json, --ndjson, --yaml, --compact, --table for single and batch
```

---

## Phase 4: ProbeChannel Unification

**Goal**: Single ProbeChannel type for VA1 and VA2.

### 4.1 Introduce shared ProbeChannel

| File | Action |
|------|--------|
| `src/probe.rs` (new) or `src/payload/mod.rs` | Define `ProbeChannel { Path, Query, Header, Body, Method, Cookie }` with `Display`, `Serialize`, `Deserialize` |
| `src/virtual_adversary/dae.rs` | Replace local `ProbeChannel` with shared type; add `Cookie` if not present |
| `src/virtual_adversary2/mod.rs` | Replace `Va2ProbeChannel` with shared `ProbeChannel`; map Cookie to a no-op or extend VA2 if needed |
| `src/hardening/translate.rs` | Update `control_family_from_va2_channel` to use shared type |

**Skills impact**: None. No CLI changes.

### 4.2 Update security-audit workflow

| File | Action |
|------|--------|
| `agent-skills/security-audit/WORKFLOW.md` | If probe module path changes, update "Review security-sensitive modules" step |

### Gate

```bash
cargo test -q
python3 agent-skills/check_wrappers.py
```

---

## Phase 5: Provider Macro

**Goal**: Reduce ~96 match arms in providers/mod.rs.

### 5.1 Add provider forwarding macro

| File | Action |
|------|--------|
| `src/providers/mod.rs` | Add macro `impl_provider_forward!` that generates `name`, `version`, `description`, `provider_type`, `confidence_base`, `priority`, `enabled`, `detect`, `passive_detect`, `active_detect` for each variant |
| `src/providers/mod.rs` | Replace manual match arms with macro invocations |

**Skills impact**: None.

### Gate

```bash
cargo test -q
cargo clippy -- -D warnings
```

---

## Phase 6: CLI Split

**Goal**: Break cli/mod.rs (~3,964 lines) into focused modules.

### 6.1 Create module structure

| New File | Responsibility |
|----------|----------------|
| `src/cli/args.rs` | `build_simple_cli()`, ArgMatches parsing, `determine_format` |
| `src/cli/output.rs` | `emit_results`, `print_*`, table formatting (already populated in Phase 3) |
| `src/cli/scan.rs` | `scan_single`, `scan_batch` |
| `src/cli/subcommands.rs` | `run_*_subcommand` dispatch, `run_subcommand` |
| `src/cli/completions.rs` | `completion_*_options`, `render_*` |
| `src/cli/mod.rs` | Re-exports, `SimpleCliApp`, thin orchestration |

### 6.2 Move logic

- Extract functions and types into the new modules.
- Keep `OutputFormat` in `args.rs` or a shared `cli` type module.
- Ensure `main.rs` and other callers still work via `cli::` exports.

### 6.3 Update security-audit workflow

| File | Action |
|------|--------|
| `agent-skills/security-audit/WORKFLOW.md` | Update "Review security-sensitive modules" to list `src/cli/args.rs`, `src/cli/scan.rs`, etc., instead of or in addition to `src/cli/mod.rs` |

### Gate

```bash
cargo test -q
cargo clippy -- -D warnings
python3 agent-skills/check_wrappers.py
```

---

## Phase 7: VA Module Splits (Optional)

**Goal**: Reduce complexity in virtual_adversary and virtual_adversary2.

### 7.1 Split virtual_adversary

| New File | Responsibility |
|----------|----------------|
| `src/virtual_adversary/config.rs` | Config struct, parsing |
| `src/virtual_adversary/report.rs` | Report types, schema |
| `src/virtual_adversary/runner.rs` | Runner logic |
| `src/virtual_adversary/mod.rs` | Re-exports |

### 7.2 Split virtual_adversary2

| New File | Responsibility |
|----------|----------------|
| `src/virtual_adversary2/plan.rs` | Plan building |
| `src/virtual_adversary2/runner.rs` | Execution |
| `src/virtual_adversary2/scoring.rs` | Differential scoring, coverage |
| `src/virtual_adversary2/mod.rs` | Re-exports |

### 7.3 Update security-audit workflow

| File | Action |
|------|--------|
| `agent-skills/security-audit/WORKFLOW.md` | Update module paths for dae, runner, etc. |

### Gate

```bash
cargo test -q
python3 agent-skills/check_wrappers.py
```

---

## Phase 8: Data-Driven Completions (Optional)

**Goal**: Replace repeated completion_*_options with a data-driven approach.

### 8.1 Define completion data

| File | Action |
|------|--------|
| `src/cli/completions.rs` | Add `COMPLETION_OPTS: &[(&str, &[&str])]` mapping subcommand to option list |
| `src/cli/completions.rs` | Derive `completion_*_options` from data or simplify generation |

### 8.2 Update cli-doctor workflow

| File | Action |
|------|--------|
| `agent-skills/cli-doctor/WORKFLOW.md` | No change if completion install commands stay the same |

### Gate

```bash
cargo test -q
# Verify completions zsh, bash, fish still work
```

---

## Execution Order

| Phase | Depends On | Skills Updates |
|-------|------------|----------------|
| 0 | — | New skills, AGENTS.md |
| 1 | — | None |
| 2 | 1 | None |
| 3 | 2 | None |
| 4 | — | security-audit (if paths change) |
| 5 | — | None |
| 6 | 3 | security-audit |
| 7 | 4 | security-audit |
| 8 | 6 | None |

Phases 0–3 can run in sequence. Phases 4 and 5 are independent. Phase 6 benefits from Phase 3. Phase 7 is optional and can follow Phase 4. Phase 8 is optional and can follow Phase 6.

---

## Final Validation

After all phases:

```bash
python3 agent-skills/check_wrappers.py
# Run full validate-build workflow
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test -q
cargo build --release
./run_validation_tests.sh  # if available
```

---

## Checklist Summary

- [x] Phase 0: codebase-explore, provider-dev skills; AGENTS.md table
- [x] Phase 1: Remove orphans, lib OutputFormat, placeholders; fix TUI docs
- [x] Phase 2: Consent helper; unify OutputFormat
- [x] Phase 3: emit_results in output.rs
- [ ] Phase 4: Shared ProbeChannel
- [ ] Phase 5: Provider macro
- [ ] Phase 6: CLI split
- [ ] Phase 7: VA splits (optional)
- [ ] Phase 8: Data-driven completions (optional)
