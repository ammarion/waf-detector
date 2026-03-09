# WAF Assess Workflow

Use this workflow when the user wants an end-to-end WAF assessment, not just a single command.

## Use Cases

- Full target assessment from detection through deeper validation
- Reproducible scan walkthroughs for coding agents
- Markdown assessment reports with concrete remediation guidance

## Guardrails

- Only test systems the user owns or is explicitly authorized to assess.
- Prefer the built binary when it exists; rebuild when missing or stale.
- If a prerequisite fails, stop and report the blocker instead of guessing.

## Recommended Order

1. Build or confirm the binary
2. Run doctor
3. Check consent and target authorization
4. Run detection
5. Run smoke testing
6. Run effectiveness testing when the user wants deeper validation
7. Run enforcement and behavioral testing only when the user explicitly wants them
8. Generate a posture-style summary
9. Render a shareable HTML report when the user wants an artifact

## Commands

### 1. Build

```bash
ls -la ./target/release/waf-detect
cargo build --release
```

### 2. Environment Health

```bash
./target/release/waf-detect doctor --json
```

Treat doctor failures as blockers. Treat warnings as advisory unless the user asked for strict gating.

### 3. Detection

```bash
./target/release/waf-detect scan <url> --json
```

Extract:

- detected provider
- confidence
- provider type
- evidence count

### 3b. Origin Probe (optional)

```bash
./target/release/waf-detect origin-probe <url>
./target/release/waf-detect origin-probe <url> --json
./target/release/waf-detect origin-probe <url> --no-attack-probe
```

Use when you want to check whether health/metrics/status endpoints share the same origin IP and allow WAF bypass via direct connection.

Extract:

- origin IP
- accessible bypass paths (2xx/3xx responses)
- whether WAF block was confirmed absent (`bypass_confirmed`)

### 4. Smoke Testing

```bash
./target/release/waf-detect --smoke-test <url> --aggressive -o /tmp/waf-smoke.json
```

Extract:

- total payloads
- blocked, allowed, challenged, rate-limited counts
- effectiveness percentage
- any obvious blind spots or unblocked categories

### 5. Effectiveness Testing

```bash
./target/release/waf-detect --effectiveness <url>
./target/release/waf-detect --effectiveness <url> --effectiveness-config <path/to/config.toml>
```

Notes:

- Parser-discrepancy candidate bypass testing runs inside effectiveness by default.
- Use config overrides when the user wants a narrower or more aggressive run.

### 6. Enforcement Testing

```bash
./target/release/waf-detect va <url>
./target/release/waf-detect va <url> --json
```

Use when the user wants enforcement behavior, replay artifacts, or variant-level evidence.

### 7. Behavioral Testing

```bash
./target/release/waf-detect va2 <url> --run
./target/release/waf-detect va2 <url> --run --json
./target/release/waf-detect va2 <url> --run --output <file>
```

Use when the user wants channel coverage, statefulness, challenge behavior, rate limiting, or behavioral fingerprinting.

### 8. Posture Summary

```bash
./target/release/waf-detect --posture <url>
./target/release/waf-detect --posture <url> --posture-va2
./target/release/waf-detect --posture <url> --posture-json
```

Use when the user wants one final protection summary instead of raw per-command output.

### 10. HTML Report Rendering

```bash
./target/release/waf-detect report <saved-report.json>
./target/release/waf-detect report <saved-report.json> --output <report.html>
```

Use when the user wants a polished, shareable artifact from a saved JSON report. Prefer this over any terminal-only review flow.

## Output Expectations

Produce a concise report with:

- Target
- Doctor status
- Detection summary
- Smoke summary
- Effectiveness summary
- Optional enforcement summary
- Optional behavioral summary
- Final posture and remediation notes
- HTML report path when one was generated

## Remediation Guidance

Prefer concrete recommendations tied to observed weaknesses, for example:

- parser normalization gaps
- weak mutation resilience
- missing challenge behavior
- poor multi-channel coverage
- detection-only or monitor-mode operation
