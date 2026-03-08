# Security Audit Workflow

Use this workflow for a structured security audit of the WAF detector codebase.

## Scope

- dependency risk
- unsafe or risky code paths
- insecure defaults
- consent and authorization gaps
- missing tests on security-sensitive logic

## Steps

1. Dependency scan

```bash
cargo audit
```

If `cargo-audit` is missing, install it only if the user wants that dependency added locally.

2. Search for risky patterns

- unvalidated user input reaching shell commands, file paths, or network targets
- hardcoded secrets or credentials
- unsafe blocks without justification
- missing consent enforcement on high-risk flows
- dangerous defaults in CLI or runtime config

3. Review security-sensitive modules

- `src/cli/mod.rs`
- `src/http/mod.rs`
- effectiveness consent and authorization logic
- enforcement and behavioral testing entry points
- `src/virtual_adversary/dae.rs` — probe payload catalog; verify `validate_zero_overlap` gates all probes
- `src/effectiveness/waffled_techniques.rs` — waffled pair catalog; verify control/variant bodies don't contain live attack strings outside the intended payload constants

4. Review test coverage gaps on the above paths

5. Report findings by severity with concrete remediation guidance

## Rules

- Use actual scans and actual code references
- Do not invent findings
- Prioritize bugs, regressions, and coverage gaps over summaries
- If no findings are discovered, say so explicitly and call out residual risk
