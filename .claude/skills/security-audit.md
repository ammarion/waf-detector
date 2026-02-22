---
name: security-audit
description: Run a structured security audit on the WAF detector codebase
user_invocable: true
---

# Security Audit Skill

Run a systematic security audit of the WAF detector codebase.

## Steps

1. **Dependency scan**: Run `cargo audit` (install with `cargo install cargo-audit` if missing)
2. **Code patterns**: Search for common security issues:
   - Unwrapped user input reaching shell commands or file paths
   - Missing input validation on CLI arguments and runtime config
   - Hardcoded credentials or secrets
   - Unsafe blocks without justification
   - Missing consent/authorization protections for high-risk flows
3. **Configuration review**: Check for insecure defaults in:
   - `src/cli/mod.rs` (execution mode validation, output safety)
   - `src/http/mod.rs` (redirect policy, certificate validation)
   - Consent enforcement in VA1/VA2 paths
4. **Test coverage gaps**: Identify security-critical paths without test coverage
5. **Report**: Output findings with severity (CRITICAL/HIGH/MEDIUM/LOW) and remediation steps

## Rules

- Run actual scans, report real results. Never predict or fabricate findings.
- Check `cargo clippy` for any new warnings introduced.
- Focus on OWASP Top 10 categories relevant to this Rust security CLI.
