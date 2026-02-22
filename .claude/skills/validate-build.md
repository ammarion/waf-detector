---
name: validate-build
description: Full build validation — compile, test, lint, and verify
user_invocable: true
---

# Build Validation Skill

Run the complete build validation pipeline for the WAF detector.

## Steps (run sequentially)

1. `cargo fmt --check` — verify formatting
2. `cargo clippy --all-targets --all-features -- -D warnings` — lint with strict warnings
3. `cargo test -q` — run all tests
4. `cargo build --release` — build optimized binary

## On failure

- If fmt fails: run `cargo fmt` and report what changed
- If clippy fails: report the warnings with file locations
- If tests fail: report failing test names and error messages
- If build fails: report the compilation error

## Output

Report pass/fail for each step with counts (e.g., "298 tests passed"). Do not truncate test output if there are failures.
