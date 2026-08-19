# WAF Detector Development Guide

This document contains information for developers who want to contribute to the WAF Detector project.

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    CLI Application                            │
├──────────┬───────────┬──────────┬──────────┤
│   Scan   │ Enforce.  │ Behav.   │ Posture  │
│ Command  │ Test (va) │ (va2)    │ Report   │
├──────────┴───────────┴──────────┴──────────┤
│                   Detection Engine                            │
├──────────────────┬──────────────────┬────────────────────────┤
│ Provider Registry│ Confidence Engine│  HTTP Client            │
├──────────────────┴──────────────────┴────────────────────────┤
│                  Detection Providers                          │
├──────────────────┬──────────────────┬────────────────────────┤
│ CloudFlare       │  AWS WAF         │  Akamai                │
├──────────────────┼──────────────────┼────────────────────────┤
│ Fastly           │  Vercel          │  Azure                 │
├──────────────────┼──────────────────┼────────────────────────┤
│ F5 BIG-IP        │  Sucuri          │  Imperva + others      │
└──────────────────┴──────────────────┴────────────────────────┘
```

### Enforcement Testing Architecture

Enforcement testing is a consent-gated engine that sends known attack payloads and measures block/challenge/allow rates.

- **Runner + Evidence**: `src/virtual_adversary/mod.rs`
- **Report Persistence**: `src/virtual_adversary/report_store.rs`
- **Replay Plan**: exported in reports for audit and reproducibility

Key flow:
1. Build probe plan (tier + budget)
2. Collect baseline response signature
3. Execute probes, record evidence, classify enforcement
4. Store report with replay plan for later audit

### Behavioral Analysis Architecture

Behavioral analysis profiles WAF sophistication via paired control probes across 5 channels (Path, Query, Header, Body, Method).

- **Campaign Plan + Runner**: `src/virtual_adversary2/mod.rs`
- **Fixture Replay**: `src/virtual_adversary2/fixture.rs` (deterministic testing)
- 5 phases: Baseline, ProtocolVariance, StateEscalation, BehavioralPressure, ChallengeInteraction
- Per-channel discrimination scoring and unprotected channel detection

## Testing

### Run all tests:
```bash
cargo test
```

### Run specific test suites:
```bash
# Library tests only (261 tests)
cargo test --lib

# Integration tests
cargo test integration_test

# CLI tests
cargo test --test va_cli_test

# CloudFlare provider tests
cargo test cloudflare
```

### Validation scripts (CI):
```bash
./run_validation_tests.sh
python3 ci_validation.py ./target/release/waf-detect
python3 accuracy_validation.py ./target/release/waf-detect
```

## Adding New Providers

1. **Create provider module:**
```rust
// src/providers/new_provider.rs
pub struct NewProvider {
    // Implementation
}

#[async_trait::async_trait]
impl DetectionProvider for NewProvider {
    fn name(&self) -> &str { "NewProvider" }
    fn provider_type(&self) -> ProviderType { ProviderType::WAF }
    fn confidence_base(&self) -> f64 { 0.85 }

    async fn detect(&self, context: &DetectionContext) -> anyhow::Result<Vec<Evidence>> {
        // Detection logic
    }
}
```

2. **Add tests:**
```rust
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_new_provider_detection() {
        // Test implementation
    }
}
```

3. **Register in CLI** (`src/cli/mod.rs`):
```rust
let provider = Arc::new(NewProvider::new());
registry.register_provider(provider, metadata)?;
```

## Future Development

### Open
- [ ] **Probabilistic enforcement model** — replace linear PMI weights with posterior distribution + confidence intervals
- [ ] **Bypass distance metric** — count transformations needed before WAF response normalizes
- [x] **Monitor-mode detection** — infer WAF presence from subtle behavioral signals when nothing is blocked
- [x] **Posture CLI with VA1** — `--posture` integration with enforcement testing
- [ ] **Cookie channel** — add cookie inspection as a probe channel

### Done
- [x] Multi-channel perturbation (PR #29)
- [x] Interactive TUI (PR #38)
- [x] User-facing jargon cleanup (PR #39 + #40)
- [x] Dead code / repo cleanup (PR #41)

## Contributing

1. **Fork the repository**
2. **Create feature branch** (`git checkout -b feature/new-provider`)
3. **Write tests first** (TDD approach)
4. **Implement functionality**
5. **Ensure all tests pass** (`cargo test`)
6. **Submit pull request**

### Guidelines:
- Follow TDD methodology
- Maintain >80% test coverage
- Follow Rust idioms and best practices
- Run `cargo fmt && cargo clippy -- -D warnings` before committing

## Related Projects

- [WAFW00F](https://github.com/EnableSecurity/wafw00f) - Python WAF detection
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb) - Web technology identification
- [Wappalyzer](https://github.com/wappalyzer/wappalyzer) - Technology detection
