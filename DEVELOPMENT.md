# WAF Detector Development Guide

This document contains information for developers who want to contribute to the WAF Detector project.

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Application                          │
├─────────────────┬─────────────────┬─────────────────────────┤
│   Scan Command  │  Batch Command  │   List Command          │
├─────────────────┴─────────────────┴─────────────────────────┤
│                   Detection Engine                          │
├─────────────────┬─────────────────┬─────────────────────────┤
│ Provider Registry│ Confidence Engine│  HTTP Client           │
├─────────────────┴─────────────────┴─────────────────────────┤
│                 Detection Providers                         │
├─────────────────┬─────────────────┬─────────────────────────┤
│ CloudFlare      │  AWS WAF        │  Akamai                 │
├─────────────────┼─────────────────┼─────────────────────────┤
│ Fastly          │  Vercel         │  Azure                  │
├─────────────────┼─────────────────┼─────────────────────────┤
│ F5 BIG-IP       │                 │                         │
└─────────────────┴─────────────────┴─────────────────────────┘
```

### 🧠 Virtual Adversary Architecture

Virtual Adversary (VA) is a consent-gated effectiveness engine built around a **differential probe catalog** and **replayable plans**.

- **Probe Catalog**: `src/virtual_adversary/dae.rs`
- **Runner + Evidence**: `src/virtual_adversary/mod.rs`
- **Replay Plan**: exported in VA reports for audit and reproducibility
- **Web UI**: report modal + history downloads (replay JSON/CSV)
- **API Endpoints**: `/api/virtual-adversary/reports/:id/replay.json` and `.csv`

Key flow:
1. Build probe plan (tier + budget)
2. Collect baseline response signature
3. Execute probes, record evidence, classify enforcement
4. Store report with replay plan for later audit

## 🧪 Testing

### Run all tests:
```bash
cargo test
```

### Run specific test suites:
```bash
# Unit tests only
cargo test --lib

# Integration tests
cargo test integration_test

# CloudFlare provider tests
cargo test cloudflare
```

## 🛠️ Adding New Providers

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

2. **Add comprehensive tests:**
```rust
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_new_provider_detection() {
        // Test implementation
    }
}
```

3. **Register in CLI:**
```rust
// In cli/mod.rs
let provider = Arc::new(NewProvider::new());
registry.register_provider(provider, metadata)?;
```

## 📋 Future Development

### High Priority
- [ ] **Additional WAF Providers** - Support for more WAF vendors
- [ ] **Active Probing** - Enhanced detection techniques
- [ ] **Performance Benchmarks** - Criterion-based benchmarking
- [ ] **VA Replay Runner** - Re-execute a stored replay plan against a target with integrity checks

### Medium Priority  
- [ ] **DNS Analysis** - DNS-based detection methods
- [ ] **TLS Fingerprinting** - JA3 hash analysis
- [ ] **VA Replay Diffs** - Compare current run to previous replay plan results

### Low Priority
- [ ] **HTTP Server Mode** - REST API server
- [ ] **WebSocket Streaming** - Real-time detection
- [ ] **Signature Database** - External signature loading
- [ ] **Machine Learning** - ML-based confidence scoring

## 🤝 Contributing

1. **Fork the repository**
2. **Create feature branch** (`git checkout -b feature/new-provider`)
3. **Write tests first** (TDD approach)
4. **Implement functionality**
5. **Ensure all tests pass** (`cargo test`)
6. **Submit pull request**

### Contribution Guidelines:
- Follow TDD methodology
- Maintain >80% test coverage
- Document all public APIs
- Include performance benchmarks for new features
- Follow Rust idioms and best practices

## 🔗 Related Projects

- [WAFW00F](https://github.com/EnableSecurity/wafw00f) - Python WAF detection
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb) - Web technology identification
- [Wappalyzer](https://github.com/wappalyzer/wappalyzer) - Technology detection
