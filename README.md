# WAF Detector 🛡️

A high-performance, extensible WAF/CDN detection utility built in Rust using Test-Driven Development (TDD).

## 🎯 Project Status

### ✅ Completed Features (TDD Phase 1)

1. **Core Architecture**
   - ✅ Detection provider trait system
   - ✅ Evidence collection and confidence scoring
   - ✅ Bayesian confidence engine
   - ✅ Plugin-based provider registry
   - ✅ Async HTTP client with connection pooling

2. **Multi-Provider Support**
   - ✅ CloudFlare (WAF + CDN)
   - ✅ AWS WAF + CloudFront
   - ✅ Akamai (WAF + CDN)
   - ✅ Fastly (CDN)
   - ✅ Vercel (CDN)
   - ✅ Multi-vendor detection (different providers for WAF vs CDN)

3. **CLI Interface**
   - ✅ Single URL scanning
   - ✅ Batch processing from file (@filename.txt syntax)
   - ✅ Multiple output formats (JSON, YAML, table)
   - ✅ Web interface with dashboard
   - ✅ Provider listing

4. **WAF Effectiveness Testing**
   - ✅ Built-in attack payload testing
   - ✅ 8 attack categories (SQL Injection, XSS, XXE, RFI, LFI, RCE, Command Injection, Path Traversal)
   - ✅ Combined detection + effectiveness testing
   - ✅ Effectiveness scoring and recommendations
   - ✅ Standalone bash script integration

5. **Web Interface**
   - ✅ Interactive web dashboard
   - ✅ Real-time scanning results
   - ✅ Combined detection + effectiveness testing
   - ✅ Evidence visualization
   - ✅ RESTful API endpoints

6. **Testing Infrastructure**
   - ✅ Unit tests for core components
   - ✅ Integration tests for provider functionality
   - ✅ Mock HTTP responses for testing
   - ✅ Regex pattern validation tests

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
│ CloudFlare      │  AWS WAF (TODO) │  F5 BIG-IP (TODO)      │
└─────────────────┴─────────────────┴─────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Rust 1.70+ 
- Cargo

### Installation
```bash
git clone <repository>
cd waf-detector
cargo build --release
```

### Basic Usage

**Scan a single URL:**
```bash
./target/release/waf-detect example.com
```

**Scan multiple URLs:**
```bash
./target/release/waf-detect example.com google.com cloudflare.com
```

**Batch scanning from file:**
```bash
# Create a file with URLs (one per line)
echo "https://cloudflare.com" > urls.txt
echo "https://example.com" >> urls.txt

./target/release/waf-detect @urls.txt
```

**JSON output:**
```bash
./target/release/waf-detect example.com --json
```

**Web interface:**
```bash
./target/release/waf-detect --web
# Visit http://localhost:8080
```

**List available providers:**
```bash
./target/release/waf-detect --list
```

## 🧪 WAF Effectiveness Testing

### Integrated Testing
The tool now includes built-in WAF effectiveness testing that combines detection with attack payload testing:

```bash
# Web interface includes combined testing
./target/release/waf-detect --web

# Use the /api/combined-scan endpoint
curl -X POST "http://localhost:8080/api/combined-scan" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Standalone Testing Script
For manual testing or CI/CD integration:

```bash
# Basic effectiveness test
./scripts/waf-smoke-test.sh "https://example.com"

# Generate JSON report
./scripts/waf-smoke-test.sh "https://example.com" -o results.json

# Custom headers
./scripts/waf-smoke-test.sh "https://example.com" -H "Authorization: Bearer token"
```

### Attack Categories Tested
- **SQL Injection**: `' OR '1'='1`
- **XSS**: `<script>alert('XSS')</script>`
- **XXE**: XML External Entity injection
- **RFI**: Remote File Inclusion
- **LFI**: Local File Inclusion  
- **RCE**: Remote Code Execution
- **Command Injection**: `&& id`
- **Path Traversal**: `../../etc/passwd`

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

### Test Coverage:
- Core trait implementations: ✅
- HTTP client functionality: ✅
- CloudFlare detection patterns: ✅
- Confidence calculation: ✅
- Provider registry: ✅

## 📊 Detection Capabilities

### CloudFlare Detection (95% accuracy target)

**Headers Detected:**
- `cf-ray`: CloudFlare Ray ID (95% confidence)
- `cf-cache-status`: Cache status (90% confidence)  
- `server`: CloudFlare server header (85% confidence)
- `cf-request-id`: Request ID (90% confidence)
- `cf-ipcountry`: IP country (85% confidence)

**Body Patterns:**
- Browser challenge pages (90% confidence)
- Error pages with CloudFlare branding (85% confidence)
- JavaScript challenge tokens (95% confidence)

**Status Codes:**
- 403 with CloudFlare content (70% confidence)
- 503 with CloudFlare content (75% confidence)

## 🔧 Configuration

### Detection Config Options:
```rust
DetectionConfig {
    aggressive_mode: bool,      // Enable active probing
    timeout_ms: u64,           // Request timeout
    max_retries: u32,          // Retry attempts
    user_agent: String,        // Custom user agent
    follow_redirects: bool,    // Follow HTTP redirects
    verify_ssl: bool,          // SSL certificate verification
}
```

## 📈 Performance Targets

- **Latency**: <100ms per detection (95th percentile)
- **Throughput**: 50,000+ requests/second (batch mode)
- **Memory**: <50MB for signature database
- **Accuracy**: 95%+ detection rate, <2% false positives

## 🛠️ Development

### Adding New Providers

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

### TDD Workflow

1. **Write failing test** (RED)
2. **Implement minimum code** (GREEN)  
3. **Refactor and optimize** (REFACTOR)
4. **Repeat for next feature**

## 📋 Next Steps (TDD Phase 2)

### High Priority
- [ ] **AWS WAF Provider** - Implement detection for AWS WAF
- [ ] **F5 BIG-IP Provider** - Enterprise WAF detection
- [ ] **Active Probing** - XSS/SQLi probe detection
- [ ] **Performance Benchmarks** - Criterion-based benchmarking

### Medium Priority  
- [ ] **Akamai Provider** - CDN detection
- [ ] **Imperva Provider** - WAF detection
- [ ] **DNS Analysis** - DNS-based detection methods
- [ ] **TLS Fingerprinting** - JA3 hash analysis

### Low Priority
- [ ] **HTTP Server Mode** - REST API server
- [ ] **WebSocket Streaming** - Real-time detection
- [ ] **Signature Database** - External signature loading
- [ ] **Machine Learning** - ML-based confidence scoring

## 📚 Learning Resources

See [LEARNING_RESOURCES.md](LEARNING_RESOURCES.md) for comprehensive learning materials covering:
- Rust programming and async development
- HTTP/networking fundamentals  
- WAF/CDN architecture and detection
- Performance optimization techniques
- Security testing methodologies

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

## 📄 License

MIT OR Apache-2.0

## 🔗 Related Projects

- [WAFW00F](https://github.com/EnableSecurity/wafw00f) - Python WAF detection
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb) - Web technology identification
- [Wappalyzer](https://github.com/wappalyzer/wappalyzer) - Technology detection

---

**Built with ❤️ using Test-Driven Development and Rust** 🦀 