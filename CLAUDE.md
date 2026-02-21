# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
WAF Detector - A high-performance tool for detecting and testing Web Application Firewalls (WAFs) and Content Delivery Networks (CDNs). The project provides both CLI and web interfaces for security professionals to validate their defensive systems.

## Build and Development Commands

### Core Build Commands
- `cargo build --release` - Build optimized binary
- `cargo check` - Quick compilation check without building
- `cargo clippy -- -D warnings` - Run linter with strict warnings
- `cargo fmt` - Format code automatically

### Testing Commands
- `cargo test --all` - Run all unit tests
- `cargo test --lib` - Run library tests quickly
- `./run_validation_tests.sh` - Run comprehensive validation suite including Python tests
- `cargo test --bin waf-detect` - Test the main binary
- `cargo test --test integration_test` - Run integration tests

### Running the Application
- `./target/release/waf-detect example.com` - Scan a single URL
- `./target/release/waf-detect --web` - Start web interface (default port 8080)
- `./start_server.sh` - Build and start web server with proper setup
- `./debug_server.sh` - Start server in debug mode
- `./target/release/waf-detect --smoke-test example.com` - Run basic WAF smoke testing
- `./target/release/waf-detect --effectiveness example.com` - Run advanced effectiveness testing (requires consent)

### Posture Report Commands
- `./target/release/waf-detect --posture example.com` - Generate unified posture report (detection only)
- `./target/release/waf-detect --posture example.com --posture-va2` - Include VA2 behavioral profiling (requires consent)
- `./target/release/waf-detect --posture example.com --posture-json` - Output posture report as JSON

### Effectiveness Testing Commands
- `./target/release/waf-detect --consent` - Check consent status and authorized targets
- `./target/release/waf-detect --consent request` - Request user consent for effectiveness testing
- `./target/release/waf-detect --consent add-target domain.com` - Add authorized target domain
- `./target/release/waf-detect --effectiveness example.com` - Run comprehensive effectiveness testing
- `./target/release/waf-detect --effectiveness example.com --json` - Export results as JSON

## Architecture Overview

### Core Modules Structure
```
src/
├── lib.rs              # Core traits: DetectionProvider, Evidence, DetectionResult
├── main.rs             # Entry point using SimpleCliApp
├── cli/                # Command-line interface
├── engine/             # Detection engine coordinating providers
├── providers/          # WAF/CDN detection implementations
├── registry/           # Provider registration and management
├── confidence/         # Advanced scoring algorithms
├── effectiveness/      # WAF effectiveness testing (consent required)
├── posture/            # Unified posture report (grade A-F, risk 0-100)
├── payload/            # WAF smoke testing payloads
├── web/               # Axum-based web server
└── http/              # HTTP client with retry logic
```

### Key Architectural Components

1. **Detection Engine** (`src/engine/mod.rs`)
   - Coordinates multiple providers
   - Manages batch detection with configurable workers
   - Integrates WAF mode detection

2. **Provider System** (`src/providers/`)
   - Each provider implements `DetectionProvider` trait
   - Providers: CloudFlare, AWS, Akamai, Fastly, Vercel, Azure, F5
   - Evidence-based detection with confidence scoring

3. **Web Interface** (`src/web/mod.rs`)
   - Axum web framework
   - REST API endpoints for detection and testing
   - Real-time results streaming
   - Interactive dashboard with smoke testing

4. **Effectiveness Testing** (`src/effectiveness/`)
   - Requires explicit consent (`--consent request`)
   - Multi-phase testing: baseline, detection, evasion
   - Advanced evasion techniques (WAFFLED)
   - Comprehensive reporting with risk scores
   - Risk score calculation with vulnerability penalties
   - Static content detection and warnings
   - Configurable intensity levels and rate limiting

## Provider Implementation Pattern

When adding a new provider:
1. Create new file in `src/providers/`
2. Implement `DetectionProvider` trait
3. Define detection methods: passive (headers/body), active (probes), DNS
4. Register in `SimpleCliApp::new()` in `src/cli/mod.rs`
5. Add tests in `tests/` directory

Example structure:
```rust
pub struct NewProvider {
    name: String,
    version: String,
}

#[async_trait]
impl DetectionProvider for NewProvider {
    fn name(&self) -> &str { &self.name }
    fn provider_type(&self) -> ProviderType { ProviderType::Both }
    // ... implement required methods
}
```

## Testing Infrastructure

### Validation Scripts
- `ci_validation.py` - CI/CD validation with required metrics
- `accuracy_validation.py` - Comprehensive accuracy testing
- `header_comparison_test.py` - Header pattern analysis
- `test_payload_integration.py` - Payload testing validation

### Required Metrics (CI)
- Overall accuracy: ≥85%
- WAF precision: ≥90%
- WAF recall: ≥80%
- Max detection time: ≤5 seconds
- Average detection time: ≤2 seconds

## Important Considerations

### Security and Ethics
- Effectiveness testing requires explicit consent
- Only test systems you own or have permission to test
- Rate limiting is enforced (60 requests/minute default)
- All tests are logged for audit purposes

### Performance Optimization
- Batch detection uses concurrent workers
- Connection pooling in HTTP client
- Retry logic with exponential backoff
- DNS caching for improved performance
- Rate limiting prevents overwhelming targets (60 requests/minute default)
- Request delays configurable for stealth testing (500ms default)
- Memory-efficient streaming for large test suites
- Timeout handling prevents hanging requests (30s default)

### Performance Tuning Guidelines
- **Production Testing**: Use intensity level 1-2 for minimal impact
- **Development Testing**: Level 3 (default) provides good coverage
- **Security Audits**: Level 4-5 for comprehensive evaluation
- **Rate Limiting**: Adjust based on target capacity and testing window
- **Request Delays**: Increase for stealth, decrease for faster testing
- **Timeout Values**: Increase for slow targets, decrease for responsive ones

### Error Handling
- Use `Result<T, anyhow::Error>` for fallible operations
- Detailed error context with `anyhow`
- Graceful degradation for failed providers
- Comprehensive logging with `tracing`

## Common Development Tasks

### Adding New Attack Patterns
1. Edit `src/payload/waf_smoke_test.rs`
2. Add patterns to appropriate category
3. Update test cases
4. Run `cargo test --lib`

### Modifying Web UI
1. Templates in `src/web/templates.rs`
2. Static files served from `/web/static`
3. API endpoints in `src/web/mod.rs`
4. Test with `./start_server.sh`

### Debugging Detection Issues
1. Use `--debug` flag for verbose output
2. Check evidence in JSON output (`--json`)
3. Review provider confidence scores
4. Validate with `test_integration.rs`

### Debugging Effectiveness Testing Issues
1. **Consent Issues**: Check `~/.waf-detector-consent.json` for valid consent
2. **Target Authorization**: Ensure target is in authorized targets list
3. **Rate Limiting**: Monitor for 429 responses or unexpected delays
4. **Static Content Detection**: Review warnings about static content serving
5. **WAF Detection Failures**: Verify basic detection works before effectiveness testing
6. **Timeout Issues**: Check network connectivity and adjust timeout values
7. **Response Analysis**: Review block indicators in response bodies and status codes

### Common Issues and Solutions

**"User must acknowledge responsible use"**
- Run `./target/release/waf-detect --consent request` to provide consent
- Ensure consent hasn't expired (30-day validity)

**"Target URL is not in the list of authorized targets"**
- Add target with `--consent add-target domain.com`
- Check that domain matches exactly (including subdomains)

**"All baseline requests returned nearly identical responses"**
- Target may serve only static content
- Consider testing dynamic endpoints (login, search, API endpoints)
- Review target selection for parameter processing capabilities

**High response times or timeouts**
- Target may have aggressive rate limiting
- Reduce request rate or increase delays
- Check network connectivity and DNS resolution

**Low block rates despite known WAF presence**
- WAF may be in detection-only mode
- Review WAF configuration and blocking rules
- Consider testing with higher intensity levels

**Memory or performance issues**
- Reduce batch sizes for concurrent operations
- Increase request delays to reduce system load
- Monitor system resources during testing

## API Documentation - Effectiveness Module

### Core Types and Structures

#### EffectivenessConfig
```rust
pub struct EffectivenessConfig {
    pub max_requests_per_minute: u32,    // Rate limiting (default: 60)
    pub audit_logging: bool,             // Enable audit trail (default: true)
    pub intensity_level: u8,             // Testing intensity 1-5 (default: 3)
    pub custom_headers: HashMap<String, String>, // Custom request headers
    pub request_timeout: Duration,       // Request timeout (default: 30s)
    pub request_delay: Duration,         // Delay between requests (default: 500ms)
}
```

#### EffectivenessReport
```rust
pub struct EffectivenessReport {
    pub target_url: String,              // Target being tested
    pub timestamp: DateTime<Utc>,        // Test execution time
    pub risk_score: f64,                 // 0-100 risk assessment
    pub phases: Vec<TestPhase>,          // Testing phases executed
    pub vulnerabilities: Vec<Vulnerability>, // Security issues found
    pub recommendations: Vec<Recommendation>, // Remediation guidance
    pub test_results: HashMap<String, TestResult>, // Individual test outcomes
    pub baseline_results: HashMap<String, TestResult>, // Baseline behavior
    pub statistics: TestStatistics,      // Aggregate statistics
}
```

#### TestResult
```rust
pub struct TestResult {
    pub blocked: bool,                   // Whether request was blocked
    pub status_code: u16,                // HTTP status code received
    pub evidence: String,                // Response body or headers
    pub response_time: Duration,         // Request duration
}
```

#### Vulnerability
```rust
pub struct Vulnerability {
    pub severity: String,                // CRITICAL, HIGH, MEDIUM, LOW
    pub category: String,                // Attack category (SQL Injection, XSS, etc.)
    pub description: String,             // Human-readable description
    pub evidence: String,                // Proof of vulnerability
    pub remediation: String,             // Suggested fix
}
```

### Public API Methods

#### ConsentManager
```rust
impl ConsentManager {
    pub fn new() -> Self;
    pub fn has_valid_consent(&self) -> Result<bool>;
    pub fn request_consent(&self) -> Result<()>;
    pub fn is_target_allowed(&self, target_url: &str) -> Result<bool>;
    pub fn add_authorized_target(&self, target: &str) -> Result<()>;
}
```

#### EffectivenessTest
```rust
impl EffectivenessTest {
    pub async fn new(config: EffectivenessConfig) -> Result<Self>;
    pub async fn test_effectiveness(&mut self, url: &str) -> Result<EffectivenessReport>;
    pub fn is_blocked(status_code: u16, body: &str) -> bool;
}
```

#### EffectivenessReport Methods
```rust
impl EffectivenessReport {
    pub fn new(target_url: &str) -> Self;
    pub fn add_vulnerability(&mut self, vulnerability: Vulnerability);
    pub fn add_recommendation(&mut self, recommendation: Recommendation);
    pub fn generate_summary(&self) -> String;
    pub fn to_json(&self) -> Result<String, serde_json::Error>;
    pub fn to_html(&self) -> String;
}
```

### Risk Score Calculation Methodology

The risk score is calculated using the following algorithm:

1. **Base Risk Score**: `(1.0 - block_rate) * 100.0`
   - 100% blocked = 0 risk
   - 0% blocked = 100 risk

2. **Vulnerability Penalties**:
   - CRITICAL: +5.0 points per vulnerability
   - HIGH: +3.0 points per vulnerability  
   - MEDIUM: +2.0 points per vulnerability
   - LOW: +1.0 point per vulnerability

3. **Final Score**: `min(base_risk + penalties, 100.0)`

### Testing Intensity Levels

- **Level 1**: Basic patterns only (3 tests) - Safe for production
- **Level 2**: Basic + simple variations (6-8 tests) - Conservative testing
- **Level 3**: Standard attack patterns (12-15 tests) - Default level
- **Level 4**: Advanced patterns + evasion techniques (20-25 tests) - Comprehensive
- **Level 5**: All techniques including sophisticated evasion (30+ tests) - Aggressive

### Block Detection Logic

Requests are considered "blocked" if:

1. **Status Codes**: 403, 406, 429, 503
2. **Response Body Contains**:
   - "access denied", "forbidden", "blocked"
   - "firewall", "security policy", "violation" 
   - "suspicious", "malicious", "threat detected"
   - "request rejected", "waf protection"

### Usage Examples

#### Basic Effectiveness Testing
```rust
use waf-detector::effectiveness::{EffectivenessTest, EffectivenessConfig};

let mut test = EffectivenessTest::new(EffectivenessConfig::default()).await?;
let report = test.test_effectiveness("https://example.com").await?;

println!("Risk Score: {}", report.risk_score);
println!("Vulnerabilities: {}", report.vulnerabilities.len());
```

#### Custom Configuration
```rust
let config = EffectivenessConfig {
    max_requests_per_minute: 30,  // Slower rate
    intensity_level: 2,           // Conservative testing
    request_delay: Duration::from_secs(2), // 2 second delays
    ..Default::default()
};

let mut test = EffectivenessTest::new(config).await?;
```

#### Report Generation
```rust
let report = test.test_effectiveness("https://example.com").await?;

// Generate summary
println!("{}", report.generate_summary());

// Export as JSON
let json_report = report.to_json()?;
std::fs::write("report.json", json_report)?;

// Export as HTML
let html_report = report.to_html();
std::fs::write("report.html", html_report)?;
```

## Git Workflow
- Feature branches: `feature/your-feature-name`
- Test branches: `test/your-test-name`
- No direct commits to `main`
- Run `cargo fmt` and `cargo clippy` before commits
- Ensure all tests pass with `cargo test --all`