# WAF Detector Integration Testing Guide

## Overview

The WAF Detector integration testing framework provides comprehensive testing capabilities for validating WAF/CDN detection accuracy, performance, and reliability across different providers and scenarios.

## Table of Contents

1. [Architecture](#architecture)
2. [Running Tests](#running-tests)
3. [Writing Tests](#writing-tests)
4. [Mock Server](#mock-server)
5. [CI/CD Integration](#cicd-integration)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

## Architecture

The integration testing framework is organized into several key modules:

```
tests/
├── integration/
│   ├── mod.rs              # Module exports
│   ├── framework.rs        # Core test framework
│   ├── mock_server.rs      # HTTP mock server
│   ├── test_data.rs        # Test case definitions
│   ├── utils.rs            # Testing utilities
│   └── scenarios.rs        # E2E test scenarios
├── cloudflare_integration_test.rs
├── aws_integration_test.rs
└── run_integration_tests.rs
```

### Core Components

#### 1. Test Framework (`framework.rs`)

The framework provides:
- `IntegrationTestCase` trait for defining tests
- `TestRunner` for executing test suites
- `TestContext` for sharing state between tests
- Assertion helpers for validating results

```rust
#[async_trait]
impl IntegrationTestCase for MyTest {
    fn name(&self) -> &str { "my_test" }
    fn description(&self) -> &str { "Test description" }
    
    async fn setup(&mut self, context: &mut TestContext) -> Result<()> {
        // Setup test environment
    }
    
    async fn execute(&self, context: &TestContext) -> Result<TestResult> {
        // Run test logic
    }
    
    async fn teardown(&mut self, context: &mut TestContext) -> Result<()> {
        // Cleanup
    }
}
```

#### 2. Mock Server (`mock_server.rs`)

Simulates WAF/CDN responses for testing:

```rust
let mut server = MockServer::new().await?;
let url = server.start().await?;

// Mock CloudFlare response
server.mock_cloudflare("/");

// Mock custom response
server.mock_response("/custom", MockResponse {
    status: 200,
    headers: headers,
    body: "response body".to_string(),
    delay_ms: Some(100),
});
```

#### 3. Test Data (`test_data.rs`)

Predefined test cases for all providers:

```rust
let test_cases = TestDataProvider::cloudflare_test_cases();
let edge_cases = TestDataProvider::edge_case_test_cases();
```

## Running Tests

### Basic Commands

```bash
# Run all integration tests
cargo test --test "*integration*"

# Run specific test file
cargo test --test cloudflare_integration_test

# Run with output
cargo test --test run_integration_tests -- --nocapture

# Run specific test
cargo test --test run_integration_tests test_basic_detection_individually

# Run with debug output
DEBUG=1 cargo test --test run_integration_tests
```

### Using the Test Runner

```bash
# Run comprehensive validation suite
./run_validation_tests.sh

# Run CI validation
python3 ci_validation.py ./target/release/waf-detect

# Run with custom binary
WAF_DETECTOR_BINARY=/path/to/binary cargo test
```

## Writing Tests

### 1. Create a Test Scenario

```rust
use crate::integration::*;

pub struct MyScenario {
    name: String,
    mock_server: Option<MockServer>,
}

impl MyScenario {
    pub fn new() -> Self {
        Self {
            name: "my_scenario".to_string(),
            mock_server: None,
        }
    }
}

#[async_trait]
impl IntegrationTestCase for MyScenario {
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { "My test scenario" }
    
    async fn setup(&mut self, context: &mut TestContext) -> Result<()> {
        let mut server = MockServer::new().await?;
        let url = server.start().await?;
        
        // Configure mock responses
        server.mock_cloudflare("/test");
        
        context.mock_server_url = Some(url);
        self.mock_server = Some(server);
        Ok(())
    }
    
    async fn execute(&self, context: &TestContext) -> Result<TestResult> {
        let url = context.mock_server_url.as_ref().unwrap();
        
        // Run detector
        let output = run_detector_cli_async(
            &[url, "--json"],
            Duration::from_secs(10)
        ).await?;
        
        // Validate results
        let json = output.json_output.unwrap();
        let results = parse_detection_results(&json)?;
        
        // Return test result
        Ok(TestResult {
            name: self.name().to_string(),
            passed: results.waf.is_some(),
            message: "Detection successful".to_string(),
            duration: Duration::from_secs(0),
            details: None,
        })
    }
}
```

### 2. Add Provider-Specific Tests

```rust
// In tests/provider_integration_test.rs
mod integration;

use integration::*;

struct ProviderSpecificTest {
    // test implementation
}

#[tokio::test]
async fn test_provider_integration() {
    let mut runner = TestRunner::new();
    runner = runner.add_test(ProviderSpecificTest::new());
    
    let results = runner.run_all().await;
    let report = runner.generate_report(&results);
    
    println!("{}", report);
    assert!(results.iter().all(|r| r.passed));
}
```

### 3. Use Test Utilities

```rust
// Parse detection results
let results = parse_detection_results(&json)?;

// Compare detections
compare_detections(&results, Some("CloudFlare"), Some("CloudFlare"))?;

// Assert CLI success
assert_cli_success(&output)?;

// Wait for server
wait_for_server(&url, 10).await?;
```

## Mock Server

### Available Mock Methods

```rust
// Provider-specific mocks
server.mock_cloudflare(path);
server.mock_aws_cloudfront(path);
server.mock_akamai(path);
server.mock_fastly(path);

// WAF blocking responses
server.mock_waf_blocked(path, "cloudflare");
server.mock_waf_blocked(path, "aws");

// Custom responses
server.mock_response(path, MockResponse {
    status: 403,
    headers: HashMap::new(),
    body: "Blocked".to_string(),
    delay_ms: Some(500),
});
```

### Recording Requests

```rust
// Get recorded requests
let requests = server.get_requests();

// Clear request log
server.clear_requests();

// Verify request was made
assert!(requests.iter().any(|r| r.path == "/test"));
```

## CI/CD Integration

### GitHub Actions Workflow

The `.github/workflows/integration_tests.yml` provides:

1. **Multi-platform testing**: Ubuntu, macOS, Windows
2. **Multiple Rust versions**: stable, beta, nightly
3. **Performance benchmarks**: Track regression
4. **Security audits**: Check dependencies
5. **Docker builds**: Container testing
6. **Coverage reports**: Code coverage metrics

### Running in CI

```yaml
- name: Run integration tests
  run: |
    cargo test --test "*integration*" --verbose
    cargo test --test run_integration_tests --verbose
```

## Best Practices

### 1. Test Organization

- Group related tests in scenarios
- Use descriptive test names
- Keep tests focused and atomic
- Clean up resources in teardown

### 2. Mock Server Usage

- Always start mock server in setup
- Configure all needed responses upfront
- Use appropriate delays for timing tests
- Clean up server in teardown

### 3. Assertions

- Use provided assertion helpers
- Check both positive and negative cases
- Verify confidence scores
- Validate evidence presence

### 4. Performance

- Set reasonable timeouts
- Run tests in parallel when possible
- Use batch operations for multiple URLs
- Monitor test execution time

## Troubleshooting

### Common Issues

#### Mock Server Not Starting
```bash
# Check if port is in use
lsof -i :8080

# Use random port
let listener = TcpListener::bind("127.0.0.1:0").await?;
```

#### Test Timeouts
```rust
// Increase timeout
let output = run_detector_cli_async(
    &[url, "--json"],
    Duration::from_secs(30)  // Increased timeout
).await?;
```

#### JSON Parsing Errors
```rust
// Debug JSON output
if let Err(e) = serde_json::from_str(&output.stdout) {
    eprintln!("JSON parse error: {}", e);
    eprintln!("Raw output: {}", output.stdout);
}
```

### Debug Mode

Enable debug output:
```bash
# Set debug environment variable
DEBUG=1 cargo test

# Or in test context
let context = TestContext {
    debug_mode: true,
    ..Default::default()
};
```

### Viewing Test Reports

Test reports are saved to:
- `integration_test_report.txt` - Human-readable report
- `ci_validation_results.json` - CI validation results
- `validation_report.md` - Markdown formatted report

## Examples

### Complete Test Example

```rust
#[tokio::test]
async fn test_complete_integration() {
    // Setup
    let mut server = MockServer::new().await.unwrap();
    let server_url = server.start().await.unwrap();
    
    // Configure responses
    server.mock_cloudflare("/");
    server.mock_aws_cloudfront("/aws");
    
    // Test CloudFlare
    let cf_output = run_detector_cli(&[
        &format!("{}/", server_url),
        "--json"
    ]).unwrap();
    
    assert_eq!(cf_output.exit_code, 0);
    
    let cf_json = cf_output.json_output.unwrap();
    let cf_results = parse_detection_results(&cf_json).unwrap();
    
    assert!(cf_results.waf.is_some());
    assert_eq!(cf_results.waf.unwrap().name, "CloudFlare");
    
    // Test AWS
    let aws_output = run_detector_cli(&[
        &format!("{}/aws", server_url),
        "--json"
    ]).unwrap();
    
    let aws_json = aws_output.json_output.unwrap();
    let aws_results = parse_detection_results(&aws_json).unwrap();
    
    assert!(aws_results.cdn.is_some());
    assert_eq!(aws_results.cdn.unwrap().name, "AWS");
}
```

## Contributing

When adding new integration tests:

1. Follow the existing test structure
2. Add appropriate mock responses
3. Include both positive and negative test cases
4. Update this documentation
5. Ensure tests pass in CI/CD

For questions or issues, please open a GitHub issue or pull request.