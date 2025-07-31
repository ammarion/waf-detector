#![allow(clippy::field_reassign_with_default)]

use crate::integration::{
    framework::{IntegrationTestCase, TestContext, TestResult},
    mock_server::MockServer,
    utils::{compare_detections, parse_detection_results, run_detector_cli_async},
};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;

/// End-to-end test scenario for basic detection
pub struct BasicDetectionScenario {
    name: String,
    mock_server: Option<MockServer>,
}

impl BasicDetectionScenario {
    pub fn new() -> Self {
        Self {
            name: "basic_detection_e2e".to_string(),
            mock_server: None,
        }
    }
}

#[async_trait]
impl IntegrationTestCase for BasicDetectionScenario {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "End-to-end test for basic WAF/CDN detection"
    }

    async fn setup(&mut self, context: &mut TestContext) -> Result<()> {
        // Start mock server
        let mut server = MockServer::new().await?;
        let url = server.start().await?;

        // Configure CloudFlare response
        server.mock_cloudflare("/");

        context.mock_server_url = Some(url);
        self.mock_server = Some(server);

        Ok(())
    }

    async fn execute(&self, context: &TestContext) -> Result<TestResult> {
        let url = context
            .mock_server_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Mock server URL not set"))?;

        // Run detector
        let output = run_detector_cli_async(&[url, "--json"], Duration::from_secs(10)).await?;

        if output.exit_code != 0 {
            return Ok(TestResult {
                name: self.name().to_string(),
                passed: false,
                message: format!("Detector failed: {}", output.stderr),
                duration: Duration::from_secs(0),
                details: None,
            });
        }

        // Parse results
        let json = output
            .json_output
            .ok_or_else(|| anyhow::anyhow!("No JSON output"))?;
        let results = parse_detection_results(&json)?;

        // Verify detection
        match compare_detections(&results, Some("CloudFlare"), Some("CloudFlare")) {
            Ok(_) => Ok(TestResult {
                name: self.name().to_string(),
                passed: true,
                message: "Detection successful".to_string(),
                duration: Duration::from_secs(0),
                details: None,
            }),
            Err(e) => Ok(TestResult {
                name: self.name().to_string(),
                passed: false,
                message: e.to_string(),
                duration: Duration::from_secs(0),
                details: None,
            }),
        }
    }
}

/// Scenario for testing multiple providers
pub struct MultiProviderScenario {
    name: String,
    mock_server: Option<MockServer>,
}

impl MultiProviderScenario {
    pub fn new() -> Self {
        Self {
            name: "multi_provider_detection".to_string(),
            mock_server: None,
        }
    }
}

#[async_trait]
impl IntegrationTestCase for MultiProviderScenario {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "Test detection of multiple providers"
    }

    async fn setup(&mut self, context: &mut TestContext) -> Result<()> {
        let mut server = MockServer::new().await?;
        let url = server.start().await?;

        // Configure different responses for different paths
        server.mock_cloudflare("/cloudflare");
        server.mock_aws_cloudfront("/aws");
        server.mock_akamai("/akamai");
        server.mock_fastly("/fastly");

        context.mock_server_url = Some(url);
        self.mock_server = Some(server);

        Ok(())
    }

    async fn execute(&self, context: &TestContext) -> Result<TestResult> {
        let base_url = context
            .mock_server_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Mock server URL not set"))?;

        let test_cases = vec![
            ("/cloudflare", "CloudFlare", "CloudFlare"),
            ("/aws", "AWS", "AWS"),
            ("/akamai", "Akamai", "Akamai"),
            ("/fastly", "Fastly", "Fastly"),
        ];

        let mut all_passed = true;
        let mut messages = Vec::new();

        for (path, expected_waf, expected_cdn) in test_cases {
            let url = format!("{base_url}{path}");
            let output = run_detector_cli_async(&[&url, "--json"], Duration::from_secs(10)).await?;

            if output.exit_code != 0 {
                all_passed = false;
                messages.push(format!("{path}: CLI failed"));
                continue;
            }

            if let Some(json) = output.json_output {
                let results = parse_detection_results(&json)?;
                if let Err(e) = compare_detections(&results, Some(expected_waf), Some(expected_cdn))
                {
                    all_passed = false;
                    messages.push(format!("{path}: {e}"));
                } else {
                    messages.push(format!("{path}: OK"));
                }
            } else {
                all_passed = false;
                messages.push(format!("{path}: No JSON output"));
            }
        }

        Ok(TestResult {
            name: self.name().to_string(),
            passed: all_passed,
            message: messages.join(", "),
            duration: Duration::from_secs(0),
            details: None,
        })
    }
}

/// Performance testing scenario
pub struct PerformanceScenario {
    name: String,
    mock_server: Option<MockServer>,
}

impl PerformanceScenario {
    pub fn new() -> Self {
        Self {
            name: "performance_test".to_string(),
            mock_server: None,
        }
    }
}

#[async_trait]
impl IntegrationTestCase for PerformanceScenario {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "Test detection performance and timeouts"
    }

    async fn setup(&mut self, context: &mut TestContext) -> Result<()> {
        let mut server = MockServer::new().await?;
        let url = server.start().await?;

        // Configure responses with different delays
        let mut response = super::mock_server::MockResponse::default();
        response.delay_ms = Some(100);
        response
            .headers
            .insert("cf-ray".to_string(), "test123".to_string());
        server.mock_response("/fast", response.clone());

        response.delay_ms = Some(2000);
        server.mock_response("/slow", response);

        context.mock_server_url = Some(url);
        self.mock_server = Some(server);

        Ok(())
    }

    async fn execute(&self, context: &TestContext) -> Result<TestResult> {
        let base_url = context
            .mock_server_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Mock server URL not set"))?;

        // Test fast response
        let start = std::time::Instant::now();
        let fast_url = format!("{base_url}/fast");
        let fast_output =
            run_detector_cli_async(&[&fast_url, "--json"], Duration::from_secs(5)).await?;
        let fast_duration = start.elapsed();

        if fast_output.exit_code != 0 {
            return Ok(TestResult {
                name: self.name().to_string(),
                passed: false,
                message: "Fast detection failed".to_string(),
                duration: fast_duration,
                details: None,
            });
        }

        // Test slow response
        let start = std::time::Instant::now();
        let slow_url = format!("{base_url}/slow");
        let slow_output =
            run_detector_cli_async(&[&slow_url, "--json"], Duration::from_secs(5)).await?;
        let slow_duration = start.elapsed();

        // Check performance criteria
        let fast_ok = fast_duration < Duration::from_secs(2);
        let slow_ok = slow_duration < Duration::from_secs(5);

        let passed = fast_ok && slow_ok && slow_output.exit_code == 0;
        let message = format!(
            "Fast: {:?} ({}), Slow: {:?} ({})",
            fast_duration,
            if fast_ok { "OK" } else { "SLOW" },
            slow_duration,
            if slow_ok { "OK" } else { "TIMEOUT" }
        );

        Ok(TestResult {
            name: self.name().to_string(),
            passed,
            message,
            duration: fast_duration + slow_duration,
            details: None,
        })
    }
}

/// WAF blocking detection scenario
pub struct WafBlockingScenario {
    name: String,
    mock_server: Option<MockServer>,
}

impl WafBlockingScenario {
    pub fn new() -> Self {
        Self {
            name: "waf_blocking_detection".to_string(),
            mock_server: None,
        }
    }
}

#[async_trait]
impl IntegrationTestCase for WafBlockingScenario {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "Test detection of WAF blocking responses"
    }

    async fn setup(&mut self, context: &mut TestContext) -> Result<()> {
        let mut server = MockServer::new().await?;
        let url = server.start().await?;

        // Configure blocked responses
        server.mock_waf_blocked("/cloudflare-blocked", "cloudflare");
        server.mock_waf_blocked("/aws-blocked", "aws");

        context.mock_server_url = Some(url);
        self.mock_server = Some(server);

        Ok(())
    }

    async fn execute(&self, context: &TestContext) -> Result<TestResult> {
        let base_url = context
            .mock_server_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Mock server URL not set"))?;

        let test_cases = vec![
            ("/cloudflare-blocked", "CloudFlare", 403),
            ("/aws-blocked", "AWS", 403),
        ];

        let mut all_passed = true;
        let mut messages = Vec::new();

        for (path, expected_waf, _expected_status) in test_cases {
            let url = format!("{base_url}{path}");
            let output = run_detector_cli_async(&[&url, "--json"], Duration::from_secs(10)).await?;

            if output.exit_code != 0 {
                // This is expected for blocked requests
                messages.push(format!("{path}: Blocked (as expected)"));
                continue;
            }

            if let Some(json) = output.json_output {
                let results = parse_detection_results(&json)?;

                // Check if WAF was detected
                if let Some(waf) = &results.waf {
                    if waf.name == expected_waf {
                        messages.push(format!("{path}: Detected {expected_waf} (OK)"));
                    } else {
                        all_passed = false;
                        messages.push(format!(
                            "{}: Expected {}, got {}",
                            path, expected_waf, waf.name
                        ));
                    }
                } else {
                    all_passed = false;
                    messages.push(format!("{path}: No WAF detected"));
                }
            }
        }

        Ok(TestResult {
            name: self.name().to_string(),
            passed: all_passed,
            message: messages.join(", "),
            duration: Duration::from_secs(0),
            details: None,
        })
    }
}

/// Batch detection scenario
pub struct BatchDetectionScenario {
    name: String,
    mock_server: Option<MockServer>,
}

impl BatchDetectionScenario {
    pub fn new() -> Self {
        Self {
            name: "batch_detection".to_string(),
            mock_server: None,
        }
    }
}

#[async_trait]
impl IntegrationTestCase for BatchDetectionScenario {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "Test batch detection of multiple URLs"
    }

    async fn setup(&mut self, context: &mut TestContext) -> Result<()> {
        let mut server = MockServer::new().await?;
        let url = server.start().await?;

        // Configure various responses
        server.mock_cloudflare("/site1");
        server.mock_aws_cloudfront("/site2");
        server.mock_akamai("/site3");

        context.mock_server_url = Some(url);
        self.mock_server = Some(server);

        Ok(())
    }

    async fn execute(&self, context: &TestContext) -> Result<TestResult> {
        let base_url = context
            .mock_server_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Mock server URL not set"))?;

        // Create URL list file
        let temp_dir = tempfile::tempdir()?;
        let urls_file = temp_dir.path().join("urls.txt");

        let urls = [
            format!("{base_url}/site1"),
            format!("{base_url}/site2"),
            format!("{base_url}/site3"),
        ];

        std::fs::write(&urls_file, urls.join("\n"))?;

        // Run batch detection
        let output = run_detector_cli_async(
            &["--batch", urls_file.to_str().unwrap(), "--json"],
            Duration::from_secs(30),
        )
        .await?;

        if output.exit_code != 0 {
            return Ok(TestResult {
                name: self.name().to_string(),
                passed: false,
                message: format!("Batch detection failed: {}", output.stderr),
                duration: Duration::from_secs(0),
                details: None,
            });
        }

        // Verify we got results for all URLs
        let passed = output.stdout.contains("CloudFlare")
            && output.stdout.contains("AWS")
            && output.stdout.contains("Akamai");

        Ok(TestResult {
            name: self.name().to_string(),
            passed,
            message: if passed {
                "All providers detected in batch".to_string()
            } else {
                "Some providers not detected".to_string()
            },
            duration: Duration::from_secs(0),
            details: None,
        })
    }
}
