#![allow(dead_code)]
#![allow(clippy::field_reassign_with_default)]

mod integration;

use anyhow::Result;
use async_trait::async_trait;
use integration::{
    framework::{IntegrationTestCase, TestContext, TestResult, TestRunner},
    mock_server::MockServer,
    utils::{parse_detection_results, run_detector_cli_async},
};
use std::time::Duration;

/// CloudFlare-specific integration tests
struct CloudFlareIntegrationTest {
    name: String,
    mock_server: Option<MockServer>,
}

impl CloudFlareIntegrationTest {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            mock_server: None,
        }
    }
}

/// Test CloudFlare standard headers detection
struct CloudFlareHeaderTest(CloudFlareIntegrationTest);

impl CloudFlareHeaderTest {
    fn new() -> Self {
        Self(CloudFlareIntegrationTest::new(
            "cloudflare_header_detection",
        ))
    }
}

#[async_trait]
impl IntegrationTestCase for CloudFlareHeaderTest {
    fn name(&self) -> &str {
        &self.0.name
    }

    fn description(&self) -> &str {
        "Test CloudFlare detection via standard headers"
    }

    async fn setup(&mut self, context: &mut TestContext) -> Result<()> {
        let mut server = MockServer::new().await?;
        let url = server.start().await?;

        // Standard CloudFlare headers
        server.mock_cloudflare("/standard");

        // CloudFlare with additional headers
        let mut response = integration::mock_server::MockResponse::default();
        response.status = 200;
        response
            .headers
            .insert("cf-ray".to_string(), "7e6789abc123def0-DFW".to_string());
        response
            .headers
            .insert("cf-cache-status".to_string(), "HIT".to_string());
        response
            .headers
            .insert("cf-request-id".to_string(), "123456789".to_string());
        response
            .headers
            .insert("cf-edge-server".to_string(), "DFW50".to_string());
        response
            .headers
            .insert("server".to_string(), "cloudflare".to_string());
        response.body =
            r#"<!DOCTYPE html><html><body>CloudFlare Protected</body></html>"#.to_string();

        server.mock_response("/enhanced", response);

        context.mock_server_url = Some(url);
        self.0.mock_server = Some(server);

        Ok(())
    }

    async fn execute(&self, context: &TestContext) -> Result<TestResult> {
        let base_url = context
            .mock_server_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Mock server URL not set"))?;

        // Test standard headers
        let url = format!("{base_url}/standard");
        let output = run_detector_cli_async(&[&url, "--json"], Duration::from_secs(10)).await?;

        if output.exit_code != 0 {
            return Ok(TestResult {
                name: self.name().to_string(),
                passed: false,
                message: format!("Standard detection failed: {}", output.stderr),
                duration: Duration::from_secs(0),
                details: None,
            });
        }

        let json = output
            .json_output
            .ok_or_else(|| anyhow::anyhow!("No JSON output"))?;
        let results = parse_detection_results(&json)?;

        // Verify CloudFlare was detected
        let mut checks = vec![];

        if let Some(waf) = &results.waf {
            checks.push(("WAF detection", waf.name == "CloudFlare"));
            checks.push(("WAF confidence", waf.confidence >= 0.95));
        } else {
            checks.push(("WAF detection", false));
        }

        if let Some(cdn) = &results.cdn {
            checks.push(("CDN detection", cdn.name == "CloudFlare"));
            checks.push(("CDN confidence", cdn.confidence >= 0.95));
        } else {
            checks.push(("CDN detection", false));
        }

        // Check evidence
        let has_cf_ray = results.evidence.iter().any(|e| {
            let description = e.description.to_lowercase();
            let method_type = e.method_type.to_lowercase();
            method_type.contains("cf-ray")
                || description.contains("cf-ray")
                || description.contains("ray id")
        });
        checks.push(("CF-Ray evidence", has_cf_ray));

        let all_passed = checks.iter().all(|(_, passed)| *passed);
        let message = checks
            .iter()
            .map(|(check, passed)| format!("{}: {}", check, if *passed { "PASS" } else { "FAIL" }))
            .collect::<Vec<_>>()
            .join(", ");

        Ok(TestResult {
            name: self.name().to_string(),
            passed: all_passed,
            message,
            duration: Duration::from_secs(0),
            details: None,
        })
    }
}

/// Test CloudFlare challenge page detection
struct CloudFlareChallengePage(CloudFlareIntegrationTest);

impl CloudFlareChallengePage {
    fn new() -> Self {
        Self(CloudFlareIntegrationTest::new("cloudflare_challenge_page"))
    }
}

#[async_trait]
impl IntegrationTestCase for CloudFlareChallengePage {
    fn name(&self) -> &str {
        &self.0.name
    }

    fn description(&self) -> &str {
        "Test CloudFlare challenge page detection"
    }

    async fn setup(&mut self, context: &mut TestContext) -> Result<()> {
        let mut server = MockServer::new().await?;
        let url = server.start().await?;

        // CloudFlare challenge page
        let mut response = integration::mock_server::MockResponse::default();
        response.status = 503;
        response
            .headers
            .insert("cf-ray".to_string(), "7e6789abc123def0-DFW".to_string());
        response
            .headers
            .insert("cf-chl-bypass".to_string(), "1".to_string());
        response.body = r#"<!DOCTYPE html>
<html>
<head>
    <title>Just a moment...</title>
    <script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>
</head>
<body>
    <div class="cf-browser-verification cf-im-under-attack">
        <h1 data-translate="turn_on_js">Please turn JavaScript on and reload the page.</h1>
        <div id="cf-content">Checking your browser before accessing the Cloudflare website.</div>
        <input type="hidden" name="cf_chl_jschl_tk" value="test-token" />
    </div>
</body>
</html>"#
            .to_string();

        server.mock_response("/challenge", response);

        context.mock_server_url = Some(url);
        self.0.mock_server = Some(server);

        Ok(())
    }

    async fn execute(&self, context: &TestContext) -> Result<TestResult> {
        let base_url = context
            .mock_server_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Mock server URL not set"))?;

        let url = format!("{base_url}/challenge");
        let output = run_detector_cli_async(&[&url, "--json"], Duration::from_secs(10)).await?;

        // Challenge pages might cause non-zero exit codes
        let json = output
            .json_output
            .ok_or_else(|| anyhow::anyhow!("No JSON output"))?;
        let results = parse_detection_results(&json)?;

        // Should detect CloudFlare with high confidence
        let waf_ok = results
            .waf
            .as_ref()
            .map(|w| w.name == "CloudFlare" && w.confidence >= 0.95)
            .unwrap_or(false);

        // Check for challenge page evidence
        let has_challenge_evidence = results.evidence.iter().any(|e| {
            e.description.to_lowercase().contains("challenge")
                || e.description.contains("cf-browser-verification")
        });

        let passed = waf_ok && has_challenge_evidence;

        Ok(TestResult {
            name: self.name().to_string(),
            passed,
            message: format!(
                "WAF: {}, Challenge evidence: {}",
                if waf_ok { "OK" } else { "FAIL" },
                if has_challenge_evidence {
                    "Found"
                } else {
                    "Missing"
                }
            ),
            duration: Duration::from_secs(0),
            details: None,
        })
    }
}

/// Test CloudFlare Workers detection
struct CloudFlareWorkersTest(CloudFlareIntegrationTest);

impl CloudFlareWorkersTest {
    fn new() -> Self {
        Self(CloudFlareIntegrationTest::new(
            "cloudflare_workers_detection",
        ))
    }
}

#[async_trait]
impl IntegrationTestCase for CloudFlareWorkersTest {
    fn name(&self) -> &str {
        &self.0.name
    }

    fn description(&self) -> &str {
        "Test CloudFlare Workers detection"
    }

    async fn setup(&mut self, context: &mut TestContext) -> Result<()> {
        let mut server = MockServer::new().await?;
        let url = server.start().await?;

        // CloudFlare Workers response
        let mut response = integration::mock_server::MockResponse::default();
        response.status = 200;
        response
            .headers
            .insert("cf-ray".to_string(), "7e6789abc123def0-DFW".to_string());
        response
            .headers
            .insert("cf-worker".to_string(), "example.workers.dev".to_string());
        response
            .headers
            .insert("server".to_string(), "cloudflare".to_string());
        response.body = r#"{"message": "Hello from CloudFlare Workers!"}"#.to_string();

        server.mock_response("/worker", response);

        context.mock_server_url = Some(url);
        self.0.mock_server = Some(server);

        Ok(())
    }

    async fn execute(&self, context: &TestContext) -> Result<TestResult> {
        let base_url = context
            .mock_server_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Mock server URL not set"))?;

        let url = format!("{base_url}/worker");
        let output = run_detector_cli_async(&[&url, "--json"], Duration::from_secs(10)).await?;

        if output.exit_code != 0 {
            return Ok(TestResult {
                name: self.name().to_string(),
                passed: false,
                message: format!("Detection failed: {}", output.stderr),
                duration: Duration::from_secs(0),
                details: None,
            });
        }

        let json = output
            .json_output
            .ok_or_else(|| anyhow::anyhow!("No JSON output"))?;
        let results = parse_detection_results(&json)?;

        // Should detect CloudFlare
        let detected = results
            .waf
            .as_ref()
            .map(|w| w.name == "CloudFlare")
            .unwrap_or(false)
            || results
                .cdn
                .as_ref()
                .map(|c| c.name == "CloudFlare")
                .unwrap_or(false);

        // Check for Workers evidence
        let has_worker_evidence = results
            .evidence
            .iter()
            .any(|e| e.description.contains("cf-worker") || e.description.contains("Workers"));

        Ok(TestResult {
            name: self.name().to_string(),
            passed: detected,
            message: format!(
                "Detection: {}, Workers evidence: {}",
                if detected { "OK" } else { "FAIL" },
                if has_worker_evidence {
                    "Found"
                } else {
                    "Not specific"
                }
            ),
            duration: Duration::from_secs(0),
            details: None,
        })
    }
}

#[tokio::test]
async fn test_cloudflare_integration() {
    let mut runner = TestRunner::new();

    // Add all CloudFlare tests
    runner = runner
        .add_test(CloudFlareHeaderTest::new())
        .add_test(CloudFlareChallengePage::new())
        .add_test(CloudFlareWorkersTest::new());

    let results = runner.run_all().await;
    let report = runner.generate_report(&results);

    println!("{report}");

    // Assert all tests passed
    let all_passed = results.iter().all(|r| r.passed);
    assert!(all_passed, "Some CloudFlare integration tests failed");
}
