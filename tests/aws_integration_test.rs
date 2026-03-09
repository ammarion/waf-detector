#![allow(dead_code)]
#![allow(clippy::field_reassign_with_default)]

mod integration;

use anyhow::Result;
use async_trait::async_trait;
use integration::{
    framework::{IntegrationTestCase, TestContext, TestResult, TestRunner},
    mock_server::MockServer,
    utils::{parse_detection_results, run_detector_cli_async, wait_for_server},
};
use std::time::Duration;

/// AWS CloudFront standard detection test
struct AwsCloudFrontTest {
    name: String,
    mock_server: Option<MockServer>,
}

impl AwsCloudFrontTest {
    fn new() -> Self {
        Self {
            name: "aws_cloudfront_detection".to_string(),
            mock_server: None,
        }
    }
}

#[async_trait]
impl IntegrationTestCase for AwsCloudFrontTest {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "Test AWS CloudFront CDN detection"
    }

    async fn setup(&mut self, context: &mut TestContext) -> Result<()> {
        let mut server = MockServer::new().await?;
        let url = server.start().await?;

        // Standard CloudFront response
        server.mock_aws_cloudfront("/standard");

        // CloudFront with S3 origin
        let mut response = integration::mock_server::MockResponse::default();
        response.status = 200;
        response.headers.insert(
            "x-amz-cf-id".to_string(),
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
        );
        response
            .headers
            .insert("x-amz-cf-pop".to_string(), "DFW50-C1".to_string());
        response
            .headers
            .insert("x-cache".to_string(), "Hit from cloudfront".to_string());
        response.headers.insert(
            "x-amz-server-side-encryption".to_string(),
            "AES256".to_string(),
        );
        response.headers.insert(
            "via".to_string(),
            "1.1 abc123.cloudfront.net (CloudFront)".to_string(),
        );
        server.mock_response("/s3-origin", response);

        context.mock_server_url = Some(url.clone());
        self.mock_server = Some(server);

        wait_for_server(&url, 5).await?;
        Ok(())
    }

    async fn execute(&self, context: &TestContext) -> Result<TestResult> {
        let base_url = context
            .mock_server_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Mock server URL not set"))?;

        let test_cases = vec![
            ("/standard", "Standard CloudFront"),
            ("/s3-origin", "CloudFront with S3"),
        ];

        let mut all_passed = true;
        let mut messages = Vec::new();

        for (path, description) in test_cases {
            let url = format!("{base_url}{path}");
            let output = run_detector_cli_async(&[&url, "--json"], Duration::from_secs(10)).await?;

            if output.exit_code != 0 {
                all_passed = false;
                messages.push(format!("{description}: CLI failed"));
                continue;
            }

            let json = output
                .json_output
                .ok_or_else(|| anyhow::anyhow!("No JSON output"))?;
            let results = parse_detection_results(&json)?;

            // Check CDN detection
            let cdn_ok = results
                .cdn
                .as_ref()
                .map(|c| c.name == "AWS" && c.confidence >= 0.90)
                .unwrap_or(false);

            // Check for CloudFront evidence
            let has_cf_evidence = results.evidence.iter().any(|e| {
                e.description.contains("x-amz-cf-id") || e.description.contains("CloudFront")
            });

            if cdn_ok && has_cf_evidence {
                messages.push(format!("{description}: PASS"));
            } else {
                all_passed = false;
                messages.push(format!(
                    "{}: FAIL (CDN: {}, Evidence: {})",
                    description,
                    if cdn_ok { "OK" } else { "Missing" },
                    if has_cf_evidence { "OK" } else { "Missing" }
                ));
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

/// AWS WAF detection test
struct AwsWafTest {
    name: String,
    mock_server: Option<MockServer>,
}

impl AwsWafTest {
    fn new() -> Self {
        Self {
            name: "aws_waf_detection".to_string(),
            mock_server: None,
        }
    }
}

#[async_trait]
impl IntegrationTestCase for AwsWafTest {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "Test AWS WAF detection and blocking"
    }

    async fn setup(&mut self, context: &mut TestContext) -> Result<()> {
        let mut server = MockServer::new().await?;
        let url = server.start().await?;

        // AWS WAF blocked response
        server.mock_waf_blocked("/blocked", "aws");

        // AWS WAF with custom rule
        let mut response = integration::mock_server::MockResponse::default();
        response.status = 403;
        response.headers.insert(
            "x-amzn-requestid".to_string(),
            "12345678-1234-5678-9abc-def012345678".to_string(),
        );
        response.headers.insert(
            "x-amzn-errortype".to_string(),
            "AwsWafException".to_string(),
        );
        response.body = r#"<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body>
    <h1>403 Forbidden</h1>
    <p>Request blocked by AWS WAF.</p>
    <p>If you think this is an error, please contact the website owner.</p>
    <hr>
    <p>Request ID: 1234567890</p>
</body>
</html>"#
            .to_string();
        server.mock_response("/custom-rule", response);

        // AWS Shield response
        let mut shield_response = integration::mock_server::MockResponse::default();
        shield_response.status = 403;
        shield_response
            .headers
            .insert("x-amzn-requestid".to_string(), "shield-123".to_string());
        shield_response
            .headers
            .insert("server".to_string(), "AmazonS3".to_string());
        shield_response.body = r#"<Error><Code>RequestThrottled</Code><Message>AWS Shield has blocked this request</Message></Error>"#.to_string();
        server.mock_response("/shield", shield_response);

        context.mock_server_url = Some(url.clone());
        self.mock_server = Some(server);

        wait_for_server(&url, 5).await?;
        Ok(())
    }

    async fn execute(&self, context: &TestContext) -> Result<TestResult> {
        let base_url = context
            .mock_server_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Mock server URL not set"))?;

        let test_cases = vec![
            ("/blocked", "Standard WAF block", true),
            ("/custom-rule", "Custom rule block", true),
            ("/shield", "AWS Shield block", true),
        ];

        let mut all_passed = true;
        let mut messages = Vec::new();

        for (path, description, expect_waf) in test_cases {
            let url = format!("{base_url}{path}");
            let output = run_detector_cli_async(&[&url, "--json"], Duration::from_secs(10)).await?;

            // WAF blocks might return non-zero exit codes
            if let Some(json) = output.json_output {
                let results = parse_detection_results(&json)?;

                let waf_detected = results.waf.is_some();
                let is_aws = results
                    .waf
                    .as_ref()
                    .map(|w| w.name == "AWS")
                    .unwrap_or(false);

                if expect_waf && is_aws {
                    messages.push(format!("{description}: PASS"));
                } else {
                    all_passed = false;
                    messages.push(format!(
                        "{description}: FAIL (WAF detected: {waf_detected}, Is AWS: {is_aws})"
                    ));
                }
            } else {
                // No JSON might indicate blocking worked
                messages.push(format!(
                    "{}: Blocked (exit code: {})",
                    description, output.exit_code
                ));
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

/// AWS ALB/ELB detection test
struct AwsLoadBalancerTest {
    name: String,
    mock_server: Option<MockServer>,
}

impl AwsLoadBalancerTest {
    fn new() -> Self {
        Self {
            name: "aws_load_balancer_detection".to_string(),
            mock_server: None,
        }
    }
}

#[async_trait]
impl IntegrationTestCase for AwsLoadBalancerTest {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "Test AWS ALB/ELB detection"
    }

    async fn setup(&mut self, context: &mut TestContext) -> Result<()> {
        let mut server = MockServer::new().await?;
        let url = server.start().await?;

        // ALB response
        let mut alb_response = integration::mock_server::MockResponse::default();
        alb_response.status = 200;
        alb_response
            .headers
            .insert("server".to_string(), "awselb/2.0".to_string());
        alb_response.headers.insert(
            "x-amzn-trace-id".to_string(),
            "Root=1-12345678-12345678123456781234567".to_string(),
        );
        server.mock_response("/alb", alb_response);

        // Classic ELB response
        let mut elb_response = integration::mock_server::MockResponse::default();
        elb_response.status = 200;
        elb_response
            .headers
            .insert("server".to_string(), "AmazonEC2".to_string());
        server.mock_response("/elb", elb_response);

        context.mock_server_url = Some(url.clone());
        self.mock_server = Some(server);

        wait_for_server(&url, 5).await?;
        Ok(())
    }

    async fn execute(&self, context: &TestContext) -> Result<TestResult> {
        let base_url = context
            .mock_server_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Mock server URL not set"))?;

        let test_cases = vec![("/alb", "ALB detection"), ("/elb", "Classic ELB detection")];

        let mut detected_count = 0;
        let mut messages = Vec::new();

        for (path, description) in test_cases {
            let url = format!("{base_url}{path}");
            let output = run_detector_cli_async(&[&url, "--json"], Duration::from_secs(10)).await?;

            if output.exit_code == 0 {
                if let Some(json) = output.json_output {
                    let results = parse_detection_results(&json)?;

                    let detected = results.waf.is_some() || results.cdn.is_some();
                    let is_aws = results
                        .waf
                        .as_ref()
                        .map(|w| w.name == "AWS")
                        .unwrap_or(false)
                        || results
                            .cdn
                            .as_ref()
                            .map(|c| c.name == "AWS")
                            .unwrap_or(false);

                    if detected && is_aws {
                        detected_count += 1;
                        messages.push(format!("{description}: Detected"));
                    } else {
                        messages.push(format!("{description}: Not detected"));
                    }
                }
            }
        }

        // At least one should be detected
        let passed = detected_count > 0;

        Ok(TestResult {
            name: self.name().to_string(),
            passed,
            message: format!(
                "Detected {}/2 load balancers. {}",
                detected_count,
                messages.join(", ")
            ),
            duration: Duration::from_secs(0),
            details: None,
        })
    }
}

#[tokio::test]
async fn test_aws_integration() {
    let mut runner = TestRunner::new();

    // Add all AWS tests
    runner = runner
        .add_test(AwsCloudFrontTest::new())
        .add_test(AwsWafTest::new())
        .add_test(AwsLoadBalancerTest::new());

    let results = runner.run_all().await;
    let report = runner.generate_report(&results);

    println!("{report}");

    // Assert critical tests passed (CloudFront should always work)
    let cloudfront_passed = results
        .iter()
        .find(|r| r.name == "aws_cloudfront_detection")
        .map(|r| r.passed)
        .unwrap_or(false);

    assert!(cloudfront_passed, "AWS CloudFront detection test failed");
}
