use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;
use waf_detector::{DetectionResult, Evidence};

/// Core integration test framework
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct IntegrationTest {
    pub name: String,
    pub description: String,
    pub timeout: Duration,
    pub context: TestContext,
}

/// Test context containing shared state and configuration
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct TestContext {
    pub mock_server_url: Option<String>,
    pub test_data: HashMap<String, String>,
    pub environment: HashMap<String, String>,
    pub retry_count: u32,
    pub debug_mode: bool,
}

/// Result of a test execution
#[derive(Debug)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
    pub duration: Duration,
    pub details: Option<HashMap<String, serde_json::Value>>,
}

/// Trait for implementing integration tests
#[async_trait]
#[allow(dead_code)]
pub trait IntegrationTestCase: Send + Sync {
    /// Test name
    fn name(&self) -> &str;

    /// Test description
    fn description(&self) -> &str;

    /// Setup test environment
    async fn setup(&mut self, _context: &mut TestContext) -> Result<()> {
        Ok(())
    }

    /// Execute the test
    async fn execute(&self, context: &TestContext) -> Result<TestResult>;

    /// Cleanup after test
    async fn teardown(&mut self, _context: &mut TestContext) -> Result<()> {
        Ok(())
    }
}

/// Test runner for executing integration tests
pub struct TestRunner {
    tests: Vec<Box<dyn IntegrationTestCase>>,
    context: TestContext,
}

impl TestRunner {
    pub fn new() -> Self {
        Self {
            tests: Vec::new(),
            context: TestContext::default(),
        }
    }

    pub fn with_context(mut self, context: TestContext) -> Self {
        self.context = context;
        self
    }

    pub fn add_test<T: IntegrationTestCase + 'static>(mut self, test: T) -> Self {
        self.tests.push(Box::new(test));
        self
    }

    pub async fn run_all(&mut self) -> Vec<TestResult> {
        let mut results = Vec::new();

        for test in &mut self.tests {
            let start = std::time::Instant::now();

            // Setup
            if let Err(e) = test.setup(&mut self.context).await {
                results.push(TestResult {
                    name: test.name().to_string(),
                    passed: false,
                    message: format!("Setup failed: {e}"),
                    duration: start.elapsed(),
                    details: None,
                });
                continue;
            }

            // Execute
            let result = match test.execute(&self.context).await {
                Ok(mut res) => {
                    res.duration = start.elapsed();
                    res
                }
                Err(e) => TestResult {
                    name: test.name().to_string(),
                    passed: false,
                    message: format!("Test failed: {e}"),
                    duration: start.elapsed(),
                    details: None,
                },
            };

            // Teardown
            if let Err(e) = test.teardown(&mut self.context).await {
                eprintln!("Warning: Teardown failed for {}: {}", test.name(), e);
            }

            results.push(result);
        }

        results
    }

    pub fn generate_report(&self, results: &[TestResult]) -> String {
        let total = results.len();
        let passed = results.iter().filter(|r| r.passed).count();
        let failed = total - passed;

        let mut report = format!(
            "Integration Test Report\n\
             ======================\n\n\
             Total Tests: {}\n\
             Passed: {} ({:.1}%)\n\
             Failed: {} ({:.1}%)\n\n",
            total,
            passed,
            (passed as f64 / total as f64) * 100.0,
            failed,
            (failed as f64 / total as f64) * 100.0
        );

        if failed > 0 {
            report.push_str("Failed Tests:\n");
            report.push_str("-------------\n");
            for result in results.iter().filter(|r| !r.passed) {
                report.push_str(&format!(
                    "- {} ({}ms): {}\n",
                    result.name,
                    result.duration.as_millis(),
                    result.message
                ));
            }
            report.push('\n');
        }

        report.push_str("Test Details:\n");
        report.push_str("-------------\n");
        for result in results {
            let status = if result.passed { "PASS" } else { "FAIL" };
            report.push_str(&format!(
                "{}: {} ({}ms)\n",
                status,
                result.name,
                result.duration.as_millis()
            ));

            if !result.passed {
                report.push_str(&format!("  Error: {}\n", result.message));
            }

            if let Some(details) = &result.details {
                for (key, value) in details {
                    report.push_str(&format!("  {key}: {value}\n"));
                }
            }
            report.push('\n');
        }

        report
    }
}

/// Helper function to assert detection results
pub fn assert_detection(
    result: &DetectionResult,
    expected_provider: &str,
    min_confidence: f64,
    message: &str,
) -> Result<()> {
    // Check both WAF and CDN detections
    let detected_provider = result
        .detected_waf
        .as_ref()
        .map(|w| w.name.as_str())
        .or_else(|| result.detected_cdn.as_ref().map(|c| c.name.as_str()));

    match detected_provider {
        Some(provider) if provider == expected_provider => {
            // Check confidence
            let confidence = result
                .detected_waf
                .as_ref()
                .map(|w| w.confidence)
                .or_else(|| result.detected_cdn.as_ref().map(|c| c.confidence))
                .unwrap_or(0.0);

            if confidence < min_confidence {
                return Err(anyhow::anyhow!(
                    "{}: Confidence {} is below minimum {}",
                    message,
                    confidence,
                    min_confidence
                ));
            }
            Ok(())
        }
        Some(provider) => Err(anyhow::anyhow!(
            "{}: Expected provider '{}', got '{}'",
            message,
            expected_provider,
            provider
        )),
        None => Err(anyhow::anyhow!(
            "{}: No provider detected, expected '{}'",
            message,
            expected_provider
        )),
    }
}

/// Helper function to verify evidence
pub fn assert_evidence_contains(
    evidence: &[Evidence],
    method_type_substr: &str,
    description_substr: &str,
) -> Result<()> {
    let found = evidence.iter().any(|e| {
        let method_str = format!("{:?}", e.method_type);
        method_str.contains(method_type_substr) && e.description.contains(description_substr)
    });

    if !found {
        return Err(anyhow::anyhow!(
            "Evidence not found with method containing '{}' and description containing '{}'",
            method_type_substr,
            description_substr
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleTest;

    #[async_trait]
    impl IntegrationTestCase for SimpleTest {
        fn name(&self) -> &str {
            "simple_test"
        }

        fn description(&self) -> &str {
            "A simple test case"
        }

        async fn execute(&self, _context: &TestContext) -> Result<TestResult> {
            Ok(TestResult {
                name: self.name().to_string(),
                passed: true,
                message: "Test passed".to_string(),
                duration: Duration::from_millis(100),
                details: None,
            })
        }
    }

    #[tokio::test]
    async fn test_runner_basic() {
        let mut runner = TestRunner::new().add_test(SimpleTest);

        let results = runner.run_all().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
    }
}
