// Main integration test runner
#![allow(dead_code)]

mod integration;

use integration::{
    framework::{TestContext, TestRunner},
    scenarios::*,
};
use std::env;
use std::time::Instant;

fn should_run_integration_tests() -> bool {
    matches!(
        env::var("WAF_DETECTOR_RUN_INTEGRATION").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

#[tokio::test]
async fn test_all_integration_scenarios() {
    if !should_run_integration_tests() {
        eprintln!("Skipping integration scenarios (set WAF_DETECTOR_RUN_INTEGRATION=1 to enable).");
        return;
    }
    // Set up test context
    let context = TestContext {
        debug_mode: env::var("DEBUG").is_ok(),
        retry_count: 3,
        ..Default::default()
    };

    // Create test runner
    let mut runner = TestRunner::new().with_context(context);

    // Add all test scenarios
    runner = runner
        // Basic scenarios
        .add_test(BasicDetectionScenario::new())
        .add_test(MultiProviderScenario::new())
        .add_test(PerformanceScenario::new())
        .add_test(WafBlockingScenario::new())
        .add_test(BatchDetectionScenario::new());

    // Run all tests
    let start = Instant::now();
    let results = runner.run_all().await;
    let duration = start.elapsed();

    // Generate report
    let report = runner.generate_report(&results);
    println!("\n{report}");
    println!("Total test duration: {duration:?}\n");

    // Check if all tests passed
    let all_passed = results.iter().all(|r| r.passed);
    let passed_count = results.iter().filter(|r| r.passed).count();
    let total_count = results.len();

    // Save report to file
    if std::fs::write("integration_test_report.txt", &report).is_ok() {
        println!("Report saved to integration_test_report.txt");
    }

    // Assert all tests passed
    assert!(
        all_passed,
        "Integration tests failed: {passed_count}/{total_count} passed"
    );
}

#[tokio::test]
async fn test_provider_specific_scenarios() {
    if !should_run_integration_tests() {
        eprintln!("Skipping provider-specific scenarios (set WAF_DETECTOR_RUN_INTEGRATION=1 to enable).");
        return;
    }
    let context = TestContext::default();

    let mut runner = TestRunner::new().with_context(context);

    // Add provider-specific test scenarios
    // These would be implemented in separate test files
    // For now, we'll just test the basic scenarios

    let results = runner.run_all().await;
    let report = runner.generate_report(&results);

    println!("\nProvider-Specific Tests:\n{report}");
}

#[cfg(test)]
mod integration_helpers {
    use super::*;

    /// Helper to run a specific test scenario
    pub async fn run_single_scenario<T: integration::framework::IntegrationTestCase + 'static>(
        test: T,
    ) -> bool {
        let mut runner = TestRunner::new().add_test(test);

        let results = runner.run_all().await;
        results.first().map(|r| r.passed).unwrap_or(false)
    }
}

// Individual scenario tests for debugging
#[tokio::test]
async fn test_basic_detection_individually() {
    if !should_run_integration_tests() {
        eprintln!("Skipping basic detection scenario (set WAF_DETECTOR_RUN_INTEGRATION=1 to enable).");
        return;
    }
    let passed = integration_helpers::run_single_scenario(BasicDetectionScenario::new()).await;

    assert!(passed, "Basic detection scenario failed");
}

#[tokio::test]
async fn test_performance_individually() {
    if !should_run_integration_tests() {
        eprintln!("Skipping performance scenario (set WAF_DETECTOR_RUN_INTEGRATION=1 to enable).");
        return;
    }
    let passed = integration_helpers::run_single_scenario(PerformanceScenario::new()).await;

    assert!(passed, "Performance scenario failed");
}

#[tokio::test]
async fn test_waf_blocking_individually() {
    if !should_run_integration_tests() {
        eprintln!("Skipping WAF blocking scenario (set WAF_DETECTOR_RUN_INTEGRATION=1 to enable).");
        return;
    }
    let passed = integration_helpers::run_single_scenario(WafBlockingScenario::new()).await;

    assert!(passed, "WAF blocking scenario failed");
}
