//! Integration tests for WAF effectiveness testing module

use waf_detector::effectiveness::{EffectivenessConfig, EffectivenessTest};

#[tokio::test]
#[ignore = "Requires configured target scope - run with cargo test -- --ignored"]
async fn test_effectiveness_basic_flow() {
    // This test is ignored by default since it requires configured target scope
    // Run with: cargo test test_effectiveness_basic_flow -- --ignored

    let config = EffectivenessConfig {
        intensity_level: 1, // Basic level only
        ..Default::default()
    };

    // This will fail if no target scope is present
    match EffectivenessTest::new(config).await {
        Ok(_test) => {
            // Would run against a test URL if target scope was configured
            println!("Effectiveness test created successfully");
        }
        Err(e) => {
            // Expected when no target scope file exists
            assert!(e.to_string().contains("active target scope is required"));
        }
    }
}
