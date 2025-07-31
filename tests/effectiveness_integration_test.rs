//! Integration tests for WAF effectiveness testing module

use waf_detector::effectiveness::{EffectivenessConfig, EffectivenessTest};

#[tokio::test]
#[ignore = "Requires user consent - run with cargo test -- --ignored"]
async fn test_effectiveness_basic_flow() {
    // This test is ignored by default since it requires user consent
    // Run with: cargo test test_effectiveness_basic_flow -- --ignored

    let config = EffectivenessConfig {
        intensity_level: 1, // Basic level only
        ..Default::default()
    };

    // This will fail if no consent is present
    match EffectivenessTest::new(config).await {
        Ok(_test) => {
            // Would run against a test URL if consent was provided
            println!("Effectiveness test created successfully");
        }
        Err(e) => {
            // Expected when no consent file exists
            assert!(e.to_string().contains("must acknowledge responsible use"));
        }
    }
}
