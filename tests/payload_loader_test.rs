use std::path::Path;
use waf_detector::payload::loader::PayloadLoader;

#[test]
fn test_load_external_toml_payloads() {
    let payloads_dir = Path::new("payloads");

    if !payloads_dir.exists() {
        println!("Payloads directory not found, skipping test");
        return;
    }

    let payloads = PayloadLoader::load_from_directory(payloads_dir)
        .expect("Failed to load payloads from TOML files");

    assert!(
        !payloads.is_empty(),
        "Should load at least one payload from TOML files"
    );

    // Verify we have payloads from different categories
    let categories: std::collections::HashSet<_> =
        payloads.iter().map(|p| p.category.as_str()).collect();

    println!(
        "Loaded {} payloads from {} categories",
        payloads.len(),
        categories.len()
    );

    // Check for expected categories
    assert!(categories.contains("XSS"), "Should have XSS payloads");
    assert!(
        categories.contains("SQLInjection"),
        "Should have SQL injection payloads"
    );
    assert!(
        categories.contains("CommandInjection"),
        "Should have command injection payloads"
    );
    assert!(
        categories.contains("PathTraversal"),
        "Should have path traversal payloads"
    );
    assert!(categories.contains("SSTI"), "Should have SSTI payloads");
    assert!(categories.contains("SSRF"), "Should have SSRF payloads");
    assert!(
        categories.contains("Log4Shell"),
        "Should have Log4Shell payloads"
    );
    assert!(
        categories.contains("PrototypePollution"),
        "Should have prototype pollution payloads"
    );

    // Verify each payload has required fields
    for payload in &payloads {
        assert!(!payload.id.is_empty(), "Payload ID should not be empty");
        assert!(!payload.name.is_empty(), "Payload name should not be empty");
        assert!(
            !payload.pattern.is_empty(),
            "Payload pattern should not be empty"
        );
        assert!(
            !payload.description.is_empty(),
            "Payload description should not be empty"
        );
        assert!(
            !payload.risk_level.is_empty(),
            "Payload risk_level should not be empty"
        );
    }
}

#[test]
fn test_load_with_fallback() {
    // Test loading with fallback
    let payloads = PayloadLoader::load_with_fallback(None);

    assert!(
        !payloads.is_empty(),
        "Fallback should provide at least built-in payloads"
    );

    println!("Loaded {} payloads via fallback mechanism", payloads.len());
}

#[test]
fn test_filter_by_category() {
    let payloads = PayloadLoader::load_with_fallback(None);

    let xss_payloads = PayloadLoader::get_by_category(&payloads, "XSS");
    assert!(!xss_payloads.is_empty(), "Should have XSS payloads");
    assert!(
        xss_payloads.iter().all(|p| p.category == "XSS"),
        "All filtered payloads should be XSS"
    );

    println!("Found {} XSS payloads", xss_payloads.len());
}

#[test]
fn test_filter_by_risk_level() {
    let payloads = PayloadLoader::load_with_fallback(None);

    let critical = PayloadLoader::get_by_risk_level(&payloads, "CRITICAL");
    assert!(!critical.is_empty(), "Should have CRITICAL risk payloads");
    assert!(
        critical.iter().all(|p| p.risk_level == "CRITICAL"),
        "All filtered payloads should be CRITICAL"
    );

    let high_and_above = PayloadLoader::get_by_risk_level(&payloads, "HIGH");
    assert!(
        high_and_above.len() >= critical.len(),
        "HIGH filter should include CRITICAL payloads"
    );

    println!(
        "Found {} CRITICAL and {} HIGH+ payloads",
        critical.len(),
        high_and_above.len()
    );
}

#[test]
fn test_specific_toml_files() {
    let payloads_dir = Path::new("payloads");

    if !payloads_dir.exists() {
        println!("Payloads directory not found, skipping test");
        return;
    }

    // Check that specific TOML files exist and are parseable
    let expected_files = vec![
        "xss.toml",
        "sqli.toml",
        "command_injection.toml",
        "path_traversal.toml",
        "smuggling.toml",
        "graphql.toml",
        "ssti.toml",
        "ssrf.toml",
        "log4shell.toml",
        "prototype_pollution.toml",
        "websocket.toml",
        "benign.toml",
    ];

    for filename in expected_files {
        let file_path = payloads_dir.join(filename);
        assert!(
            file_path.exists(),
            "Expected TOML file should exist: {}",
            filename
        );

        // Verify the file can be read
        let content = std::fs::read_to_string(&file_path)
            .unwrap_or_else(|_| panic!("Should be able to read {}", filename));
        assert!(!content.is_empty(), "{} should not be empty", filename);
    }
}
