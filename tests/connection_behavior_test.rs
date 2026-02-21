//! Integration tests for connection behavior analysis

use std::collections::HashMap;
use waf_detector::timing::connection_behavior::ConnectionBehaviorAnalyzer;

#[test]
fn test_cloudflare_connection_behavior_detection() {
    let analyzer = ConnectionBehaviorAnalyzer::new();

    let mut headers = HashMap::new();
    headers.insert(
        "server-timing".to_string(),
        "cfRequestDuration;dur=45.2".to_string(),
    );
    headers.insert("alt-svc".to_string(), "h3=\":443\"; ma=86400".to_string());
    headers.insert("connection".to_string(), "keep-alive".to_string());
    headers.insert("keep-alive".to_string(), "timeout=5, max=100".to_string());

    let evidence = analyzer.analyze_response_headers(&headers);

    // Should detect CloudFlare based on server-timing and alt-svc patterns
    assert!(
        !evidence.is_empty(),
        "Should detect CloudFlare connection behavior"
    );

    let cf_evidence = evidence
        .iter()
        .find(|e| e.signature_matched == "connection-behavior-cloudflare");
    assert!(
        cf_evidence.is_some(),
        "Should have CloudFlare-specific evidence"
    );

    let ev = cf_evidence.unwrap();
    assert!(
        ev.confidence >= 0.70,
        "CloudFlare detection should have high confidence"
    );
    assert!(
        ev.description.contains("CloudFlare"),
        "Description should mention CloudFlare"
    );
}

#[test]
fn test_aws_cloudfront_via_header_detection() {
    let analyzer = ConnectionBehaviorAnalyzer::new();

    let mut headers = HashMap::new();
    headers.insert(
        "via".to_string(),
        "1.1 abc123.cloudfront.net (CloudFront)".to_string(),
    );
    headers.insert("connection".to_string(), "keep-alive".to_string());
    headers.insert("keep-alive".to_string(), "timeout=10".to_string());

    let evidence = analyzer.analyze_response_headers(&headers);

    // Should detect AWS CloudFront based on via header
    assert!(
        !evidence.is_empty(),
        "Should detect AWS CloudFront connection behavior"
    );

    let aws_evidence = evidence
        .iter()
        .find(|e| e.signature_matched == "connection-behavior-aws");
    assert!(aws_evidence.is_some(), "Should have AWS-specific evidence");

    let ev = aws_evidence.unwrap();
    assert!(
        ev.confidence >= 0.70,
        "AWS detection should have high confidence"
    );
    assert!(
        ev.description.contains("AWS"),
        "Description should mention AWS"
    );
}

#[test]
fn test_akamai_via_header_detection() {
    let analyzer = ConnectionBehaviorAnalyzer::new();

    let mut headers = HashMap::new();
    headers.insert(
        "via".to_string(),
        "1.1 akamai.net (ghost) (AkamaiGHost)".to_string(),
    );
    headers.insert("connection".to_string(), "keep-alive".to_string());

    let evidence = analyzer.analyze_response_headers(&headers);

    assert!(
        !evidence.is_empty(),
        "Should detect Akamai connection behavior"
    );

    let akamai_evidence = evidence
        .iter()
        .find(|e| e.signature_matched == "connection-behavior-akamai");
    assert!(
        akamai_evidence.is_some(),
        "Should have Akamai-specific evidence"
    );
}

#[test]
fn test_multiple_provider_patterns_in_headers() {
    let analyzer = ConnectionBehaviorAnalyzer::new();

    // Edge case: Headers that might match multiple patterns
    let mut headers = HashMap::new();
    headers.insert("via".to_string(), "1.1 cloudfront.net".to_string());
    headers.insert(
        "server-timing".to_string(),
        "cdn-upstream;dur=5".to_string(),
    );

    let evidence = analyzer.analyze_response_headers(&headers);

    // Should only match AWS due to cloudfront via header
    let aws_matches = evidence
        .iter()
        .filter(|e| e.signature_matched == "connection-behavior-aws")
        .count();
    assert_eq!(aws_matches, 1, "Should match AWS once");
}

#[test]
fn test_no_false_positives_on_generic_headers() {
    let analyzer = ConnectionBehaviorAnalyzer::new();

    let mut headers = HashMap::new();
    headers.insert("connection".to_string(), "keep-alive".to_string());
    headers.insert("keep-alive".to_string(), "timeout=5".to_string());
    headers.insert("content-type".to_string(), "text/html".to_string());

    let evidence = analyzer.analyze_response_headers(&headers);

    // Generic keep-alive patterns without distinctive signals should not match
    // or should have low confidence
    for ev in &evidence {
        assert!(
            ev.confidence < 0.70 || evidence.is_empty(),
            "Generic patterns should not produce high-confidence matches"
        );
    }
}

#[test]
fn test_azure_via_detection() {
    let analyzer = ConnectionBehaviorAnalyzer::new();

    let mut headers = HashMap::new();
    headers.insert("via".to_string(), "1.1 Azure-Edge-XYZ".to_string());
    headers.insert("connection".to_string(), "keep-alive".to_string());

    let evidence = analyzer.analyze_response_headers(&headers);

    assert!(
        !evidence.is_empty(),
        "Should detect Azure connection behavior"
    );

    let azure_evidence = evidence
        .iter()
        .find(|e| e.signature_matched == "connection-behavior-azure");
    assert!(
        azure_evidence.is_some(),
        "Should have Azure-specific evidence"
    );
}

#[test]
fn test_case_insensitive_header_names() {
    let analyzer = ConnectionBehaviorAnalyzer::new();

    let mut headers = HashMap::new();
    // Use various case combinations
    headers.insert(
        "Server-Timing".to_string(),
        "cfRequestDuration;dur=50".to_string(),
    );
    headers.insert("ALT-SVC".to_string(), "h3=\":443\"".to_string());
    headers.insert("Connection".to_string(), "keep-alive".to_string());

    let evidence = analyzer.analyze_response_headers(&headers);

    assert!(
        !evidence.is_empty(),
        "Case-insensitive matching should work"
    );

    let cf_evidence = evidence
        .iter()
        .find(|e| e.signature_matched == "connection-behavior-cloudflare");
    assert!(
        cf_evidence.is_some(),
        "Should detect CloudFlare regardless of header case"
    );
}
