use waf_detector::*;
use std::collections::HashMap;

#[tokio::test]
async fn test_cloudflare_detection_integration() {
    // Create a mock HTTP response that looks like CloudFlare
    let mut headers = HashMap::new();
    headers.insert("cf-ray".to_string(), "1234567890abcdef-DFW".to_string());
    headers.insert("server".to_string(), "cloudflare".to_string());
    
    let response = http::HttpResponse {
        status: 200,
        headers,
        body: "<!DOCTYPE html><html>".to_string(),
        url: "https://example.com".to_string(),
    };
    
    // Test CloudFlare provider directly
    let provider = providers::cloudflare::CloudFlareProvider::new();
    
    assert_eq!(provider.name(), "CloudFlare");
    assert_eq!(provider.provider_type(), ProviderType::Both);
    assert_eq!(provider.confidence_base(), 0.95);
}

#[tokio::test]
async fn test_confidence_engine() {
    let engine = confidence::ConfidenceEngine::new();
    
    let evidence = vec![
        Evidence {
            method_type: DetectionMethod::Header("cf-ray".to_string()),
            confidence: 0.95,
            description: "CloudFlare Ray ID header detected".to_string(),
            raw_data: "1234567890abcdef-DFW".to_string(),
            signature_matched: "cf-ray-pattern".to_string(),
        },
    ];
    
    let confidence = engine.calculate_confidence("CloudFlare", evidence.len(), 0.95);
    assert!(confidence > 0.8);
    assert!(confidence <= 1.0);
}

#[tokio::test]
async fn test_provider_registry() {
    let mut registry = registry::ProviderRegistry::new();
    
    let provider = providers::Provider::CloudFlare(providers::cloudflare::CloudFlareProvider::new());
    
    let result = registry.register_provider(provider);
    assert!(result.is_ok());
    
    let providers = registry.list_providers();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].name, "CloudFlare");
}

#[test]
fn test_detection_types() {
    // Test our core types work correctly
    let evidence = Evidence {
        method_type: DetectionMethod::Header("test".to_string()),
        confidence: 0.9,
        description: "Test evidence".to_string(),
        raw_data: "test-data".to_string(),
        signature_matched: "test-pattern".to_string(),
    };
    
    assert_eq!(evidence.confidence, 0.9);
    assert_eq!(evidence.description, "Test evidence");
    
    match evidence.method_type {
        DetectionMethod::Header(ref name) => assert_eq!(name, "test"),
        _ => panic!("Expected Header detection method"),
    }
}

#[tokio::test]
async fn test_http_client() {
    let client = http::HttpClient::new();
    assert!(client.is_ok());
    
    // Test HTTP response structure
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/html".to_string());
    
    let response = http::HttpResponse {
        status: 200,
        headers,
        body: "<html></html>".to_string(),
        url: "https://example.com".to_string(),
    };
    
    assert_eq!(response.status, 200);
    assert_eq!(response.url, "https://example.com");
    assert!(response.headers.contains_key("content-type"));
} 