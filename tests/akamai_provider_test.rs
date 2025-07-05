use waf_detector::*;
use std::collections::HashMap;

#[tokio::test]
async fn test_akamai_provider_creation() {
    let provider = providers::akamai::AkamaiProvider::new();
    
    assert_eq!(provider.name(), "Akamai");
    assert_eq!(provider.provider_type(), ProviderType::Both);
    assert_eq!(provider.confidence_base(), 0.92);
}

#[tokio::test]
async fn test_akamai_server_header_detection() {
    let provider = providers::akamai::AkamaiProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("server".to_string(), "AkamaiGHost".to_string());
    
    let response = http::HttpResponse {
        status: 200,
        headers,
        body: String::new(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.check_headers(&response).await;
    
    assert!(!evidence.is_empty());
    assert_eq!(evidence[0].confidence, 0.95);
    assert!(evidence[0].description.contains("Akamai server header"));
    assert_eq!(evidence[0].method_type, MethodType::Header("server".to_string()));
}

#[tokio::test]
async fn test_akamai_x_cache_header_detection() {
    let provider = providers::akamai::AkamaiProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("x-cache".to_string(), "TCP_HIT from a23-45-67-89.deploy.akamaitechnologies.com".to_string());
    headers.insert("x-cache-remote".to_string(), "TCP_HIT from a12-34-56-78.deploy.akamaitechnologies.com".to_string());
    
    let response = http::HttpResponse {
        status: 200,
        headers,
        body: String::new(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.check_headers(&response).await;
    
    assert!(!evidence.is_empty());
    // Should find both X-Cache and X-Cache-Remote
    assert!(evidence.len() >= 2);
    
    let x_cache_evidence = evidence.iter().find(|e| e.description.contains("x-cache")).unwrap();
    assert!(x_cache_evidence.confidence >= 0.9);
}

#[tokio::test]
async fn test_akamai_reference_header_detection() {
    let provider = providers::akamai::AkamaiProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("x-akamai-request-id".to_string(), "1a2b3c4d".to_string());
    headers.insert("x-akamai-session-info".to_string(), "name=AKA_PM_TD_FD_CACHE; value=hit".to_string());
    
    let response = http::HttpResponse {
        status: 200,
        headers,
        body: String::new(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.check_headers(&response).await;
    
    assert!(!evidence.is_empty());
    assert!(evidence.iter().any(|e| e.description.contains("x-akamai-request-id")));
    assert!(evidence.iter().any(|e| e.description.contains("x-akamai-session-info")));
}

#[tokio::test]
async fn test_akamai_error_page_detection() {
    let provider = providers::akamai::AkamaiProvider::new();
    
    let response = http::HttpResponse {
        status: 403,
        headers: HashMap::new(),
        body: r#"
            <HTML><HEAD><TITLE>Access Denied</TITLE></HEAD>
            <BODY>
            <H1>Access Denied</H1>
            You don't have permission to access this resource.
            <HR>
            <ADDRESS>Reference #18.1234abcd.1234567890.abcdef12</ADDRESS>
            </BODY></HTML>
        "#.to_string(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.check_body_patterns(&response).await;
    
    assert!(!evidence.is_empty());
    assert!(evidence[0].confidence >= 0.85);
    assert!(evidence.iter().any(|e| e.description.contains("Akamai reference ID") || e.description.contains("Akamai access denied")));
}

#[tokio::test]
async fn test_akamai_reference_id_pattern() {
    let provider = providers::akamai::AkamaiProvider::new();
    
    let response = http::HttpResponse {
        status: 403,
        headers: HashMap::new(),
        body: "Reference #18.7f123456.1703123456.2a3b4c5d - Access denied".to_string(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.check_body_patterns(&response).await;
    
    assert!(!evidence.is_empty());
    assert!(evidence[0].confidence >= 0.9);
    assert!(evidence[0].description.contains("Akamai reference ID"));
}

#[tokio::test]
async fn test_akamai_multiple_detection_methods() {
    let provider = providers::akamai::AkamaiProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("server".to_string(), "AkamaiGHost".to_string());
    headers.insert("x-cache".to_string(), "TCP_HIT from a23-45-67-89.deploy.akamaitechnologies.com".to_string());
    
    let response = http::HttpResponse {
        status: 200,
        headers,
        body: String::new(),
        url: "https://example.com".to_string(),
    };
    
    let header_evidence = provider.check_headers(&response).await;
    let body_evidence = provider.check_body_patterns(&response).await;
    let status_evidence = provider.check_status_codes(&response).await;
    
    // Should have multiple pieces of evidence from headers
    assert!(header_evidence.len() >= 2);
    
    // Combine all evidence
    let mut all_evidence = Vec::new();
    all_evidence.extend(header_evidence);
    all_evidence.extend(body_evidence);
    all_evidence.extend(status_evidence);
    
    assert!(!all_evidence.is_empty());
}

#[tokio::test]
async fn test_akamai_no_false_positives() {
    let provider = providers::akamai::AkamaiProvider::new();
    
    // Test with non-Akamai response
    let mut headers = HashMap::new();
    headers.insert("server".to_string(), "nginx".to_string());
    headers.insert("x-powered-by".to_string(), "PHP".to_string());
    
    let response = http::HttpResponse {
        status: 200,
        headers,
        body: "Regular website content".to_string(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.check_headers(&response).await;
    
    // Should not detect Akamai
    assert!(evidence.is_empty());
}

#[test]
fn test_akamai_regex_patterns() {
    // Test the regex patterns directly
    use regex::Regex;
    
    // Test Akamai server pattern
    let server_pattern = Regex::new(r"(?i)akamai").unwrap();
    assert!(server_pattern.is_match("AkamaiGHost"));
    assert!(server_pattern.is_match("akamai-server"));
    assert!(!server_pattern.is_match("nginx"));
    
    // Test Akamai cache pattern
    let cache_pattern = Regex::new(r"(?i)\.akamaitechnologies\.com").unwrap();
    assert!(cache_pattern.is_match("a23-45-67-89.deploy.akamaitechnologies.com"));
    assert!(!cache_pattern.is_match("cloudflare.com"));
    
    // Test reference ID pattern
    let ref_pattern = Regex::new(r"Reference #\d+\.[a-f0-9]+\.\d+\.[a-f0-9]+").unwrap();
    assert!(ref_pattern.is_match("Reference #18.7f123456.1703123456.2a3b4c5d"));
    assert!(!ref_pattern.is_match("CloudFlare Ray ID: 123"));
} 