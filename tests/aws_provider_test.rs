//! AWS WAF/CloudFront Detection Provider Tests

use waf_detector::{
    providers::aws::AwsProvider, 
    DetectionProvider, 
    DetectionContext, 
    http::{HttpResponse, HttpClient}, 
    MethodType,
    ProviderType
};
use std::collections::HashMap;

#[tokio::test]
async fn test_aws_provider_basic_metadata() {
    let provider = AwsProvider::new();
    
    assert_eq!(provider.name(), "AWS");
    assert_eq!(provider.version(), "1.0.0");
    assert!(provider.description().is_some());
    assert_eq!(provider.provider_type(), ProviderType::Both); // AWS provides both WAF and CDN
    assert!(provider.enabled());
    assert_eq!(provider.priority(), 100);
    assert!(provider.confidence_base() > 0.0);
}

#[tokio::test]
async fn test_aws_waf_request_id_header_detection() {
    let provider = AwsProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("x-amzn-requestid".to_string(), "1234abcd-12ab-34cd-56ef-1234567890ab".to_string());
    
    let response = HttpResponse {
        status: 200,
        headers,
        body: "".to_string(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.passive_detect(&response).await.unwrap();
    
    assert!(!evidence.is_empty());
    let request_id_evidence = evidence.iter()
        .find(|e| matches!(e.method_type, MethodType::Header(ref h) if h == "x-amzn-requestid"))
        .expect("Should find x-amzn-requestid evidence");
    
    assert!(request_id_evidence.confidence >= 0.85);
    assert!(request_id_evidence.description.contains("AWS"));
    assert!(request_id_evidence.description.contains("request"));
}

#[tokio::test]
async fn test_aws_error_type_header_detection() {
    let provider = AwsProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("x-amzn-errortype".to_string(), "AccessDeniedException".to_string());
    
    let response = HttpResponse {
        status: 403,
        headers,
        body: "".to_string(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.passive_detect(&response).await.unwrap();
    
    assert!(!evidence.is_empty());
    let error_evidence = evidence.iter()
        .find(|e| matches!(e.method_type, MethodType::Header(ref h) if h == "x-amzn-errortype"))
        .expect("Should find x-amzn-errortype evidence");
    
    assert!(error_evidence.confidence >= 0.90);
    assert!(error_evidence.description.contains("AWS"));
    assert!(error_evidence.description.contains("error"));
}

#[tokio::test]
async fn test_cloudfront_id_header_detection() {
    let provider = AwsProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("x-amz-cf-id".to_string(), "abcd1234-EFGH-5678-IJKL-9012mnopqrst".to_string());
    
    let response = HttpResponse {
        status: 200,
        headers,
        body: "".to_string(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.passive_detect(&response).await.unwrap();
    
    assert!(!evidence.is_empty());
    let cf_evidence = evidence.iter()
        .find(|e| matches!(e.method_type, MethodType::Header(ref h) if h == "x-amz-cf-id"))
        .expect("Should find x-amz-cf-id evidence");
    
    assert!(cf_evidence.confidence >= 0.95);
    assert!(cf_evidence.description.contains("CloudFront"));
}

#[tokio::test]
async fn test_cloudfront_pop_header_detection() {
    let provider = AwsProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("x-amz-cf-pop".to_string(), "DFW3-C1".to_string());
    
    let response = HttpResponse {
        status: 200,
        headers,
        body: "".to_string(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.passive_detect(&response).await.unwrap();
    
    assert!(!evidence.is_empty());
    let pop_evidence = evidence.iter()
        .find(|e| matches!(e.method_type, MethodType::Header(ref h) if h == "x-amz-cf-pop"))
        .expect("Should find x-amz-cf-pop evidence");
    
    assert!(pop_evidence.confidence >= 0.90);
    assert!(pop_evidence.description.contains("CloudFront"));
    assert!(pop_evidence.description.contains("Point of Presence"));
}

#[tokio::test]
async fn test_cloudfront_via_header_detection() {
    let provider = AwsProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("via".to_string(), "1.1 abcd1234.cloudfront.net (CloudFront)".to_string());
    
    let response = HttpResponse {
        status: 200,
        headers,
        body: "".to_string(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.passive_detect(&response).await.unwrap();
    
    assert!(!evidence.is_empty());
    let via_evidence = evidence.iter()
        .find(|e| matches!(e.method_type, MethodType::Header(ref h) if h == "via"))
        .expect("Should find via evidence");
    
    assert!(via_evidence.confidence >= 0.85);
    assert!(via_evidence.description.contains("CloudFront"));
}

#[tokio::test]
async fn test_cloudfront_cache_header_detection() {
    let provider = AwsProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("x-cache".to_string(), "Hit from cloudfront".to_string());
    
    let response = HttpResponse {
        status: 200,
        headers,
        body: "".to_string(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.passive_detect(&response).await.unwrap();
    
    assert!(!evidence.is_empty());
    let cache_evidence = evidence.iter()
        .find(|e| matches!(e.method_type, MethodType::Header(ref h) if h == "x-cache"))
        .expect("Should find x-cache evidence");
    
    assert!(cache_evidence.confidence >= 0.80);
    assert!(cache_evidence.description.contains("CloudFront"));
    assert!(cache_evidence.description.contains("cache"));
}

#[tokio::test]
async fn test_aws_waf_blocked_page_body_detection() {
    let provider = AwsProvider::new();
    
    let headers = HashMap::new();
    let body = r#"
        <html>
        <head><title>Access Denied</title></head>
        <body>
        <h1>Access Denied</h1>
        <p>You don't have permission to access this resource.</p>
        <p>Request ID: 1234abcd-12ab-34cd-56ef-1234567890ab</p>
        </body>
        </html>
    "#.to_string();
    
    let response = HttpResponse {
        status: 403,
        headers,
        body,
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.passive_detect(&response).await.unwrap();
    
    assert!(!evidence.is_empty());
    let body_evidence = evidence.iter()
        .find(|e| matches!(e.method_type, MethodType::Body(_)))
        .expect("Should find body evidence");
    
    assert!(body_evidence.confidence >= 0.75);
    assert!(body_evidence.description.contains("AWS"));
}

#[tokio::test]
async fn test_aws_waf_json_error_body_detection() {
    let provider = AwsProvider::new();
    
    let headers = HashMap::new();
    let body = r#"
        {
            "__type": "AccessDeniedException",
            "message": "User is not authorized to perform this action",
            "requestId": "1234abcd-12ab-34cd-56ef-1234567890ab"
        }
    "#.to_string();
    
    let response = HttpResponse {
        status: 403,
        headers,
        body,
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.passive_detect(&response).await.unwrap();
    
    assert!(!evidence.is_empty());
    let json_evidence = evidence.iter()
        .find(|e| matches!(e.method_type, MethodType::Body(_)))
        .expect("Should find JSON error evidence");
    
    assert!(json_evidence.confidence >= 0.80);
    assert!(json_evidence.description.contains("AWS"));
    assert!(json_evidence.description.contains("JSON"));
}

#[tokio::test]
async fn test_aws_waf_403_status_with_signatures() {
    let provider = AwsProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("x-amzn-requestid".to_string(), "1234abcd-12ab-34cd-56ef-1234567890ab".to_string());
    
    let response = HttpResponse {
        status: 403,
        headers,
        body: "Access Denied".to_string(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.passive_detect(&response).await.unwrap();
    
    assert!(!evidence.is_empty());
    let status_evidence = evidence.iter()
        .find(|e| matches!(e.method_type, MethodType::StatusCode(403)))
        .expect("Should find 403 status evidence");
    
    assert!(status_evidence.confidence >= 0.75);
    assert!(status_evidence.description.contains("AWS"));
    assert!(status_evidence.description.contains("403"));
}

#[tokio::test]
async fn test_aws_waf_429_rate_limit_detection() {
    let provider = AwsProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("x-amzn-requestid".to_string(), "1234abcd-12ab-34cd-56ef-1234567890ab".to_string());
    
    let response = HttpResponse {
        status: 429,
        headers,
        body: "Too Many Requests".to_string(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.passive_detect(&response).await.unwrap();
    
    assert!(!evidence.is_empty());
    let rate_limit_evidence = evidence.iter()
        .find(|e| matches!(e.method_type, MethodType::StatusCode(429)))
        .expect("Should find 429 rate limit evidence");
    
    assert!(rate_limit_evidence.confidence >= 0.80);
    assert!(rate_limit_evidence.description.contains("AWS"));
    assert!(rate_limit_evidence.description.contains("rate"));
}

#[tokio::test]
async fn test_multiple_aws_headers_combined_confidence() {
    let provider = AwsProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("x-amzn-requestid".to_string(), "1234abcd-12ab-34cd-56ef-1234567890ab".to_string());
    headers.insert("x-amz-cf-id".to_string(), "abcd1234-EFGH-5678-IJKL-9012mnopqrst".to_string());
    headers.insert("x-amz-cf-pop".to_string(), "DFW3-C1".to_string());
    headers.insert("via".to_string(), "1.1 abcd1234.cloudfront.net (CloudFront)".to_string());
    
    let response = HttpResponse {
        status: 200,
        headers,
        body: "".to_string(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.passive_detect(&response).await.unwrap();
    
    // Should have multiple pieces of evidence
    assert!(evidence.len() >= 4);
    
    // Should have evidence for each header
    assert!(evidence.iter().any(|e| matches!(e.method_type, MethodType::Header(ref h) if h == "x-amzn-requestid")));
    assert!(evidence.iter().any(|e| matches!(e.method_type, MethodType::Header(ref h) if h == "x-amz-cf-id")));
    assert!(evidence.iter().any(|e| matches!(e.method_type, MethodType::Header(ref h) if h == "x-amz-cf-pop")));
    assert!(evidence.iter().any(|e| matches!(e.method_type, MethodType::Header(ref h) if h == "via")));
}

#[tokio::test]
async fn test_no_false_positives_for_non_aws() {
    let provider = AwsProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("server".to_string(), "nginx/1.18.0".to_string());
    headers.insert("x-powered-by".to_string(), "Express".to_string());
    
    let response = HttpResponse {
        status: 200,
        headers,
        body: "Hello World".to_string(),
        url: "https://example.com".to_string(),
    };
    
    let evidence = provider.passive_detect(&response).await.unwrap();
    
    // Should have no evidence for non-AWS response
    assert!(evidence.is_empty());
}

#[tokio::test]
async fn test_aws_provider_integration_with_detection_context() {
    let provider = AwsProvider::new();
    
    let mut headers = HashMap::new();
    headers.insert("x-amzn-requestid".to_string(), "1234abcd-12ab-34cd-56ef-1234567890ab".to_string());
    
    let response = HttpResponse {
        status: 200,
        headers,
        body: "".to_string(),
        url: "https://example.com".to_string(),
    };
    
    let context = DetectionContext {
        url: "https://example.com".to_string(),
        response: Some(response),
        dns_info: None,
        user_agent: "waf-detector/1.0".to_string(),
    };
    
    // This tests the full detection flow
    let result = provider.detect(&context).await;
    assert!(result.is_ok());
    
    let evidence = result.unwrap();
    assert!(!evidence.is_empty());
} 