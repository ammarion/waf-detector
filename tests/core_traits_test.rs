use waf_detector::*;

#[tokio::test]
async fn test_detection_provider_interface() {
    // This test will fail initially - that's expected in TDD!
    let provider = MockProvider::new();
    let context = DetectionContext::default();
    
    let _evidence = provider.detect(&context).await.unwrap();
    
    assert_eq!(provider.name(), "MockProvider");
    assert_eq!(provider.provider_type(), ProviderType::WAF);
    assert!(provider.confidence_base() > 0.0);
    assert!(provider.confidence_base() <= 1.0);
}

#[tokio::test] 
async fn test_evidence_structure() {
    let evidence = Evidence {
        method_type: DetectionMethod::Header("server".to_string()),
        confidence: 0.9,
        description: "Test evidence".to_string(),
        raw_data: Some("nginx".to_string()),
        signature_matched: "server-pattern".to_string(),
    };
    
    assert_eq!(evidence.confidence, 0.9);
    assert_eq!(evidence.description, "Test evidence");
    assert_eq!(evidence.raw_data, Some("nginx".to_string()));
    
    match evidence.method_type {
        DetectionMethod::Header(ref header) => assert_eq!(header, "server"),
        _ => panic!("Expected Header detection method"),
    }
}

#[test]
fn test_provider_type_variants() {
    assert_eq!(ProviderType::WAF, ProviderType::WAF);
    assert_eq!(ProviderType::CDN, ProviderType::CDN);
    assert_eq!(ProviderType::Both, ProviderType::Both);
    assert_ne!(ProviderType::WAF, ProviderType::CDN);
}

#[test]
fn test_detection_method_variants() {
    let header_method = DetectionMethod::Header("cf-ray".to_string());
    let body_method = DetectionMethod::BodyPattern;
    let status_method = DetectionMethod::StatusCode(403);
    
    assert_ne!(header_method, body_method);
    
    match header_method {
        DetectionMethod::Header(ref h) => assert_eq!(h, "cf-ray"),
        _ => panic!("Expected Header variant"),
    }
    
    match status_method {
        DetectionMethod::StatusCode(code) => assert_eq!(code, 403),
        _ => panic!("Expected StatusCode variant"),
    }
}

// Mock provider for testing
struct MockProvider;

impl MockProvider {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl DetectionProvider for MockProvider {
    fn name(&self) -> &str { "MockProvider" }
    fn provider_type(&self) -> ProviderType { ProviderType::WAF }
    fn confidence_base(&self) -> f64 { 0.8 }
    
    async fn detect(&self, _context: &DetectionContext) -> anyhow::Result<Vec<Evidence>> {
        Ok(vec![])
    }
} 