// tests/test_multi_provider.rs
// TDD: Multi-Provider Detection Tests

use std::collections::HashMap;
use waf_detector::{DetectionMethod, Evidence};

// New types we need to implement
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderRole {
    WAF,    // Web Application Firewall
    CDN,    // Content Delivery Network
    Origin, // Origin server
    Both,   // Both WAF and CDN
}

#[derive(Debug, Clone)]
pub struct ProviderWithRole {
    pub name: String,
    pub confidence: f64,
    pub role: ProviderRole,
}

#[derive(Debug)]
pub struct MultiProviderResult {
    pub providers: Vec<ProviderWithRole>,
    pub primary_waf: Option<ProviderWithRole>,
    pub origin: Option<ProviderWithRole>,
}

// Implementation: Detect providers with role classification
fn detect_providers_with_roles(
    evidence_map: HashMap<String, Vec<Evidence>>,
) -> MultiProviderResult {
    let mut providers = Vec::new();

    // Process each provider and classify its role
    for (name, evidence) in evidence_map.iter() {
        let confidence = calculate_confidence(evidence);
        let role = classify_provider_role(name, evidence);

        providers.push(ProviderWithRole {
            name: name.clone(),
            confidence,
            role,
        });
    }

    // Sort by confidence (highest first)
    providers.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

    // Identify primary WAF (highest confidence WAF)
    let primary_waf = providers
        .iter()
        .find(|p| matches!(p.role, ProviderRole::WAF | ProviderRole::Both))
        .cloned();

    // Identify origin (provider marked as Origin)
    let origin = providers
        .iter()
        .find(|p| p.role == ProviderRole::Origin)
        .cloned();

    MultiProviderResult {
        providers,
        primary_waf,
        origin,
    }
}

// Implementation: Classify provider role based on name and evidence
fn classify_provider_role(provider_name: &str, evidence: &[Evidence]) -> ProviderRole {
    // First check provider name for known roles
    let name_lower = provider_name.to_lowercase();

    // Known WAF providers
    if name_lower.contains("akamai")
        || name_lower.contains("imperva")
        || name_lower.contains("f5")
        || name_lower.contains("fortiweb")
        || name_lower == "aws waf"
    {
        return ProviderRole::WAF;
    }

    // Known Both providers (WAF + CDN)
    if name_lower.contains("cloudflare") || name_lower.contains("fastly") {
        return ProviderRole::Both;
    }

    // Known Origin providers
    if name_lower == "aws"
        || name_lower.contains("azure")
        || name_lower.contains("gcp")
        || name_lower.contains("google cloud")
    {
        return ProviderRole::Origin;
    }

    // If no name match, classify by evidence behavior
    for ev in evidence {
        match &ev.method_type {
            // Blocking behavior indicates WAF
            DetectionMethod::StatusCode(code) if *code == 403 || *code == 406 => {
                return ProviderRole::WAF;
            }

            // Payload blocking indicates WAF
            DetectionMethod::Payload if ev.description.to_lowercase().contains("block") => {
                return ProviderRole::WAF;
            }

            // Server-specific headers indicate Origin
            DetectionMethod::Header(name)
                if name.starts_with("x-amz-")
                    || name.starts_with("x-ms-")
                    || name == "x-powered-by" =>
            {
                return ProviderRole::Origin;
            }

            // Cache headers indicate CDN
            DetectionMethod::Header(name)
                if name.contains("cache") || name.contains("cf-cache") =>
            {
                return ProviderRole::CDN;
            }

            _ => {}
        }
    }

    // Default: WAF if we can't determine
    ProviderRole::WAF
}

// Helper: Calculate confidence from evidence
fn calculate_confidence(evidence: &[Evidence]) -> f64 {
    if evidence.is_empty() {
        return 0.0;
    }

    // Average confidence across all evidence
    let sum: f64 = evidence.iter().map(|e| e.confidence).sum();
    sum / evidence.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test 1: Adobe scenario - Akamai WAF + AWS Origin
    #[test]
    fn test_adobe_akamai_waf_aws_origin() {
        // ARRANGE
        let mut evidence_map = HashMap::new();

        // Akamai WAF evidence
        evidence_map.insert(
            "Akamai".to_string(),
            vec![Evidence {
                method_type: DetectionMethod::Header("akamai-grn".to_string()),
                confidence: 0.9,
                description: "Akamai GRN header".to_string(),
                raw_data: "0.85d02e17.1759886344.c1909522".to_string(),
                signature_matched: "akamai-grn".to_string(),
            }],
        );

        // AWS Origin evidence
        evidence_map.insert(
            "AWS".to_string(),
            vec![Evidence {
                method_type: DetectionMethod::Header("x-amz-server-side-encryption".to_string()),
                confidence: 0.7,
                description: "AWS S3 encryption header".to_string(),
                raw_data: "AES256".to_string(),
                signature_matched: "aws-s3".to_string(),
            }],
        );

        // ACT
        let result = detect_providers_with_roles(evidence_map);

        // ASSERT
        assert_eq!(result.providers.len(), 2, "Should detect both providers");

        // Find Akamai
        let akamai = result.providers.iter().find(|p| p.name == "Akamai");
        assert!(akamai.is_some(), "Should detect Akamai");
        assert_eq!(
            akamai.unwrap().role,
            ProviderRole::WAF,
            "Akamai should be WAF"
        );

        // Find AWS
        let aws = result.providers.iter().find(|p| p.name == "AWS");
        assert!(aws.is_some(), "Should detect AWS");
        assert_eq!(
            aws.unwrap().role,
            ProviderRole::Origin,
            "AWS should be Origin"
        );

        // Primary WAF should be Akamai
        assert!(result.primary_waf.is_some(), "Should have primary WAF");
        assert_eq!(result.primary_waf.unwrap().name, "Akamai");

        // Origin should be AWS
        assert!(result.origin.is_some(), "Should have origin");
        assert_eq!(result.origin.unwrap().name, "AWS");
    }

    /// Test 2: CloudFlare as both WAF and CDN
    #[test]
    fn test_cloudflare_both_roles() {
        // ARRANGE
        let mut evidence_map = HashMap::new();

        evidence_map.insert(
            "CloudFlare".to_string(),
            vec![Evidence {
                method_type: DetectionMethod::Header("cf-ray".to_string()),
                confidence: 0.95,
                description: "CloudFlare Ray ID".to_string(),
                raw_data: "abc123-SJC".to_string(),
                signature_matched: "cf-ray".to_string(),
            }],
        );

        // ACT
        let result = detect_providers_with_roles(evidence_map);

        // ASSERT
        assert_eq!(result.providers.len(), 1);
        let cf = &result.providers[0];
        assert_eq!(cf.name, "CloudFlare");
        assert_eq!(
            cf.role,
            ProviderRole::Both,
            "CloudFlare should have Both role"
        );
    }

    /// Test 3: Role classification by provider name
    #[test]
    fn test_role_classification_by_name() {
        let evidence = vec![];

        // Known WAF providers
        assert_eq!(
            classify_provider_role("Akamai", &evidence),
            ProviderRole::WAF
        );
        assert_eq!(
            classify_provider_role("Imperva", &evidence),
            ProviderRole::WAF
        );

        // Known Both providers
        assert_eq!(
            classify_provider_role("CloudFlare", &evidence),
            ProviderRole::Both
        );
        assert_eq!(
            classify_provider_role("Cloudflare", &evidence),
            ProviderRole::Both
        );

        // Known Origin providers
        assert_eq!(
            classify_provider_role("AWS", &evidence),
            ProviderRole::Origin
        );
        assert_eq!(
            classify_provider_role("Azure", &evidence),
            ProviderRole::Origin
        );
    }

    /// Test 4: Role classification by evidence type
    #[test]
    fn test_role_classification_by_evidence() {
        // WAF-like evidence (blocking behavior)
        let waf_evidence = vec![Evidence {
            method_type: DetectionMethod::StatusCode(403),
            confidence: 0.9,
            description: "Blocked request".to_string(),
            raw_data: "Access Denied".to_string(),
            signature_matched: "waf-block".to_string(),
        }];

        let role = classify_provider_role("Unknown", &waf_evidence);
        assert_eq!(role, ProviderRole::WAF, "Blocking behavior indicates WAF");

        // Origin-like evidence (server headers)
        let origin_evidence = vec![Evidence {
            method_type: DetectionMethod::Header("x-powered-by".to_string()),
            confidence: 0.7,
            description: "Server technology header".to_string(),
            raw_data: "Express".to_string(),
            signature_matched: "origin-tech".to_string(),
        }];

        let role = classify_provider_role("Unknown", &origin_evidence);
        assert_eq!(role, ProviderRole::Origin, "Server headers indicate Origin");
    }

    /// Test 5: Multiple providers ordered by role priority
    #[test]
    fn test_provider_ordering() {
        // ARRANGE: 3 providers - WAF, CDN, Origin
        let mut evidence_map = HashMap::new();

        evidence_map.insert(
            "Akamai".to_string(),
            vec![Evidence {
                method_type: DetectionMethod::Header("akamai-grn".to_string()),
                confidence: 0.9,
                description: "WAF".to_string(),
                raw_data: "xyz".to_string(),
                signature_matched: "akamai".to_string(),
            }],
        );

        evidence_map.insert(
            "CloudFlare".to_string(),
            vec![Evidence {
                method_type: DetectionMethod::Header("cf-cache".to_string()),
                confidence: 0.8,
                description: "CDN".to_string(),
                raw_data: "HIT".to_string(),
                signature_matched: "cf-cache".to_string(),
            }],
        );

        evidence_map.insert(
            "AWS".to_string(),
            vec![Evidence {
                method_type: DetectionMethod::Header("x-amz-id".to_string()),
                confidence: 0.7,
                description: "Origin".to_string(),
                raw_data: "abc".to_string(),
                signature_matched: "aws".to_string(),
            }],
        );

        // ACT
        let result = detect_providers_with_roles(evidence_map);

        // ASSERT: Should have clear WAF and Origin
        assert!(result.primary_waf.is_some(), "Should identify primary WAF");
        assert!(result.origin.is_some(), "Should identify origin");

        // WAF should be highest confidence WAF
        let waf = result.primary_waf.unwrap();
        assert_eq!(waf.name, "Akamai", "Akamai should be primary WAF");

        // Origin should be identified
        let origin = result.origin.unwrap();
        assert_eq!(origin.name, "AWS", "AWS should be origin");
    }
}
