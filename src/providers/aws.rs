//! AWS WAF/CloudFront Detection Provider

use crate::{DetectionProvider, DetectionContext, Evidence, ProviderType, MethodType};
use regex::Regex;
use std::sync::OnceLock;
use anyhow::Result;

/// AWS WAF/CloudFront detection provider
#[derive(Debug, Clone)]
pub struct AwsProvider {
    name: String,
    version: String,
    description: String,
    enabled: bool,
}

impl AwsProvider {
    pub fn new() -> Self {
        Self {
            name: "AWS".to_string(),
            version: "1.0.0".to_string(),
            description: "AWS WAF and CloudFront CDN detection provider".to_string(),
            enabled: true,
        }
    }

    // Pre-compiled regex patterns for performance
    fn aws_request_id_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$").unwrap())
    }

    fn cloudfront_id_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"^[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}$").unwrap())
    }

    fn cloudfront_pop_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"^[A-Z]{3}[0-9]+-[A-Z][0-9]+$").unwrap())
    }

    fn cloudfront_via_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(cloudfront|1\.1 [a-f0-9]+ \(CloudFront\))").unwrap())
    }

    fn cloudfront_cache_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)((hit|miss|refresh_hit|error|bypass)\s+(from\s+)?cloudfront|cloudfront)").unwrap())
    }

    fn cloudfront_server_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(cloudfront|amazon\s*cloudfront)").unwrap())
    }

    fn cloudfront_age_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"^\d+$").unwrap())
    }

    fn aws_error_body_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(access\s+denied|request\s+id|you\s+don't\s+have\s+permission)").unwrap())
    }

    fn aws_json_error_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r#"(?i)("__type"|"errortype"|"requestid"|"accessdenied|"throttling")"#).unwrap())
    }

    async fn check_headers(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check x-amzn-RequestId header (AWS services)
        if let Some(request_id) = response.headers.get("x-amzn-requestid") {
            if Self::aws_request_id_pattern().is_match(request_id) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-amzn-requestid".to_string()),
                    confidence: 0.85,
                    description: "AWS request ID header detected".to_string(),
                    raw_data: request_id.clone(),
                    signature_matched: "aws-request-id-pattern".to_string(),
                });
            }
        }

        // Check x-amzn-ErrorType header (AWS errors)
        if let Some(error_type) = response.headers.get("x-amzn-errortype") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-amzn-errortype".to_string()),
                confidence: 0.90,
                description: "AWS error type header detected".to_string(),
                raw_data: error_type.clone(),
                signature_matched: "aws-error-type-pattern".to_string(),
            });
        }

        // Check x-amz-cf-id header (CloudFront)
        if let Some(cf_id) = response.headers.get("x-amz-cf-id") {
            if Self::cloudfront_id_pattern().is_match(cf_id) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-amz-cf-id".to_string()),
                    confidence: 0.95,
                    description: "CloudFront request ID header detected".to_string(),
                    raw_data: cf_id.clone(),
                    signature_matched: "cloudfront-id-pattern".to_string(),
                });
            }
        }

        // Check x-amz-cf-pop header (CloudFront Point of Presence)
        if let Some(cf_pop) = response.headers.get("x-amz-cf-pop") {
            if Self::cloudfront_pop_pattern().is_match(cf_pop) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-amz-cf-pop".to_string()),
                    confidence: 0.90,
                    description: "CloudFront Point of Presence header detected".to_string(),
                    raw_data: cf_pop.clone(),
                    signature_matched: "cloudfront-pop-pattern".to_string(),
                });
            }
        }

        // Check Via header for CloudFront
        if let Some(via) = response.headers.get("via") {
            if Self::cloudfront_via_pattern().is_match(via) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("via".to_string()),
                    confidence: 0.85,
                    description: "CloudFront via header detected".to_string(),
                    raw_data: via.clone(),
                    signature_matched: "cloudfront-via-pattern".to_string(),
                });
            }
        }

        // Check x-cache header for CloudFront
        if let Some(cache) = response.headers.get("x-cache") {
            if Self::cloudfront_cache_pattern().is_match(cache) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-cache".to_string()),
                    confidence: 0.80,
                    description: "CloudFront cache header detected".to_string(),
                    raw_data: cache.clone(),
                    signature_matched: "cloudfront-cache-pattern".to_string(),
                });
            }
        }

        // Check server header for CloudFront
        if let Some(server) = response.headers.get("server") {
            if Self::cloudfront_server_pattern().is_match(server) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("server".to_string()),
                    confidence: 0.85,
                    description: "CloudFront server header detected".to_string(),
                    raw_data: server.clone(),
                    signature_matched: "cloudfront-server-pattern".to_string(),
                });
            }
        }

        // Check age header (commonly present with CloudFront)
        if let Some(age) = response.headers.get("age") {
            if Self::cloudfront_age_pattern().is_match(age) {
                // Only add moderate confidence if other CloudFront indicators are present
                let has_other_cf_indicators = response.headers.get("x-amz-cf-id").is_some() ||
                    response.headers.get("x-amz-cf-pop").is_some() ||
                    response.headers.get("via").map_or(false, |v| Self::cloudfront_via_pattern().is_match(v)) ||
                    response.headers.get("x-cache").map_or(false, |c| Self::cloudfront_cache_pattern().is_match(c));
                
                if has_other_cf_indicators {
                    evidence.push(Evidence {
                        method_type: MethodType::Header("age".to_string()),
                        confidence: 0.60,
                        description: "Age header supporting CloudFront evidence".to_string(),
                        raw_data: age.clone(),
                        signature_matched: "cloudfront-age-pattern".to_string(),
                    });
                }
            }
        }

        // Check for CloudFront distribution domain patterns
        if let Some(host) = response.headers.get("host") {
            if host.ends_with(".cloudfront.net") || host.contains("cloudfront") {
                evidence.push(Evidence {
                    method_type: MethodType::Header("host".to_string()),
                    confidence: 0.95,
                    description: "CloudFront distribution domain detected".to_string(),
                    raw_data: host.clone(),
                    signature_matched: "cloudfront-domain-pattern".to_string(),
                });
            }
        }

        // Check for CloudFront specific served-by headers (more specific patterns)
        if let Some(timing) = response.headers.get("x-served-by") {
            // Must contain CloudFront-specific indicators, not just generic "cache"
            if timing.contains("cloudfront") || 
               (timing.contains("cache") && (
                   response.headers.get("x-amz-cf-pop").is_some() ||
                   response.headers.get("x-amz-cf-id").is_some() ||
                   response.headers.get("via").map_or(false, |v| v.contains("CloudFront"))
               )) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-served-by".to_string()),
                    confidence: 0.75,
                    description: "CloudFront served-by header detected".to_string(),
                    raw_data: timing.clone(),
                    signature_matched: "cloudfront-served-by-pattern".to_string(),
                });
            }
        }

        // Check for CloudFront response timing patterns (only when CloudFront is confirmed)
        if let Some(rt) = response.headers.get("x-timer") {
            // Only match x-timer if we have other CloudFront evidence to avoid Fastly false positives
            if rt.contains("S") && (
                response.headers.get("x-amz-cf-pop").is_some() ||
                response.headers.get("x-amz-cf-id").is_some() ||
                response.headers.get("via").map_or(false, |v| v.contains("CloudFront")) ||
                response.headers.get("server").map_or(false, |s| s.contains("CloudFront"))
            ) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-timer".to_string()),
                    confidence: 0.65,
                    description: "CloudFront timing header detected".to_string(),
                    raw_data: rt.clone(),
                    signature_matched: "cloudfront-timer-pattern".to_string(),
                });
            }
        }

        // Check for CloudFront edge location headers
        if let Some(edge) = response.headers.get("x-amz-cf-pop") {
            // More flexible pattern for CloudFront PoP
            if edge.len() >= 6 && edge.chars().take(3).all(|c| c.is_ascii_alphabetic()) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-amz-cf-pop".to_string()),
                    confidence: 0.90,
                    description: "CloudFront edge location header detected".to_string(),
                    raw_data: edge.clone(),
                    signature_matched: "cloudfront-pop-flexible-pattern".to_string(),
                });
            }
        }

        // Look for any AWS-related headers with less strict patterns
        let aws_headers = [
            ("x-amz-request-id", "AWS request ID header", 0.80),
            ("x-amz-id-2", "AWS extended request ID header", 0.75),
            ("x-amz-bucket-region", "AWS S3 bucket region header", 0.75),
            ("x-amz-server-side-encryption", "AWS S3 encryption header", 0.70),
            ("x-amz-apigw-id", "AWS API Gateway ID header", 0.85),
            ("x-amzn-trace-id", "AWS X-Ray trace ID header", 0.80),
        ];

        for (header_name, description, confidence) in aws_headers {
            if let Some(value) = response.headers.get(header_name) {
                evidence.push(Evidence {
                    method_type: MethodType::Header(header_name.to_string()),
                    confidence,
                    description: description.to_string(),
                    raw_data: value.clone(),
                    signature_matched: format!("{}-pattern", header_name),
                });
            }
        }

        // Check Content-Security-Policy for CloudFront patterns
        if let Some(csp) = response.headers.get("content-security-policy") {
            if csp.contains("cloudfront.net") || csp.contains("amazonaws.com") {
                evidence.push(Evidence {
                    method_type: MethodType::Header("content-security-policy".to_string()),
                    confidence: 0.70,
                    description: "AWS/CloudFront CSP directive detected".to_string(),
                    raw_data: csp.clone(),
                    signature_matched: "aws-csp-pattern".to_string(),
                });
            }
        }

        // More aggressive CloudFront detection - look for common CDN patterns
        // that might indicate CloudFront even without explicit headers
        
        // Check for ETag patterns that are common with CloudFront
        if let Some(etag) = response.headers.get("etag") {
            // CloudFront ETags often have specific patterns
            if etag.contains("-") && etag.len() > 10 {
                let has_cf_timing = response.headers.get("age").is_some();
                let has_cache_control = response.headers.get("cache-control").is_some();
                
                if has_cf_timing && has_cache_control {
                    evidence.push(Evidence {
                        method_type: MethodType::Header("etag".to_string()),
                        confidence: 0.45,
                        description: "ETag pattern suggesting CloudFront presence".to_string(),
                        raw_data: etag.clone(),
                        signature_matched: "cloudfront-etag-pattern".to_string(),
                    });
                }
            }
        }

        // Check for cache-control patterns ONLY when we have confirmed CloudFront evidence
        if let Some(cache_control) = response.headers.get("cache-control") {
            if cache_control.contains("max-age") && response.headers.get("age").is_some() {
                // Only match if we have specific CloudFront indicators to avoid false positives
                let has_cloudfront_evidence = response.headers.get("x-amz-cf-pop").is_some() ||
                    response.headers.get("x-amz-cf-id").is_some() ||
                    response.headers.get("via").map_or(false, |v| v.contains("CloudFront")) ||
                    response.headers.get("server").map_or(false, |s| s.contains("CloudFront")) ||
                    response.headers.get("x-amzn-requestid").is_some();
                
                if has_cloudfront_evidence {
                    evidence.push(Evidence {
                        method_type: MethodType::Header("cache-control".to_string()),
                        confidence: 0.35,
                        description: "Cache-control pattern with CloudFront evidence".to_string(),
                        raw_data: cache_control.clone(),
                        signature_matched: "cloudfront-cache-pattern".to_string(),
                    });
                }
            }
        }

        // Check for CORS headers that might indicate AWS origins
        if let Some(cors) = response.headers.get("access-control-allow-origin") {
            if cors.contains("amazonaws.com") || cors.contains("cloudfront.net") {
                evidence.push(Evidence {
                    method_type: MethodType::Header("access-control-allow-origin".to_string()),
                    confidence: 0.80,
                    description: "CORS header pointing to AWS services".to_string(),
                    raw_data: cors.clone(),
                    signature_matched: "aws-cors-pattern".to_string(),
                });
            }
        }



        evidence
    }

    async fn check_body_patterns(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check for AWS WAF blocked page patterns
        if Self::aws_error_body_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("access-denied-page".to_string()),
                confidence: 0.75,
                description: "AWS access denied page pattern detected".to_string(),
                raw_data: "access-denied-detected".to_string(),
                signature_matched: "aws-error-body-pattern".to_string(),
            });
        }

        // Check for AWS JSON error responses
        if Self::aws_json_error_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("json-error-response".to_string()),
                confidence: 0.80,
                description: "AWS JSON error response detected".to_string(),
                raw_data: "json-error-detected".to_string(),
                signature_matched: "aws-json-error-pattern".to_string(),
            });
        }

        evidence
    }

    async fn check_status_codes(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        match response.status {
            403 => {
                // Check if it's an AWS 403 (has AWS headers or signatures)
                if response.headers.get("x-amzn-requestid").is_some() || 
                   response.headers.get("x-amzn-errortype").is_some() ||
                   response.headers.get("x-amz-cf-id").is_some() ||
                   Self::aws_error_body_pattern().is_match(&response.body) {
                    evidence.push(Evidence {
                        method_type: MethodType::StatusCode(403),
                        confidence: 0.75,
                        description: "AWS WAF 403 Forbidden response".to_string(),
                        raw_data: "403".to_string(),
                        signature_matched: "aws-403-pattern".to_string(),
                    });
                }
            }
            429 => {
                // AWS rate limiting
                if response.headers.get("x-amzn-requestid").is_some() || 
                   response.headers.get("x-amz-cf-id").is_some() {
                    evidence.push(Evidence {
                        method_type: MethodType::StatusCode(429),
                        confidence: 0.80,
                        description: "AWS rate limiting detected".to_string(),
                        raw_data: "429".to_string(),
                        signature_matched: "aws-429-pattern".to_string(),
                    });
                }
            }
            503 => {
                // AWS service unavailable
                if response.headers.get("x-amzn-requestid").is_some() || 
                   response.headers.get("x-amz-cf-id").is_some() {
                    evidence.push(Evidence {
                        method_type: MethodType::StatusCode(503),
                        confidence: 0.70,
                        description: "AWS service unavailable response".to_string(),
                        raw_data: "503".to_string(),
                        signature_matched: "aws-503-pattern".to_string(),
                    });
                }
            }
            _ => {}
        }

        evidence
    }

    /// Diagnostic method to analyze headers and provide detailed detection information
    pub fn diagnose_response(&self, response: &crate::http::HttpResponse) -> String {
        let mut report = String::new();
        report.push_str(&format!("=== AWS/CloudFront Diagnostic Report ===\n"));
        report.push_str(&format!("Status Code: {}\n", response.status));
        report.push_str(&format!("Total Headers: {}\n\n", response.headers.len()));
        
        // Check for all AWS-related headers
        report.push_str("=== AWS Header Analysis ===\n");
        let aws_header_patterns = [
            "x-amz", "x-amzn", "cloudfront", "amazon", "aws"
        ];
        
        let mut found_aws_headers = Vec::new();
        for (key, value) in &response.headers {
            let key_lower = key.to_lowercase();
            for pattern in aws_header_patterns {
                if key_lower.contains(pattern) {
                    found_aws_headers.push((key.clone(), value.clone()));
                    break;
                }
            }
        }
        
        if found_aws_headers.is_empty() {
            report.push_str("❌ No obvious AWS/CloudFront headers found\n\n");
        } else {
            report.push_str("✅ Found AWS-related headers:\n");
            for (key, value) in found_aws_headers {
                report.push_str(&format!("  {}: {}\n", key, value));
            }
            report.push_str("\n");
        }
        
        // Check standard CloudFront headers
        report.push_str("=== CloudFront Header Checks ===\n");
        let cf_checks = [
            ("x-amz-cf-id", "CloudFront Request ID"),
            ("x-amz-cf-pop", "CloudFront Point of Presence"),
            ("via", "Via header (often contains CloudFront)"),
            ("x-cache", "Cache status"),
            ("server", "Server header"),
            ("age", "Cache age"),
        ];
        
        for (header, description) in cf_checks {
            if let Some(value) = response.headers.get(header) {
                report.push_str(&format!("✅ {}: {} = '{}'\n", header, description, value));
            } else {
                report.push_str(&format!("❌ {}: {} = NOT FOUND\n", header, description));
            }
        }
        
        // Check Via header specifically
        if let Some(via) = response.headers.get("via") {
            report.push_str(&format!("\n=== Via Header Analysis ===\n"));
            report.push_str(&format!("Via value: '{}'\n", via));
            if Self::cloudfront_via_pattern().is_match(via) {
                report.push_str("✅ Via header matches CloudFront pattern\n");
            } else {
                report.push_str("❌ Via header does NOT match CloudFront pattern\n");
            }
        }
        
        // Check all headers for anything CloudFront-y
        report.push_str("\n=== All Headers Scan ===\n");
        let mut cloudfront_hints = Vec::new();
        for (key, value) in &response.headers {
            let combined = format!("{}: {}", key, value).to_lowercase();
            if combined.contains("cloudfront") || combined.contains("amazon") || 
               combined.contains("aws") || combined.contains("amz") {
                cloudfront_hints.push((key.clone(), value.clone()));
            }
        }
        
        if cloudfront_hints.is_empty() {
            report.push_str("❌ No CloudFront hints in any headers\n");
        } else {
            report.push_str("✅ Found potential CloudFront hints:\n");
            for (key, value) in cloudfront_hints {
                report.push_str(&format!("  {}: {}\n", key, value));
            }
        }
        
        report.push_str("\n=== All Response Headers ===\n");
        for (key, value) in &response.headers {
            report.push_str(&format!("{}: {}\n", key, value));
        }
        
        report
    }
}

#[async_trait::async_trait]
impl DetectionProvider for AwsProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn description(&self) -> Option<String> {
        Some(self.description.clone())
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Both // AWS provides both WAF and CDN (CloudFront)
    }

    fn confidence_base(&self) -> f64 {
        0.5
    }

    fn priority(&self) -> u32 {
        100 // Same priority as other providers
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    async fn detect(&self, context: &DetectionContext) -> Result<Vec<Evidence>> {
        let mut all_evidence = Vec::new();

        if let Some(response) = &context.response {
            // Check headers
            let header_evidence = self.check_headers(response).await;
            all_evidence.extend(header_evidence);

            // Check body patterns
            let body_evidence = self.check_body_patterns(response).await;
            all_evidence.extend(body_evidence);

            // Check status codes
            let status_evidence = self.check_status_codes(response).await;
            all_evidence.extend(status_evidence);
        }

        Ok(all_evidence)
    }

    async fn passive_detect(&self, response: &crate::http::HttpResponse) -> Result<Vec<Evidence>> {
        let mut all_evidence = Vec::new();
        
        // Check headers
        all_evidence.extend(self.check_headers(response).await);
        
        // Check body patterns
        all_evidence.extend(self.check_body_patterns(response).await);
        
        // Check status codes
        all_evidence.extend(self.check_status_codes(response).await);
        
        Ok(all_evidence)
    }

    async fn active_detect(&self, client: &crate::http::HttpClient, url: &str) -> Result<Vec<Evidence>> {
        let mut evidence = Vec::new();
        
        // Try to trigger AWS WAF with suspicious requests
        let test_paths = [
            "/.aws/config",
            "/admin.php",
            "/../etc/passwd",
            "/api/v1/admin/users",
        ];
        
        for path in test_paths {
            let test_url = format!("{url}{path}");
            if let Ok(response) = client.get(&test_url).await {
                if (response.status == 403 || response.status == 429) && 
                   (response.headers.get("x-amzn-requestid").is_some() || response.headers.contains_key("x-amz-cf-id")) {
                    evidence.push(Evidence {
                        method_type: MethodType::Body(format!("test-path-{path}")),
                        confidence: 0.70,
                        description: format!("AWS WAF blocked test path: {}", path),
                        raw_data: response.status.to_string(),
                        signature_matched: "aws-active-detection".to_string(),
                    });
                    break; // Don't spam the server once we detect it
                }
            }
        }
        
        Ok(evidence)
    }
}

impl Default for AwsProvider {
    fn default() -> Self {
        Self::new()
    }
} 