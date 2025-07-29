//! F5 BIG-IP and related products detection provider

use crate::{
    http::{HttpClient, HttpResponse},
    DetectionContext, DetectionProvider, Evidence, MethodType, ProviderType,
};
use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use std::sync::OnceLock;

/// F5 BIG-IP WAF and Load Balancer provider implementation
#[derive(Debug, Clone)]
pub struct F5Provider {
    enabled: bool,
}

impl F5Provider {
    pub fn new() -> Self {
        Self { enabled: true }
    }

    // Pre-compiled regex patterns for performance
    fn f5_server_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(bigip|big-?ip|f5)").unwrap())
    }

    fn f5_cookie_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(bigip|f5|ts[0-9a-f]{8}|tsla[0-9a-f]+)").unwrap())
    }

    fn f5_block_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(the requested url was rejected|please consult with your administrator|your support id is|f5 site error)").unwrap())
    }

    fn f5_asm_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(application security manager|asm.*violation|support\s+id\s*[:=]\s*[0-9]{10,})").unwrap())
    }

    #[allow(dead_code)]
    fn f5_persistence_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"^[0-9]+\.[0-9]+\.[0-9a-f]+$").unwrap())
    }
}

impl Default for F5Provider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DetectionProvider for F5Provider {
    fn name(&self) -> &str {
        "F5"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> Option<String> {
        Some("Detects F5 BIG-IP, ASM, and related products".to_string())
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Both
    }

    fn confidence_base(&self) -> f64 {
        0.95
    }

    fn priority(&self) -> u32 {
        85
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    async fn detect(&self, context: &DetectionContext) -> Result<Vec<Evidence>> {
        let mut evidence = Vec::new();

        // Passive detection from HTTP response
        if let Some(response) = &context.response {
            evidence.extend(self.passive_detect(response).await?);
        }

        Ok(evidence)
    }

    async fn passive_detect(&self, response: &HttpResponse) -> Result<Vec<Evidence>> {
        let mut evidence = Vec::new();

        // Check headers
        evidence.extend(self.check_headers(response).await);

        // Check cookies
        evidence.extend(self.check_cookies(response).await);

        // Check body patterns
        evidence.extend(self.check_body(response).await);

        Ok(evidence)
    }

    async fn active_detect(&self, client: &HttpClient, url: &str) -> Result<Vec<Evidence>> {
        let mut evidence = Vec::new();

        // Test with payloads that might trigger F5 ASM
        let test_payloads = vec![
            ("SQL Injection", "' OR '1'='1"),
            ("XSS", "<script>alert(1)</script>"),
            ("Path Traversal", "../../../../etc/passwd"),
        ];

        for (description, payload) in test_payloads {
            let test_url = format!("{}?test={}", url, urlencoding::encode(payload));
            match client.get(&test_url).await {
                Ok(response) => {
                    // Check for F5 blocking response
                    if (response.status == 403 || response.status == 406)
                        && (Self::f5_block_pattern().is_match(&response.body)
                            || Self::f5_asm_pattern().is_match(&response.body))
                    {
                        evidence.push(Evidence {
                            method_type: MethodType::StatusCode(response.status),
                            confidence: 0.90,
                            description: format!("F5 ASM blocked {description} attempt"),
                            raw_data: format!("Status: {}", response.status),
                            signature_matched: "f5-asm-block-behavior".to_string(),
                        });
                    }
                }
                Err(_) => {
                    // Connection errors might indicate aggressive blocking
                }
            }
        }

        Ok(evidence)
    }
}

impl F5Provider {
    async fn check_headers(&self, response: &HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check Server header for F5 patterns
        if let Some(value) = response.headers.get("server") {
            if Self::f5_server_pattern().is_match(value) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("server".to_string()),
                    confidence: 0.85,
                    description: "F5 server header detected".to_string(),
                    raw_data: value.clone(),
                    signature_matched: "f5-server-pattern".to_string(),
                });
            }
        }

        // Check X-WA-Info header (F5 specific)
        if let Some(value) = response.headers.get("x-wa-info") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-wa-info".to_string()),
                confidence: 0.95,
                description: "F5 X-WA-Info header detected".to_string(),
                raw_data: value.clone(),
                signature_matched: "x-wa-info-header".to_string(),
            });
        }

        // Check X-Cnection header (F5 specific typo)
        if response.headers.contains_key("x-cnection") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-cnection".to_string()),
                confidence: 0.90,
                description: "F5 X-Cnection header detected (F5-specific typo)".to_string(),
                raw_data: response
                    .headers
                    .get("x-cnection")
                    .unwrap_or(&String::new())
                    .clone(),
                signature_matched: "x-cnection-header".to_string(),
            });
        }

        // Check for F5-specific Via header patterns
        if let Some(value) = response.headers.get("via") {
            if value.contains("BIG-IP") || value.contains("F5") {
                evidence.push(Evidence {
                    method_type: MethodType::Header("via".to_string()),
                    confidence: 0.85,
                    description: "F5 BIG-IP Via header detected".to_string(),
                    raw_data: value.clone(),
                    signature_matched: "f5-via-pattern".to_string(),
                });
            }
        }

        evidence
    }

    async fn check_cookies(&self, response: &HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check Set-Cookie headers for F5 patterns
        if let Some(cookies) = response.headers.get("set-cookie") {
            // Check for BIGipServer* cookies
            if cookies.contains("BIGipServer") {
                evidence.push(Evidence {
                    method_type: MethodType::Header("set-cookie".to_string()),
                    confidence: 0.95,
                    description: "F5 BIG-IP persistence cookie detected".to_string(),
                    raw_data: "BIGipServer cookie present".to_string(),
                    signature_matched: "bigip-server-cookie".to_string(),
                });
            }

            // Check for F5 persistence cookies (TS* cookies)
            if Self::f5_cookie_pattern().is_match(cookies) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("set-cookie".to_string()),
                    confidence: 0.85,
                    description: "F5 session/persistence cookie detected".to_string(),
                    raw_data: "F5 cookie pattern matched".to_string(),
                    signature_matched: "f5-cookie-pattern".to_string(),
                });
            }
        }

        evidence
    }

    async fn check_body(&self, response: &HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        if !response.body.is_empty() {
            // Check for F5 block page patterns
            if Self::f5_block_pattern().is_match(&response.body) {
                evidence.push(Evidence {
                    method_type: MethodType::Body("f5-block-page".to_string()),
                    confidence: 0.95,
                    description: "F5 block page detected".to_string(),
                    raw_data: "Block page pattern detected".to_string(),
                    signature_matched: "f5-block-pattern".to_string(),
                });
            }

            // Check for F5 ASM patterns
            if Self::f5_asm_pattern().is_match(&response.body) {
                evidence.push(Evidence {
                    method_type: MethodType::Body("f5-asm-page".to_string()),
                    confidence: 0.90,
                    description: "F5 ASM security page detected".to_string(),
                    raw_data: "ASM pattern detected".to_string(),
                    signature_matched: "f5-asm-pattern".to_string(),
                });
            }

            // Check for support ID patterns (common in F5 error pages)
            // More specific: needs both "support id" and "administrator" in close proximity
            if response.body.to_lowercase().contains("support id")
                && response.body.to_lowercase().contains("your administrator")
                && (response.body.contains("F5")
                    || response.body.contains("BIG-IP")
                    || response.body.contains("rejected")
                    || response.body.contains("blocked"))
            {
                evidence.push(Evidence {
                    method_type: MethodType::Body("f5-support-id".to_string()),
                    confidence: 0.85,
                    description: "F5 error page with support ID detected".to_string(),
                    raw_data: "Support ID pattern detected".to_string(),
                    signature_matched: "f5-support-id-pattern".to_string(),
                });
            }
        }

        evidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_response() -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: String::new(),
            url: "https://test.com".to_string(),
        }
    }

    #[tokio::test]
    async fn test_f5_server_header_detection() {
        let provider = F5Provider::new();
        let mut response = create_test_response();

        response
            .headers
            .insert("server".to_string(), "BIG-IP".to_string());

        let evidence = provider.passive_detect(&response).await.unwrap();

        assert!(!evidence.is_empty());
        assert!(evidence
            .iter()
            .any(|e| e.description.contains("F5 server header")));
    }

    #[tokio::test]
    async fn test_f5_cookie_detection() {
        let provider = F5Provider::new();
        let mut response = create_test_response();

        response.headers.insert(
            "set-cookie".to_string(),
            "BIGipServer_pool=1234567890.12345.0000; path=/".to_string(),
        );

        let evidence = provider.passive_detect(&response).await.unwrap();

        assert!(!evidence.is_empty());
        assert!(evidence
            .iter()
            .any(|e| e.description.contains("F5 BIG-IP persistence cookie")));
    }

    #[tokio::test]
    async fn test_f5_block_page_detection() {
        let provider = F5Provider::new();
        let mut response = create_test_response();

        response.body = "The requested URL was rejected. Please consult with your administrator. Your support ID is: 123456789".to_string();

        let evidence = provider.passive_detect(&response).await.unwrap();

        assert!(!evidence.is_empty());
        assert!(evidence
            .iter()
            .any(|e| e.description.contains("F5 block page")));
    }

    #[tokio::test]
    async fn test_f5_asm_detection() {
        let provider = F5Provider::new();
        let mut response = create_test_response();

        response.body =
            "Application Security Manager detected a violation. Support ID: 1234567890123"
                .to_string();

        let evidence = provider.passive_detect(&response).await.unwrap();

        assert!(!evidence.is_empty());
        assert!(evidence.iter().any(|e| e.description.contains("F5 ASM")));
    }
}
