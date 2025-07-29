//! Azure CDN and Application Gateway detection provider

use crate::{
    http::{HttpClient, HttpResponse},
    DetectionContext, DetectionProvider, Evidence, MethodType, ProviderType,
};
use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use std::sync::OnceLock;

/// Azure CDN and Application Gateway provider implementation
#[derive(Debug, Clone)]
pub struct AzureProvider {
    enabled: bool,
}

impl AzureProvider {
    pub fn new() -> Self {
        Self { enabled: true }
    }

    // Pre-compiled regex patterns for performance
    fn azure_cache_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(ARRAffinity|TCP_HIT from)").unwrap())
    }

    fn azure_server_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(microsoft-iis|microsoft-httpapi|azure)").unwrap())
    }

    fn azure_block_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(azure front door.*block|access denied.*azure|azure application gateway.*error)").unwrap())
    }

    fn azure_error_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| {
            Regex::new(r"(?i)(502 bad gateway.*application gateway|error 50[0-9].*azure)").unwrap()
        })
    }
}

impl Default for AzureProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DetectionProvider for AzureProvider {
    fn name(&self) -> &str {
        "Azure"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn description(&self) -> Option<String> {
        Some("Detects Azure CDN, Front Door, and Application Gateway".to_string())
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Both
    }

    fn confidence_base(&self) -> f64 {
        0.95
    }

    fn priority(&self) -> u32 {
        90
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

        // Check body patterns
        evidence.extend(self.check_body(response).await);

        Ok(evidence)
    }

    async fn active_detect(&self, client: &HttpClient, url: &str) -> Result<Vec<Evidence>> {
        let mut evidence = Vec::new();

        // Test with Azure-specific paths
        let test_paths = vec![
            "/.auth/login/aad", // Azure App Service auth endpoint
            "/api/health",      // Common Azure Function endpoint
        ];

        for path in test_paths {
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);
            match client.get(&test_url).await {
                Ok(response) => {
                    if response.status == 401 || response.status == 404 {
                        // Check if response has Azure-specific headers even on error pages
                        if response.headers.contains_key("x-azure-ref")
                            || response.headers.contains_key("x-ms-request-id")
                        {
                            evidence.push(Evidence {
                                method_type: MethodType::Header("x-azure-ref".to_string()),
                                confidence: 0.85,
                                description: "Azure-specific headers on protected endpoint"
                                    .to_string(),
                                raw_data: format!("Status {} on {}", response.status, path),
                                signature_matched: "azure-endpoint-behavior".to_string(),
                            });
                        }
                    }
                }
                Err(_) => {
                    // Network errors might indicate blocking
                }
            }
        }

        Ok(evidence)
    }
}

impl AzureProvider {
    async fn check_headers(&self, response: &HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check Azure Front Door headers
        if let Some(value) = response.headers.get("x-azure-ref") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-azure-ref".to_string()),
                confidence: 0.95,
                description: "Azure Front Door header detected".to_string(),
                raw_data: value.clone(),
                signature_matched: "x-azure-ref-header".to_string(),
            });
        }

        if let Some(value) = response.headers.get("x-azure-fdid") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-azure-fdid".to_string()),
                confidence: 0.98,
                description: "Azure Front Door ID header detected".to_string(),
                raw_data: value.clone(),
                signature_matched: "x-azure-fdid-header".to_string(),
            });
        }

        // Check X-Cache for Azure CDN patterns
        if let Some(value) = response.headers.get("x-cache") {
            if Self::azure_cache_pattern().is_match(value) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-cache".to_string()),
                    confidence: 0.85,
                    description: "X-Cache header indicates Azure CDN".to_string(),
                    raw_data: value.clone(),
                    signature_matched: "azure-cdn-cache-pattern".to_string(),
                });
            }
        }

        // Check Azure Application Gateway headers
        if let Some(value) = response.headers.get("arr-disable-session-affinity") {
            evidence.push(Evidence {
                method_type: MethodType::Header("arr-disable-session-affinity".to_string()),
                confidence: 0.90,
                description: "Azure Application Gateway session affinity header".to_string(),
                raw_data: value.clone(),
                signature_matched: "arr-session-affinity-header".to_string(),
            });
        }

        // Check X-Powered-By for ASP.NET (common in Azure)
        if let Some(value) = response.headers.get("x-powered-by") {
            if value.contains("ASP.NET") {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-powered-by".to_string()),
                    confidence: 0.60,
                    description: "ASP.NET powered-by header (common in Azure)".to_string(),
                    raw_data: value.clone(),
                    signature_matched: "aspnet-powered-by".to_string(),
                });
            }
        }

        // Check server header for Azure patterns
        if let Some(value) = response.headers.get("server") {
            if Self::azure_server_pattern().is_match(value) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("server".to_string()),
                    confidence: 0.70,
                    description: "Server header indicates Azure infrastructure".to_string(),
                    raw_data: value.clone(),
                    signature_matched: "azure-server-pattern".to_string(),
                });
            }
        }

        // Check Microsoft-specific headers
        if let Some(value) = response.headers.get("x-ms-edge-server") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-ms-edge-server".to_string()),
                confidence: 0.95,
                description: "Microsoft Edge server header detected".to_string(),
                raw_data: value.clone(),
                signature_matched: "x-ms-edge-server-header".to_string(),
            });
        }

        // Check for any x-ms-* headers
        for (name, value) in &response.headers {
            if name.starts_with("x-ms-") && name != "x-ms-edge-server" {
                evidence.push(Evidence {
                    method_type: MethodType::Header(name.to_string()),
                    confidence: 0.90,
                    description: format!("Microsoft/Azure specific header {name} detected"),
                    raw_data: value.clone(),
                    signature_matched: "x-ms-header-pattern".to_string(),
                });
            }
        }

        evidence
    }

    async fn check_body(&self, response: &HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        if !response.body.is_empty() {
            // Check for Azure Front Door block page patterns
            if Self::azure_block_pattern().is_match(&response.body) {
                evidence.push(Evidence {
                    method_type: MethodType::Body("azure-front-door-block".to_string()),
                    confidence: 0.95,
                    description: "Azure Front Door WAF block page detected".to_string(),
                    raw_data: "Block page pattern detected".to_string(),
                    signature_matched: "azure-front-door-block-pattern".to_string(),
                });
            }

            // Check for Azure Application Gateway error patterns
            if Self::azure_error_pattern().is_match(&response.body) {
                evidence.push(Evidence {
                    method_type: MethodType::Body("azure-app-gateway-error".to_string()),
                    confidence: 0.90,
                    description: "Azure Application Gateway error page detected".to_string(),
                    raw_data: "Error page pattern detected".to_string(),
                    signature_matched: "azure-app-gateway-error-pattern".to_string(),
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
    async fn test_azure_front_door_detection() {
        let provider = AzureProvider::new();
        let mut response = create_test_response();

        response
            .headers
            .insert("x-azure-fdid".to_string(), "front-door-id-123".to_string());
        response
            .headers
            .insert("x-azure-ref".to_string(), "ref-abc-123".to_string());

        let evidence = provider.passive_detect(&response).await.unwrap();

        assert!(!evidence.is_empty());
        assert!(evidence.iter().any(|e| e.confidence > 0.95));
        assert!(evidence
            .iter()
            .any(|e| e.description.contains("Azure Front Door")));
    }

    #[tokio::test]
    async fn test_azure_app_gateway_detection() {
        let provider = AzureProvider::new();
        let mut response = create_test_response();

        response.headers.insert(
            "arr-disable-session-affinity".to_string(),
            "true".to_string(),
        );

        let evidence = provider.passive_detect(&response).await.unwrap();

        assert!(!evidence.is_empty());
        assert!(evidence
            .iter()
            .any(|e| e.description.contains("Azure Application Gateway")));
    }

    #[tokio::test]
    async fn test_ms_headers_detection() {
        let provider = AzureProvider::new();
        let mut response = create_test_response();

        response
            .headers
            .insert("x-ms-request-id".to_string(), "req-123".to_string());
        response
            .headers
            .insert("x-ms-version".to_string(), "2.0".to_string());

        let evidence = provider.passive_detect(&response).await.unwrap();

        assert!(!evidence.is_empty());
        assert!(evidence
            .iter()
            .any(|e| e.description.contains("Microsoft/Azure")));
    }
}
