//! Sucuri WAF Detection Provider

use crate::{DetectionContext, DetectionProvider, Evidence, MethodType, ProviderType};
use anyhow::Result;
use regex::Regex;
use std::sync::OnceLock;

/// Sucuri detection provider
#[derive(Debug, Clone)]
pub struct SucuriProvider {
    name: String,
    version: String,
    description: String,
    enabled: bool,
}

impl SucuriProvider {
    pub fn new() -> Self {
        Self {
            name: "Sucuri".to_string(),
            version: "1.0.0".to_string(),
            description: "Sucuri CloudProxy WAF detection provider".to_string(),
            enabled: true,
        }
    }

    // Pre-compiled regex patterns for performance
    fn sucuri_cookie_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)sucuri_cloudproxy_uuid_").unwrap())
    }

    fn sucuri_server_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)sucuri(/cloudproxy)?").unwrap())
    }

    fn sucuri_cloudproxy_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)sucuri.*cloudproxy").unwrap())
    }

    fn sucuri_firewall_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)sucuri.*(firewall|website firewall)").unwrap())
    }

    fn sucuri_access_denied_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)access denied.*sucuri").unwrap())
    }

    fn sucuri_branding_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)sucuri").unwrap())
    }

    async fn check_headers(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check X-Sucuri-ID header (unique Sucuri identifier)
        if let Some(x_sucuri_id) = response.headers.get("x-sucuri-id") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-sucuri-id".to_string()),
                confidence: 0.95,
                description: "Sucuri X-Sucuri-ID header detected".to_string(),
                raw_data: x_sucuri_id.clone(),
                signature_matched: "sucuri-id-header".to_string(),
            });
        }

        // Check X-Sucuri-Cache header
        if let Some(x_sucuri_cache) = response.headers.get("x-sucuri-cache") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-sucuri-cache".to_string()),
                confidence: 0.90,
                description: "Sucuri X-Sucuri-Cache header detected".to_string(),
                raw_data: x_sucuri_cache.clone(),
                signature_matched: "sucuri-cache-header".to_string(),
            });
        }

        // Check X-Sucuri-Block header
        if let Some(x_sucuri_block) = response.headers.get("x-sucuri-block") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-sucuri-block".to_string()),
                confidence: 0.95,
                description: "Sucuri X-Sucuri-Block header detected".to_string(),
                raw_data: x_sucuri_block.clone(),
                signature_matched: "sucuri-block-header".to_string(),
            });
        }

        // Check Server header
        if let Some(server) = response.headers.get("server") {
            if Self::sucuri_server_pattern().is_match(server) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("server".to_string()),
                    confidence: 0.85,
                    description: "Sucuri Server header detected".to_string(),
                    raw_data: server.clone(),
                    signature_matched: "sucuri-server-header".to_string(),
                });
            }
        }

        // Check Set-Cookie headers for Sucuri CloudProxy UUID
        if let Some(cookies) = response.headers.get("set-cookie") {
            if Self::sucuri_cookie_pattern().is_match(cookies) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("set-cookie".to_string()),
                    confidence: 0.92,
                    description: "Sucuri CloudProxy UUID cookie detected".to_string(),
                    raw_data: "sucuri_cloudproxy_uuid_*".to_string(),
                    signature_matched: "sucuri-cookie".to_string(),
                });
            }
        }

        evidence
    }

    async fn check_body_patterns(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check for "sucuri" + "cloudproxy" combination
        if Self::sucuri_cloudproxy_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("sucuri-cloudproxy-reference".to_string()),
                confidence: 0.80,
                description: "Sucuri CloudProxy reference found in response body".to_string(),
                raw_data: "sucuri-cloudproxy-detected".to_string(),
                signature_matched: "sucuri-cloudproxy-body".to_string(),
            });
        }

        // Check for "sucuri" + "firewall" combination
        if Self::sucuri_firewall_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("sucuri-firewall-reference".to_string()),
                confidence: 0.85,
                description: "Sucuri firewall reference found in response body".to_string(),
                raw_data: "sucuri-firewall-detected".to_string(),
                signature_matched: "sucuri-firewall-body".to_string(),
            });
        }

        // Check for "access denied" + "sucuri" combination
        if Self::sucuri_access_denied_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("sucuri-access-denied".to_string()),
                confidence: 0.90,
                description: "Sucuri access denied message detected".to_string(),
                raw_data: "access-denied-sucuri".to_string(),
                signature_matched: "sucuri-access-denied-body".to_string(),
            });
        }

        // Check for generic Sucuri branding in block page
        if Self::sucuri_branding_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("sucuri-branding".to_string()),
                confidence: 0.85,
                description: "Sucuri branding found in block page".to_string(),
                raw_data: "sucuri-branding-detected".to_string(),
                signature_matched: "sucuri-branding-body".to_string(),
            });
        }

        evidence
    }

    async fn check_status_codes(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        if response.status == 403 {
            // Check if it's a Sucuri 403
            if response.headers.contains_key("x-sucuri-id")
                || Self::sucuri_branding_pattern().is_match(&response.body)
            {
                evidence.push(Evidence {
                    method_type: MethodType::StatusCode(403),
                    confidence: 0.75,
                    description: "Sucuri 403 Forbidden response".to_string(),
                    raw_data: "403".to_string(),
                    signature_matched: "sucuri-403-status".to_string(),
                });
            }
        }

        evidence
    }
}

#[async_trait::async_trait]
impl DetectionProvider for SucuriProvider {
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
        ProviderType::WAF
    }

    fn confidence_base(&self) -> f64 {
        0.93
    }

    fn priority(&self) -> u32 {
        90
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

        all_evidence.extend(self.check_headers(response).await);
        all_evidence.extend(self.check_body_patterns(response).await);
        all_evidence.extend(self.check_status_codes(response).await);

        Ok(all_evidence)
    }
}

impl Default for SucuriProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::test_utils::mock_response;

    #[tokio::test]
    async fn detects_sucuri_x_sucuri_id_header() {
        let provider = SucuriProvider::new();
        let response = mock_response(200, [("x-sucuri-id", "abc123")], "");
        let evidence = provider.passive_detect(&response).await.unwrap();
        assert!(!evidence.is_empty());
        assert!(evidence
            .iter()
            .any(|e| e.signature_matched == "sucuri-id-header"));
    }

    #[tokio::test]
    async fn detects_sucuri_server_header() {
        let provider = SucuriProvider::new();
        let response = mock_response(200, [("server", "Sucuri/CloudProxy")], "");
        let evidence = provider.passive_detect(&response).await.unwrap();
        assert!(evidence
            .iter()
            .any(|e| e.signature_matched == "sucuri-server-header"));
    }

    #[tokio::test]
    async fn no_evidence_without_sucuri_headers() {
        let provider = SucuriProvider::new();
        let response = mock_response(200, [("server", "nginx")], "");
        let evidence = provider.passive_detect(&response).await.unwrap();
        assert!(evidence.is_empty());
    }
}
