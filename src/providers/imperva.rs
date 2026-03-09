//! Imperva/Incapsula WAF Detection Provider

use crate::{DetectionContext, DetectionProvider, Evidence, MethodType, ProviderType};
use anyhow::Result;
use regex::Regex;
use std::sync::OnceLock;

/// Imperva/Incapsula detection provider
#[derive(Debug, Clone)]
pub struct ImpervaProvider {
    name: String,
    version: String,
    description: String,
    enabled: bool,
}

impl ImpervaProvider {
    pub fn new() -> Self {
        Self {
            name: "Imperva".to_string(),
            version: "1.0.0".to_string(),
            description: "Imperva/Incapsula WAF detection provider".to_string(),
            enabled: true,
        }
    }

    // Pre-compiled regex patterns for performance
    fn incap_cookie_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)incap_ses_").unwrap())
    }

    fn visid_cookie_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)visid_incap_").unwrap())
    }

    fn imperva_cdn_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(imperva|incapsula)").unwrap())
    }

    fn incapsula_body_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)incapsula").unwrap())
    }

    fn incident_id_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)incident id.*(incapsula|imperva)").unwrap())
    }

    fn powered_by_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)powered by incapsula").unwrap())
    }

    fn request_unsuccessful_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)request unsuccessful.*incapsula").unwrap())
    }

    async fn check_headers(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check X-CDN header
        if let Some(x_cdn) = response.headers.get("x-cdn") {
            if Self::imperva_cdn_pattern().is_match(x_cdn) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-cdn".to_string()),
                    confidence: 0.95,
                    description: "Imperva/Incapsula X-CDN header detected".to_string(),
                    raw_data: x_cdn.clone(),
                    signature_matched: "imperva-x-cdn-header".to_string(),
                });
            }
        }

        // Check X-Iinfo header (unique Imperva header)
        if let Some(x_iinfo) = response.headers.get("x-iinfo") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-iinfo".to_string()),
                confidence: 0.95,
                description: "Imperva X-Iinfo header detected".to_string(),
                raw_data: x_iinfo.clone(),
                signature_matched: "imperva-x-iinfo-header".to_string(),
            });
        }

        // Check Set-Cookie headers for Incapsula session cookies
        if let Some(cookies) = response.headers.get("set-cookie") {
            if Self::incap_cookie_pattern().is_match(cookies) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("set-cookie".to_string()),
                    confidence: 0.95,
                    description: "Incapsula session cookie detected".to_string(),
                    raw_data: "incap_ses_*".to_string(),
                    signature_matched: "imperva-incap-cookie".to_string(),
                });
            }

            if Self::visid_cookie_pattern().is_match(cookies) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("set-cookie".to_string()),
                    confidence: 0.95,
                    description: "Incapsula visitor ID cookie detected".to_string(),
                    raw_data: "visid_incap_*".to_string(),
                    signature_matched: "imperva-visid-cookie".to_string(),
                });
            }
        }

        // Check X-Request-ID header for Incapsula format
        if let Some(request_id) = response.headers.get("x-request-id") {
            // Incapsula request IDs typically have a specific format
            if request_id.len() > 10 {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-request-id".to_string()),
                    confidence: 0.70,
                    description: "Potential Incapsula request ID header".to_string(),
                    raw_data: request_id.clone(),
                    signature_matched: "imperva-request-id-header".to_string(),
                });
            }
        }

        evidence
    }

    async fn check_body_patterns(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check for Incapsula references in body
        if Self::incapsula_body_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("incapsula-reference".to_string()),
                confidence: 0.75,
                description: "Incapsula reference found in response body".to_string(),
                raw_data: "incapsula-reference-detected".to_string(),
                signature_matched: "imperva-incapsula-body".to_string(),
            });
        }

        // Check for incident ID with Imperva/Incapsula reference
        if Self::incident_id_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("incident-id-detected".to_string()),
                confidence: 0.85,
                description: "Imperva/Incapsula incident ID detected".to_string(),
                raw_data: "incident-id-detected".to_string(),
                signature_matched: "imperva-incident-id-body".to_string(),
            });
        }

        // Check for "powered by incapsula"
        if Self::powered_by_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("powered-by-detected".to_string()),
                confidence: 0.90,
                description: "Powered by Incapsula text detected".to_string(),
                raw_data: "powered-by-incapsula".to_string(),
                signature_matched: "imperva-powered-by-body".to_string(),
            });
        }

        // Check for "request unsuccessful" with Incapsula
        if Self::request_unsuccessful_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("request-unsuccessful-detected".to_string()),
                confidence: 0.80,
                description: "Incapsula request unsuccessful message detected".to_string(),
                raw_data: "request-unsuccessful".to_string(),
                signature_matched: "imperva-request-unsuccessful-body".to_string(),
            });
        }

        evidence
    }

    async fn check_status_codes(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        if response.status == 403 {
            // Check if it's an Imperva 403
            if response.headers.contains_key("x-iinfo")
                || Self::incapsula_body_pattern().is_match(&response.body)
            {
                evidence.push(Evidence {
                    method_type: MethodType::StatusCode(403),
                    confidence: 0.75,
                    description: "Imperva/Incapsula 403 Forbidden response".to_string(),
                    raw_data: "403".to_string(),
                    signature_matched: "imperva-403-status".to_string(),
                });
            }
        }

        evidence
    }
}

#[async_trait::async_trait]
impl DetectionProvider for ImpervaProvider {
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
        0.95
    }

    fn priority(&self) -> u32 {
        95
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

impl Default for ImpervaProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::test_utils::mock_response;

    #[tokio::test]
    async fn detects_imperva_x_iinfo_header() {
        let provider = ImpervaProvider::new();
        let response = mock_response(200, [("x-iinfo", "12345-67890-12345")], "");
        let evidence = provider.passive_detect(&response).await.unwrap();
        assert!(!evidence.is_empty());
        assert!(evidence
            .iter()
            .any(|e| e.signature_matched == "imperva-x-iinfo-header"));
    }

    #[tokio::test]
    async fn detects_imperva_x_cdn_header() {
        let provider = ImpervaProvider::new();
        let response = mock_response(200, [("x-cdn", "Incapsula")], "");
        let evidence = provider.passive_detect(&response).await.unwrap();
        assert!(evidence
            .iter()
            .any(|e| e.signature_matched == "imperva-x-cdn-header"));
    }

    #[tokio::test]
    async fn no_evidence_without_imperva_headers() {
        let provider = ImpervaProvider::new();
        let response = mock_response(200, [("server", "nginx")], "");
        let evidence = provider.passive_detect(&response).await.unwrap();
        assert!(evidence.is_empty());
    }
}
