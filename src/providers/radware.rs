//! Radware (AppWall) WAF Detection Provider

use crate::{DetectionContext, DetectionProvider, Evidence, MethodType, ProviderType};
use anyhow::Result;
use regex::Regex;
use std::sync::OnceLock;

/// Radware detection provider
#[derive(Debug, Clone)]
pub struct RadwareProvider {
    name: String,
    version: String,
    description: String,
    enabled: bool,
}

impl RadwareProvider {
    pub fn new() -> Self {
        Self {
            name: "Radware".to_string(),
            version: "1.0.0".to_string(),
            description: "Radware AppWall WAF detection provider".to_string(),
            enabled: true,
        }
    }

    // Pre-compiled regex patterns for performance
    fn cookie_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"rdwl_SID").unwrap())
    }

    fn body_appwall_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)appwall").unwrap())
    }

    fn body_radware_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)radware").unwrap())
    }

    async fn check_headers(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check X-SL-CompState header (unique Radware/AppWall signature)
        if let Some(value) = response.headers.get("x-sl-compstate") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-sl-compstate".to_string()),
                confidence: 0.95,
                description: "Radware AppWall X-SL-CompState header detected".to_string(),
                raw_data: value.clone(),
                signature_matched: "radware-compstate-header".to_string(),
            });
        }

        // Check X-SL-RequestID header
        if let Some(value) = response.headers.get("x-sl-requestid") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-sl-requestid".to_string()),
                confidence: 0.90,
                description: "Radware AppWall X-SL-RequestID header detected".to_string(),
                raw_data: value.clone(),
                signature_matched: "radware-requestid-header".to_string(),
            });
        }

        evidence
    }

    async fn check_cookies(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check for rdwl_SID cookie pattern
        if let Some(cookie) = response.headers.get("set-cookie") {
            if Self::cookie_pattern().is_match(cookie) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("set-cookie".to_string()),
                    confidence: 0.90,
                    description: "Radware session cookie detected".to_string(),
                    raw_data: cookie.clone(),
                    signature_matched: "radware-cookie".to_string(),
                });
            }
        }

        evidence
    }

    async fn check_body_patterns(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check for AppWall references
        if Self::body_appwall_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("appwall-reference".to_string()),
                confidence: 0.85,
                description: "Radware AppWall reference detected in response body".to_string(),
                raw_data: "appwall-reference".to_string(),
                signature_matched: "radware-appwall-body".to_string(),
            });
        }

        // Check for Radware block page references
        if Self::body_radware_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("radware-reference".to_string()),
                confidence: 0.80,
                description: "Radware block page reference detected".to_string(),
                raw_data: "radware-reference".to_string(),
                signature_matched: "radware-body".to_string(),
            });
        }

        evidence
    }
}

#[async_trait::async_trait]
impl DetectionProvider for RadwareProvider {
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
        0.90
    }

    fn priority(&self) -> u32 {
        82
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

            // Check cookies
            let cookie_evidence = self.check_cookies(response).await;
            all_evidence.extend(cookie_evidence);

            // Check body patterns
            let body_evidence = self.check_body_patterns(response).await;
            all_evidence.extend(body_evidence);
        }

        Ok(all_evidence)
    }

    async fn passive_detect(&self, response: &crate::http::HttpResponse) -> Result<Vec<Evidence>> {
        let mut all_evidence = Vec::new();

        all_evidence.extend(self.check_headers(response).await);
        all_evidence.extend(self.check_cookies(response).await);
        all_evidence.extend(self.check_body_patterns(response).await);

        Ok(all_evidence)
    }
}

impl Default for RadwareProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::test_utils::mock_response;

    #[tokio::test]
    async fn detects_radware_x_sl_compstate_header() {
        let provider = RadwareProvider::new();
        let response = mock_response(200, [("x-sl-compstate", "1")], "");
        let evidence = provider.passive_detect(&response).await.unwrap();
        assert!(!evidence.is_empty());
        assert!(evidence
            .iter()
            .any(|e| e.signature_matched == "radware-compstate-header"));
    }

    #[tokio::test]
    async fn detects_radware_cookie() {
        let provider = RadwareProvider::new();
        let response = mock_response(
            200,
            [("set-cookie", "rdwl_SID=abc123; path=/")],
            "",
        );
        let evidence = provider.passive_detect(&response).await.unwrap();
        assert!(evidence
            .iter()
            .any(|e| e.signature_matched == "radware-cookie"));
    }

    #[tokio::test]
    async fn no_evidence_without_radware_indicators() {
        let provider = RadwareProvider::new();
        let response = mock_response(200, [("server", "nginx")], "");
        let evidence = provider.passive_detect(&response).await.unwrap();
        assert!(evidence.is_empty());
    }
}
