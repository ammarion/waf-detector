//! FortiWeb WAF Detection Provider

use crate::{DetectionContext, DetectionProvider, Evidence, MethodType, ProviderType};
use anyhow::Result;
use regex::Regex;
use std::sync::OnceLock;

/// FortiWeb detection provider
#[derive(Debug, Clone)]
pub struct FortiWebProvider {
    name: String,
    version: String,
    description: String,
    enabled: bool,
}

impl FortiWebProvider {
    pub fn new() -> Self {
        Self {
            name: "FortiWeb".to_string(),
            version: "1.0.0".to_string(),
            description: "FortiWeb WAF detection provider".to_string(),
            enabled: true,
        }
    }

    // Pre-compiled regex patterns for performance
    fn server_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)fortiweb").unwrap())
    }

    fn cookie_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"FORTIWAFSID").unwrap())
    }

    fn body_fortinet_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(fortigate|fortiweb)").unwrap())
    }

    fn body_block_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN
            .get_or_init(|| Regex::new(r"(?i)web\s+page\s+blocked.*fortinet").unwrap())
    }

    async fn check_headers(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check Server header for FortiWeb
        if let Some(server) = response.headers.get("server") {
            if Self::server_pattern().is_match(server) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("server".to_string()),
                    confidence: 0.95,
                    description: "FortiWeb server header detected".to_string(),
                    raw_data: server.clone(),
                    signature_matched: "fortiweb-server-header".to_string(),
                });
            }
        }

        // Check X-FortiWeb-Nonce header
        if let Some(value) = response.headers.get("x-fortiweb-nonce") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-fortiweb-nonce".to_string()),
                confidence: 0.92,
                description: "FortiWeb nonce header detected".to_string(),
                raw_data: value.clone(),
                signature_matched: "fortiweb-nonce-header".to_string(),
            });
        }

        evidence
    }

    async fn check_cookies(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check for FORTIWAFSID cookie pattern
        if let Some(cookie) = response.headers.get("set-cookie") {
            if Self::cookie_pattern().is_match(cookie) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("set-cookie".to_string()),
                    confidence: 0.95,
                    description: "FortiWeb session cookie detected".to_string(),
                    raw_data: cookie.clone(),
                    signature_matched: "fortiweb-cookie".to_string(),
                });
            }
        }

        evidence
    }

    async fn check_body_patterns(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check for FortiGate/FortiWeb references
        if Self::body_fortinet_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("fortinet-reference".to_string()),
                confidence: 0.80,
                description: "FortiWeb/FortiGate reference detected in response body".to_string(),
                raw_data: "fortinet-reference".to_string(),
                signature_matched: "fortiweb-body".to_string(),
            });
        }

        // Check for "web page blocked" combined with "fortinet"
        if Self::body_block_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("fortinet-block-page".to_string()),
                confidence: 0.85,
                description: "FortiWeb block page detected".to_string(),
                raw_data: "fortinet-block-page".to_string(),
                signature_matched: "fortiweb-block-body".to_string(),
            });
        }

        evidence
    }
}

#[async_trait::async_trait]
impl DetectionProvider for FortiWebProvider {
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
        80
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

impl Default for FortiWebProvider {
    fn default() -> Self {
        Self::new()
    }
}
