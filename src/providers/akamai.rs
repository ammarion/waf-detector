//! Akamai WAF/CDN Detection Provider

use crate::{DetectionProvider, DetectionContext, Evidence, ProviderType, MethodType};
use regex::Regex;
use std::sync::OnceLock;
use anyhow::Result;

/// Akamai detection provider
#[derive(Debug, Clone)]
pub struct AkamaiProvider {
    name: String,
    version: String,
    description: String,
    enabled: bool,
}

impl AkamaiProvider {
    pub fn new() -> Self {
        Self {
            name: "Akamai".to_string(),
            version: "1.0.0".to_string(),
            description: "Akamai CDN/WAF detection provider - one of the largest CDN networks globally".to_string(),
            enabled: true,
        }
    }

    // Pre-compiled regex patterns for performance
    fn akamai_server_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)akamai").unwrap())
    }

    fn akamai_cache_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"\.akamaitechnologies\.com").unwrap())
    }

    fn akamai_reference_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"Reference #\d+\.[a-f0-9]+\.\d+\.[a-f0-9]+").unwrap())
    }

    fn akamai_error_page_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)access denied.*reference #").unwrap())
    }

    fn akamai_x_header_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"^x-akamai-").unwrap())
    }

    pub async fn check_headers(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check Server header for AkamaiGHost
        if let Some(server) = response.headers.get("server") {
            if Self::akamai_server_pattern().is_match(server) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("server".to_string()),
                    confidence: 0.95,
                    description: "Akamai server header detected".to_string(),
                    raw_data: server.clone(),
                    signature_matched: "akamai-server-pattern".to_string(),
                });
            }
        }

        // Check X-Cache headers
        for cache_header in ["x-cache", "x-cache-remote"] {
            if let Some(cache_value) = response.headers.get(cache_header) {
                if Self::akamai_cache_pattern().is_match(cache_value) {
                    evidence.push(Evidence {
                        method_type: MethodType::Header(cache_header.to_string()),
                        confidence: 0.90,
                        description: format!("Akamai {} header detected", cache_header),
                        raw_data: cache_value.clone(),
                        signature_matched: "akamai-cache-pattern".to_string(),
                    });
                }
            }
        }

        // Check X-Akamai-* headers
        for (header_name, header_value) in &response.headers {
            if Self::akamai_x_header_pattern().is_match(header_name) {
                let confidence = match header_name.as_str() {
                    "x-akamai-request-id" => 0.95,
                    "x-akamai-session-info" => 0.90,
                    "x-akamai-transformed" => 0.85,
                    "x-akamai-edgescape" => 0.85,
                    _ => 0.80,
                };

                evidence.push(Evidence {
                    method_type: MethodType::Header(header_name.clone()),
                    confidence,
                    description: format!("Akamai {} header detected", header_name),
                    raw_data: header_value.clone(),
                    signature_matched: "akamai-x-header-pattern".to_string(),
                });
            }
        }

        // Check other Akamai-specific headers
        let akamai_headers = [
            ("x-check-cacheable", "Akamai cache check header", 0.85),
            ("true-client-ip", "Akamai true client IP header", 0.75),
        ];

        for (header_name, description, confidence) in akamai_headers {
            if response.headers.contains_key(header_name) {
                evidence.push(Evidence {
                    method_type: MethodType::Header(header_name.to_string()),
                    confidence,
                    description: description.to_string(),
                    raw_data: response.headers.get(header_name).unwrap().clone(),
                    signature_matched: format!("{}-pattern", header_name),
                });
            }
        }

        evidence
    }

    pub async fn check_body_patterns(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check for Akamai reference ID patterns
        if Self::akamai_reference_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("reference-id-detected".to_string()),
                confidence: 0.90,
                description: "Akamai reference ID pattern detected".to_string(),
                raw_data: "reference-id-detected".to_string(),
                signature_matched: "akamai-reference-pattern".to_string(),
            });
        }

        // Check for Akamai error page patterns
        if Self::akamai_error_page_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("error-page-detected".to_string()),
                confidence: 0.90,
                description: "Akamai access denied page detected".to_string(),
                raw_data: "error-page-detected".to_string(),
                signature_matched: "akamai-error-page-pattern".to_string(),
            });
        }

        // Check for Akamai content references
        if response.body.contains("akamai") || response.body.contains("akamaitechnologies") {
            evidence.push(Evidence {
                method_type: MethodType::Body("content-reference-detected".to_string()),
                confidence: 0.75,
                description: "Akamai content reference detected".to_string(),
                raw_data: "content-reference-detected".to_string(),
                signature_matched: "akamai-content-pattern".to_string(),
            });
        }

        evidence
    }

    pub async fn check_status_codes(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        match response.status {
            403 => {
                // Check if it's an Akamai 403
                if response.headers.iter().any(|(k, _)| k.starts_with("x-akamai-")) ||
                   Self::akamai_reference_pattern().is_match(&response.body) {
                    evidence.push(Evidence {
                        method_type: MethodType::StatusCode(403),
                        confidence: 0.80,
                        description: "Akamai 403 Forbidden response".to_string(),
                        raw_data: "403".to_string(),
                        signature_matched: "akamai-403-pattern".to_string(),
                    });
                }
            }
            404 => {
                // Check if it's an Akamai 404 with reference pattern
                if Self::akamai_reference_pattern().is_match(&response.body) {
                    evidence.push(Evidence {
                        method_type: MethodType::StatusCode(404),
                        confidence: 0.75,
                        description: "Akamai 404 Not Found with reference ID".to_string(),
                        raw_data: "404".to_string(),
                        signature_matched: "akamai-404-pattern".to_string(),
                    });
                }
            }
            _ => {}
        }

        evidence
    }
}

#[async_trait::async_trait]
impl DetectionProvider for AkamaiProvider {
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
        ProviderType::Both
    }

    fn confidence_base(&self) -> f64 {
        0.92
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

impl Default for AkamaiProvider {
    fn default() -> Self {
        Self::new()
    }
}
