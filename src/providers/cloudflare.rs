//! CloudFlare WAF/CDN Detection Provider

use crate::{DetectionProvider, DetectionContext, Evidence, ProviderType, MethodType};
use regex::Regex;
use std::sync::OnceLock;
use anyhow::Result;

/// CloudFlare detection provider
#[derive(Debug, Clone)]
pub struct CloudFlareProvider {
    name: String,
    version: String,
    description: String,
    enabled: bool,
}

impl CloudFlareProvider {
    pub fn new() -> Self {
        Self {
            name: "CloudFlare".to_string(),
            version: "1.0.0".to_string(),
            description: "CloudFlare WAF/CDN detection provider".to_string(),
            enabled: true,
        }
    }

    // Pre-compiled regex patterns for performance
    fn cf_ray_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"^[a-f0-9]+-[A-Z]{3}$").unwrap())
    }

    fn cf_cache_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(HIT|MISS|EXPIRED|BYPASS|DYNAMIC|REVALIDATED)").unwrap())
    }

    fn cf_server_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)cloudflare").unwrap())
    }

    fn cf_challenge_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        // FIXED: Much more specific patterns - require actual CloudFlare challenge page elements
        PATTERN.get_or_init(|| Regex::new(r"(?i)(checking your browser.*cloudflare|cf_chl_jschl_tk|cf_chl_captcha_tk|challenge-platform.*cloudflare)").unwrap())
    }

    fn cf_error_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        // FIXED: Require specific CloudFlare error page structure, not just word "cloudflare"
        PATTERN.get_or_init(|| Regex::new(r"(?i)(cloudflare.*error 10\d{2}|error 10\d{2}.*cloudflare|cloudflare.*blocked|cloudflare.*access denied)").unwrap())
    }

    fn cf_js_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)(cf_chl_jschl_tk|cf_clearance|cf_chl_captcha_tk)").unwrap())
    }

    async fn check_headers(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check CF-Ray header
        if let Some(cf_ray) = response.headers.get("cf-ray") {
            if Self::cf_ray_pattern().is_match(cf_ray) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("cf-ray".to_string()),
                    confidence: 0.95,
                    description: "CloudFlare Ray ID header detected".to_string(),
                    raw_data: cf_ray.clone(),
                    signature_matched: "cf-ray-header".to_string(),
                });
            }
        }

        // Check CF-Cache-Status
        if let Some(cache_status) = response.headers.get("cf-cache-status") {
            if Self::cf_cache_pattern().is_match(cache_status) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("cf-cache-status".to_string()),
                    confidence: 0.90,
                    description: "CloudFlare cache status header detected".to_string(),
                    raw_data: cache_status.clone(),
                    signature_matched: "cf-cache-status-header".to_string(),
                });
            }
        }

        // Check Server header
        if let Some(server) = response.headers.get("server") {
            if Self::cf_server_pattern().is_match(server) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("server".to_string()),
                    confidence: 0.85,
                    description: "CloudFlare server header detected".to_string(),
                    raw_data: server.clone(),
                    signature_matched: "cloudflare-server-header".to_string(),
                });
            }
        }

        // Check other CloudFlare headers
        let cf_headers = [
            ("cf-connecting-ip", "CloudFlare connecting IP header", 0.80, "cf-connecting-ip-header"),
            ("cf-ipcountry", "CloudFlare IP country header", 0.75, "cf-ipcountry-header"),
            ("cf-visitor", "CloudFlare visitor header", 0.75, "cf-visitor-header"),
            ("cf-request-id", "CloudFlare request ID header", 0.85, "cf-request-id-header"),
        ];

        for (header_name, description, confidence, signature) in cf_headers {
            if let Some(value) = response.headers.get(header_name) {
                evidence.push(Evidence {
                    method_type: MethodType::Header(header_name.to_string()),
                    confidence,
                    description: description.to_string(),
                    raw_data: value.clone(),
                    signature_matched: signature.to_string(),
                });
            }
        }

        evidence
    }

    async fn check_body_patterns(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check for CloudFlare challenge page (REDUCED CONFIDENCE - body patterns less reliable)
        if Self::cf_challenge_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("challenge-page-detected".to_string()),
                confidence: 0.70, // REDUCED from 0.90
                description: "CloudFlare browser challenge page detected".to_string(),
                raw_data: "challenge-page-detected".to_string(),
                signature_matched: "cf-challenge-body".to_string(),
            });
        }

        // Check for CloudFlare error pages (REDUCED CONFIDENCE)
        if Self::cf_error_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("error-page-detected".to_string()),
                confidence: 0.65, // REDUCED from 0.85
                description: "CloudFlare error page detected".to_string(),
                raw_data: "error-page-detected".to_string(),
                signature_matched: "cf-error-body".to_string(),
            });
        }

        // Check for CloudFlare JavaScript tokens (REDUCED CONFIDENCE)
        if Self::cf_js_pattern().is_match(&response.body) {
            evidence.push(Evidence {
                method_type: MethodType::Body("js-tokens-detected".to_string()),
                confidence: 0.60, // REDUCED from 0.80
                description: "CloudFlare JavaScript tokens detected".to_string(),
                raw_data: "js-tokens-detected".to_string(),
                signature_matched: "cf-js-body".to_string(),
            });
        }

        evidence
    }

    async fn check_status_codes(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        match response.status {
            403 => {
                // Check if it's a CloudFlare 403
                if response.headers.get("cf-ray").is_some() || 
                   Self::cf_challenge_pattern().is_match(&response.body) {
                    evidence.push(Evidence {
                        method_type: MethodType::StatusCode(403),
                        confidence: 0.75,
                        description: "CloudFlare 403 Forbidden response".to_string(),
                        raw_data: "403".to_string(),
                        signature_matched: "cf-403-status".to_string(),
                    });
                }
            }
            429 => {
                // CloudFlare rate limiting
                if response.headers.get("cf-ray").is_some() {
                    evidence.push(Evidence {
                        method_type: MethodType::StatusCode(429),
                        confidence: 0.80,
                        description: "CloudFlare rate limiting detected".to_string(),
                        raw_data: "429".to_string(),
                        signature_matched: "cf-429-status".to_string(),
                    });
                }
            }
            _ => {}
        }

        evidence
    }
}

#[async_trait::async_trait]
impl DetectionProvider for CloudFlareProvider {
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
        0.95
    }

    fn priority(&self) -> u32 {
        100
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

impl Default for CloudFlareProvider {
    fn default() -> Self {
        Self::new()
    }
}
