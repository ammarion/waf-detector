//! Fastly Next CDN/WAF Detection Provider

use crate::{DetectionProvider, DetectionContext, Evidence, ProviderType, MethodType};
use regex::Regex;
use std::sync::OnceLock;
use anyhow::Result;

/// Fastly Next CDN/WAF detection provider
#[derive(Debug, Clone)]
pub struct FastlyProvider {
    name: String,
    version: String,
    description: String,
    enabled: bool,
}

impl FastlyProvider {
    pub fn new() -> Self {
        Self {
            name: "Fastly".to_string(),
            version: "1.0.0".to_string(),
            description: "Fastly Next Generation CDN and WAF detection provider".to_string(),
            enabled: true,
        }
    }

    // Pre-compiled regex patterns for performance
    fn fastly_restarts_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"^\d+$").unwrap())
    }

    fn fastly_via_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)1\.1 varnish").unwrap())
    }

    fn fastly_served_by_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"cache-[a-z]+\d+-[A-Z]{3}").unwrap())
    }

    fn fastly_cache_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        // Fastly cache status patterns - CloudFront exclusion handled in logic
        PATTERN.get_or_init(|| Regex::new(r"(?i)(HIT|MISS|PASS|ERROR)").unwrap())
    }

    fn fastly_timing_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"S\d+\.\d+,VS\d+,VE\d+").unwrap())
    }

    async fn check_headers(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check fastly-restarts header (DEFINITIVE FASTLY SIGNATURE)
        if let Some(restarts) = response.headers.get("fastly-restarts") {
            if Self::fastly_restarts_pattern().is_match(restarts) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("fastly-restarts".to_string()),
                    confidence: 0.98,
                    description: "Fastly restart counter header detected (definitive signature)".to_string(),
                    raw_data: restarts.clone(),
                    signature_matched: "fastly-restarts-pattern".to_string(),
                });
            }
        }

        // Check Via header for Varnish (Fastly's cache technology)
        if let Some(via) = response.headers.get("via") {
            if Self::fastly_via_pattern().is_match(via) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("via".to_string()),
                    confidence: 0.90,
                    description: "Fastly Varnish via header detected".to_string(),
                    raw_data: via.clone(),
                    signature_matched: "fastly-via-pattern".to_string(),
                });
            }
        }

        // Check x-served-by header for Fastly cache nodes
        if let Some(served_by) = response.headers.get("x-served-by") {
            if Self::fastly_served_by_pattern().is_match(served_by) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-served-by".to_string()),
                    confidence: 0.95,
                    description: "Fastly cache node served-by header detected".to_string(),
                    raw_data: served_by.clone(),
                    signature_matched: "fastly-served-by-pattern".to_string(),
                });
            }
        }

        // Check x-cache header for Fastly cache status
        if let Some(cache) = response.headers.get("x-cache") {
            // Exclude CloudFront patterns explicitly
            if Self::fastly_cache_pattern().is_match(cache) && 
               !cache.to_lowercase().contains("cloudfront") &&
               !cache.to_lowercase().contains("from cloudfront") {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-cache".to_string()),
                    confidence: 0.85,
                    description: "Fastly cache status header detected".to_string(),
                    raw_data: cache.clone(),
                    signature_matched: "fastly-cache-pattern".to_string(),
                });
            }
        }

        // Check x-cache-hits header for Fastly cache hits
        if let Some(cache_hits) = response.headers.get("x-cache-hits") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-cache-hits".to_string()),
                confidence: 0.85,
                description: "Fastly cache hits header detected".to_string(),
                raw_data: cache_hits.clone(),
                signature_matched: "fastly-cache-hits-pattern".to_string(),
            });
        }

        // Check x-timer header for Fastly timing information
        if let Some(timer) = response.headers.get("x-timer") {
            if Self::fastly_timing_pattern().is_match(timer) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-timer".to_string()),
                    confidence: 0.80,
                    description: "Fastly timing header detected".to_string(),
                    raw_data: timer.clone(),
                    signature_matched: "fastly-timing-pattern".to_string(),
                });
            }
        }

        evidence
    }

    async fn check_body_patterns(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check for Fastly error pages
        if response.body.contains("Fastly error") || response.body.contains("fastly.com") {
            evidence.push(Evidence {
                method_type: MethodType::Body("fastly-error-page".to_string()),
                confidence: 0.90,
                description: "Fastly error page detected in response body".to_string(),
                raw_data: "fastly-error-page-detected".to_string(),
                signature_matched: "fastly-error-page-pattern".to_string(),
            });
        }

        evidence
    }

    async fn check_status_codes(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        match response.status {
            403 => {
                // Check if it's a Fastly WAF 403
                if response.headers.get("fastly-restarts").is_some() ||
                   response.headers.get("x-served-by").map_or(false, |v| Self::fastly_served_by_pattern().is_match(v)) {
                    evidence.push(Evidence {
                        method_type: MethodType::StatusCode(403),
                        confidence: 0.80,
                        description: "Fastly WAF 403 Forbidden response".to_string(),
                        raw_data: "403".to_string(),
                        signature_matched: "fastly-403-pattern".to_string(),
                    });
                }
            }
            429 => {
                // Fastly rate limiting
                if response.headers.get("fastly-restarts").is_some() {
                    evidence.push(Evidence {
                        method_type: MethodType::StatusCode(429),
                        confidence: 0.85,
                        description: "Fastly rate limiting detected".to_string(),
                        raw_data: "429".to_string(),
                        signature_matched: "fastly-429-pattern".to_string(),
                    });
                }
            }
            _ => {}
        }

        evidence
    }
}

#[async_trait::async_trait]
impl DetectionProvider for FastlyProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn description(&self) -> Option<String> {
        Some(self.description.clone())
    }

    fn confidence_base(&self) -> f64 {
        0.85
    }

    fn priority(&self) -> u32 {
        95
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Both
    }

    async fn detect(&self, context: &DetectionContext) -> Result<Vec<Evidence>> {
        let mut all_evidence = Vec::new();

        if let Some(response) = &context.response {
            // Check headers (most reliable)
            all_evidence.extend(self.check_headers(response).await);
            
            // Check body patterns
            all_evidence.extend(self.check_body_patterns(response).await);
            
            // Check status codes
            all_evidence.extend(self.check_status_codes(response).await);
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

impl Default for FastlyProvider {
    fn default() -> Self {
        Self::new()
    }
} 