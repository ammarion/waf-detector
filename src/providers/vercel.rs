//! Vercel CDN Detection Provider

use crate::{DetectionProvider, DetectionContext, Evidence, ProviderType, MethodType};
use regex::Regex;
use std::sync::OnceLock;
use anyhow::Result;

/// Vercel CDN detection provider
#[derive(Debug, Clone)]
pub struct VercelProvider {
    name: String,
    version: String,
    description: String,
    enabled: bool,
}

impl VercelProvider {
    pub fn new() -> Self {
        Self {
            name: "Vercel".to_string(),
            version: "1.0.0".to_string(),
            description: "Vercel Edge Network CDN detection provider".to_string(),
            enabled: true,
        }
    }

    // Pre-compiled regex patterns for performance
    fn vercel_id_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"^[a-z0-9]+::[a-z0-9-]+-[0-9]+-[a-f0-9]+$").unwrap())
    }

    fn vercel_cache_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"(?i)^(HIT|MISS|BYPASS|STALE)$").unwrap())
    }

    async fn check_headers(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check for Vercel server header (most definitive)
        if let Some(server) = response.headers.get("server") {
            if server.eq_ignore_ascii_case("vercel") {
                evidence.push(Evidence {
                    method_type: MethodType::Header("server".to_string()),
                    confidence: 0.98,
                    description: "Vercel server header detected".to_string(),
                    raw_data: server.clone(),
                    signature_matched: "vercel-server-pattern".to_string(),
                });
            }
        }

        // Check for Vercel ID header (very strong indicator)
        if let Some(vercel_id) = response.headers.get("x-vercel-id") {
            if Self::vercel_id_pattern().is_match(vercel_id) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-vercel-id".to_string()),
                    confidence: 0.95,
                    description: "Vercel request ID header detected".to_string(),
                    raw_data: vercel_id.clone(),
                    signature_matched: "vercel-id-pattern".to_string(),
                });
            }
        }

        // Check for Vercel cache status header
        if let Some(cache) = response.headers.get("x-vercel-cache") {
            if Self::vercel_cache_pattern().is_match(cache) {
                evidence.push(Evidence {
                    method_type: MethodType::Header("x-vercel-cache".to_string()),
                    confidence: 0.90,
                    description: "Vercel cache status header detected".to_string(),
                    raw_data: cache.clone(),
                    signature_matched: "vercel-cache-pattern".to_string(),
                });
            }
        }

        // Check for Vercel deployment headers
        if let Some(deployment) = response.headers.get("x-vercel-deployment-url") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-vercel-deployment-url".to_string()),
                confidence: 0.85,
                description: "Vercel deployment URL header detected".to_string(),
                raw_data: deployment.clone(),
                signature_matched: "vercel-deployment-pattern".to_string(),
            });
        }

        // Check for Vercel region header
        if let Some(region) = response.headers.get("x-vercel-region") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-vercel-region".to_string()),
                confidence: 0.75,
                description: "Vercel region header detected".to_string(),
                raw_data: region.clone(),
                signature_matched: "vercel-region-pattern".to_string(),
            });
        }

        // Check for Vercel proxy headers
        if let Some(proxy) = response.headers.get("x-vercel-proxy-signature") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-vercel-proxy-signature".to_string()),
                confidence: 0.80,
                description: "Vercel proxy signature header detected".to_string(),
                raw_data: proxy.clone(),
                signature_matched: "vercel-proxy-pattern".to_string(),
            });
        }

        // Check for Vercel edge headers
        if let Some(edge) = response.headers.get("x-vercel-edge") {
            evidence.push(Evidence {
                method_type: MethodType::Header("x-vercel-edge".to_string()),
                confidence: 0.70,
                description: "Vercel edge header detected".to_string(),
                raw_data: edge.clone(),
                signature_matched: "vercel-edge-pattern".to_string(),
            });
        }

        // Check for common Vercel domain patterns in headers
        for (header_name, header_value) in &response.headers {
            if header_value.contains("vercel.app") || header_value.contains("vercel.com") {
                evidence.push(Evidence {
                    method_type: MethodType::Header(header_name.clone()),
                    confidence: 0.65,
                    description: format!("Vercel domain reference in {} header", header_name),
                    raw_data: header_value.clone(),
                    signature_matched: "vercel-domain-pattern".to_string(),
                });
            }
        }

        evidence
    }

    async fn check_status_codes(&self, response: &crate::http::HttpResponse) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Vercel-specific status code patterns
        match response.status {
            404 => {
                // Check if it's a Vercel 404 with specific headers
                if response.headers.get("x-vercel-id").is_some() {
                    evidence.push(Evidence {
                        method_type: MethodType::StatusCode(404),
                        confidence: 0.75,
                        description: "Vercel 404 Not Found response".to_string(),
                        raw_data: "404".to_string(),
                        signature_matched: "vercel-404-pattern".to_string(),
                    });
                }
            }
            _ => {}
        }

        evidence
    }
}

#[async_trait::async_trait]
impl DetectionProvider for VercelProvider {
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
        ProviderType::CDN  // Vercel provides CDN/Edge services, not traditional WAF
    }

    fn confidence_base(&self) -> f64 {
        0.85
    }

    fn priority(&self) -> u32 {
        90
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    async fn detect(&self, context: &DetectionContext) -> Result<Vec<Evidence>> {
        let mut evidence = Vec::new();

        if let Some(response) = &context.response {
            evidence.extend(self.check_headers(response).await);
            evidence.extend(self.check_status_codes(response).await);
        }

        Ok(evidence)
    }

    async fn passive_detect(&self, response: &crate::http::HttpResponse) -> Result<Vec<Evidence>> {
        let mut evidence = Vec::new();
        evidence.extend(self.check_headers(response).await);
        evidence.extend(self.check_status_codes(response).await);
        Ok(evidence)
    }

    async fn active_detect(&self, _client: &crate::http::HttpClient, _url: &str) -> Result<Vec<Evidence>> {
        // Vercel doesn't require active detection - all evidence is in headers
        Ok(vec![])
    }


}

impl Default for VercelProvider {
    fn default() -> Self {
        Self::new()
    }
} 