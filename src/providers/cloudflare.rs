//! CloudFlare WAF/CDN Detection Provider

use crate::{DetectionContext, DetectionProvider, Evidence, MethodType, ProviderType};
use anyhow::Result;
use regex::Regex;
use std::sync::OnceLock;

/// CloudFlare detection provider
#[derive(Debug, Clone)]
pub struct CloudFlareProvider {
    name: String,
    version: String,
    description: String,
    enabled: bool,
}

impl CloudFlareProvider {
    /// CloudFlare signals that indicate its security layer is engaged, as
    /// distinct from `cf-ray`/`server: cloudflare`, which only say traffic is
    /// proxied through CloudFlare.
    ///
    /// Two different claims, deliberately kept apart:
    ///
    /// - `__cf_bm` is set on ordinary requests whenever Bot Management or Bot
    ///   Fight Mode is enabled, *whether or not* any challenge or block
    ///   occurs. That makes it one of the few signals that survives a WAF
    ///   configured to log rather than act. It does not establish that
    ///   CloudFlare's WAF managed rules are enabled, nor their mode --
    ///   `DetectionResult::generate_caveats` attaches that qualification.
    /// - `cf-mitigated` appears when CloudFlare actually acted on the request
    ///   (e.g. `cf-mitigated: challenge`). That is evidence of *enforcement*,
    ///   not merely of presence, so it is described as such.
    pub fn check_security_module_signals(
        &self,
        response: &crate::http::HttpResponse,
    ) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        if let Some(raw) = response.headers.get("set-cookie") {
            if raw.to_ascii_lowercase().contains("__cf_bm=") {
                evidence.push(Evidence {
                    method_type: MethodType::Header("set-cookie".to_string()),
                    confidence: 0.90,
                    description: "CloudFlare Bot Management cookie '__cf_bm' — CloudFlare's \
                                  security layer is handling this request, and sets this whether \
                                  or not it challenges or blocks. Does not establish that the \
                                  WAF managed rules are enabled or which mode they are in."
                        .to_string(),
                    raw_data: "__cf_bm".to_string(),
                    signature_matched: "cloudflare-bot-management-cookie".to_string(),
                });
            }
        }

        if let Some(mitigated) = response.headers.get("cf-mitigated") {
            evidence.push(Evidence {
                method_type: MethodType::Header("cf-mitigated".to_string()),
                confidence: 0.95,
                description: format!(
                    "CloudFlare cf-mitigated: {mitigated} — CloudFlare took action on this \
                     request. This is evidence of active enforcement, not merely presence."
                ),
                raw_data: mitigated.clone(),
                signature_matched: "cloudflare-mitigated-header".to_string(),
            });
        }

        evidence
    }

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
        PATTERN.get_or_init(|| {
            Regex::new(r"(?i)(HIT|MISS|EXPIRED|BYPASS|DYNAMIC|REVALIDATED)").unwrap()
        })
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
        PATTERN.get_or_init(|| {
            Regex::new(r"(?i)(cf_chl_jschl_tk|cf_clearance|cf_chl_captcha_tk)").unwrap()
        })
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
            (
                "cf-connecting-ip",
                "CloudFlare connecting IP header",
                0.80,
                "cf-connecting-ip-header",
            ),
            (
                "cf-ipcountry",
                "CloudFlare IP country header",
                0.75,
                "cf-ipcountry-header",
            ),
            (
                "cf-visitor",
                "CloudFlare visitor header",
                0.75,
                "cf-visitor-header",
            ),
            (
                "cf-request-id",
                "CloudFlare request ID header",
                0.85,
                "cf-request-id-header",
            ),
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
                if response.headers.contains_key("cf-ray")
                    || Self::cf_challenge_pattern().is_match(&response.body)
                {
                    evidence.push(Evidence {
                        method_type: MethodType::StatusCode(403),
                        confidence: 0.75,
                        description: "CloudFlare 403 Forbidden response".to_string(),
                        raw_data: "403".to_string(),
                        signature_matched: "cf-403-status".to_string(),
                    });
                }
            }
            // CloudFlare rate limiting, confirmed by the cf-ray header
            429 if response.headers.contains_key("cf-ray") => {
                evidence.push(Evidence {
                    method_type: MethodType::StatusCode(429),
                    confidence: 0.80,
                    description: "CloudFlare rate limiting detected".to_string(),
                    raw_data: "429".to_string(),
                    signature_matched: "cf-429-status".to_string(),
                });
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
        // Delegates to `passive_detect` rather than repeating its checks.
        //
        // These two used to run the same three checks side by side, and the
        // registry calls `detect`, not `passive_detect`. That meant a check
        // added to only one of them compiled, passed its unit tests, and then
        // silently never ran against a live target -- which is exactly what
        // happened when the security-module cookie check was added below.
        let mut all_evidence = Vec::new();

        if let Some(response) = &context.response {
            all_evidence.extend(self.passive_detect(response).await?);
        }

        Ok(all_evidence)
    }

    async fn passive_detect(&self, response: &crate::http::HttpResponse) -> Result<Vec<Evidence>> {
        let mut all_evidence = Vec::new();

        all_evidence.extend(self.check_headers(response).await);
        all_evidence.extend(self.check_security_module_signals(response));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::test_utils::mock_response;

    #[tokio::test]
    async fn detects_cf_bm_cookie_without_any_block() {
        // A plain 200 with no challenge and nothing blocked, but CloudFlare's
        // bot layer has stamped the response -- which it does regardless of
        // whether it acts.
        let provider = CloudFlareProvider::new();
        let response = mock_response(
            200,
            [(
                "set-cookie",
                "__cf_bm=abc123def456; path=/; HttpOnly; Secure",
            )],
            "<html>ordinary page</html>",
        );
        let evidence = provider.passive_detect(&response).await.unwrap();
        let bm: Vec<_> = evidence
            .iter()
            .filter(|e| e.signature_matched == "cloudflare-bot-management-cookie")
            .collect();
        assert_eq!(bm.len(), 1);
        assert!(
            bm[0].description.contains("managed rules"),
            "evidence must state the WAF ruleset is not established: {}",
            bm[0].description
        );
    }

    #[tokio::test]
    async fn cf_mitigated_header_is_reported_as_enforcement_not_presence() {
        let provider = CloudFlareProvider::new();
        let response = mock_response(200, [("cf-mitigated", "challenge")], "");
        let evidence = provider.passive_detect(&response).await.unwrap();
        let hit = evidence
            .iter()
            .find(|e| e.signature_matched == "cloudflare-mitigated-header")
            .expect("expected cf-mitigated evidence");
        assert!(
            hit.description.contains("active enforcement"),
            "cf-mitigated means CloudFlare acted, and must be described that way: {}",
            hit.description
        );
    }

    #[tokio::test]
    async fn cf_ray_alone_is_not_bot_management_evidence() {
        // cf-ray proves traffic is proxied through CloudFlare, nothing more.
        // It must not be conflated with the security layer being engaged.
        let provider = CloudFlareProvider::new();
        let response = mock_response(
            200,
            [("cf-ray", "7d4f8a1b2c3d4e5f-SJC"), ("server", "cloudflare")],
            "",
        );
        let evidence = provider.passive_detect(&response).await.unwrap();
        assert!(!evidence.iter().any(|e| {
            e.signature_matched == "cloudflare-bot-management-cookie"
                || e.signature_matched == "cloudflare-mitigated-header"
        }));
        assert!(
            !evidence.is_empty(),
            "cf-ray should still identify CloudFlare"
        );
    }

    #[tokio::test]
    async fn detects_cf_ray_header() {
        let provider = CloudFlareProvider::new();
        let response = mock_response(
            200,
            [("cf-ray", "8a1b2c3d4e5f-SFO"), ("cf-cache-status", "HIT")],
            "",
        );
        let evidence = provider.passive_detect(&response).await.unwrap();
        assert!(!evidence.is_empty());
        assert!(evidence
            .iter()
            .any(|e| e.signature_matched == "cf-ray-header"));
    }

    #[tokio::test]
    async fn detects_cf_cache_status() {
        let provider = CloudFlareProvider::new();
        let response = mock_response(200, [("cf-cache-status", "MISS")], "");
        let evidence = provider.passive_detect(&response).await.unwrap();
        assert!(evidence
            .iter()
            .any(|e| e.signature_matched == "cf-cache-status-header"));
    }

    #[tokio::test]
    async fn no_evidence_without_cf_headers() {
        let provider = CloudFlareProvider::new();
        let response = mock_response(200, [("server", "nginx")], "");
        let evidence = provider.passive_detect(&response).await.unwrap();
        assert!(evidence.is_empty());
    }
}
