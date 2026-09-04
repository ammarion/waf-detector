//! Connection Behavior Analysis for WAF/CDN Fingerprinting
//!
//! Measures connection-level characteristics that differ between providers:
//! - Server-Timing headers (CloudFlare cfRequestDuration, Fastly patterns)
//! - Connection and Keep-Alive header patterns
//! - Alt-Svc header (HTTP/3 support with provider-specific values)
//! - Via header patterns (CDN hop signatures)
//!
//! **IMPORTANT**: This module analyzes EXISTING response headers from the DetectionContext.
//! It does NOT make additional HTTP requests, keeping it fast and non-intrusive.

use crate::{Evidence, MethodType};
use std::collections::HashMap;
use std::time::Duration;

/// Connection behavior profile for a provider
#[derive(Debug, Clone)]
pub struct ConnectionProfile {
    pub provider: String,
    pub expected_ttfb_range: (Duration, Duration), // (min, max) typical TTFB
    pub keep_alive_pattern: Option<String>,        // Expected keep-alive header pattern
    pub connection_pattern: Option<String>,        // Expected connection header
    pub server_timing_pattern: Option<String>,     // Server-Timing header pattern
    pub alt_svc_pattern: Option<String>,           // Alt-Svc header pattern
    pub via_pattern: Option<String>,               // Via header pattern
    pub confidence: f64,
}

/// Measured connection behavior from existing response headers
#[derive(Debug, Clone)]
pub struct ConnectionBehavior {
    pub keep_alive_value: Option<String>,
    pub connection_value: Option<String>,
    pub server_timing: Option<String>,
    pub alt_svc: Option<String>,
    pub via: Option<String>,
}

#[derive(Debug)]
pub struct ConnectionBehaviorAnalyzer {
    profiles: Vec<ConnectionProfile>,
}

impl ConnectionBehaviorAnalyzer {
    pub fn new() -> Self {
        // Every pattern below must be *vendor-specific*. Matching is ANY-of,
        // so one shared string is enough to attribute a vendor on its own --
        // which is how `alt-svc: h3=` (the RFC 9114 HTTP/3 advertisement, sent
        // by every HTTP/3 server) scored CloudFlare 0.75 and Fastly 0.72 on an
        // Akamai host. `Connection: keep-alive` and `Keep-Alive: timeout=` were
        // on every profile and are just as universal. All three are now None.
        let profiles = vec![
            // CloudFlare: Distinctive server-timing and alt-svc patterns
            ConnectionProfile {
                provider: "CloudFlare".to_string(),
                expected_ttfb_range: (Duration::from_millis(5), Duration::from_millis(200)),
                keep_alive_pattern: None,
                connection_pattern: None,
                server_timing_pattern: Some("cfRequestDuration".to_string()),
                alt_svc_pattern: None,
                via_pattern: None,
                confidence: 0.75,
            },
            // AWS CloudFront: Via header with cloudfront signature
            ConnectionProfile {
                provider: "AWS".to_string(),
                expected_ttfb_range: (Duration::from_millis(10), Duration::from_millis(300)),
                keep_alive_pattern: None,
                connection_pattern: None,
                server_timing_pattern: None,
                alt_svc_pattern: None,
                via_pattern: Some("cloudfront".to_string()),
                confidence: 0.80,
            },
            // Akamai: `Server-Timing: ak_p` is the delivery-platform marker,
            // emitted by the edge itself rather than by Bot Manager, so it is
            // independent of both which modules are enabled and their mode.
            // Verified present on www.akamai.com and on other Akamai-fronted
            // properties, and absent from Cloudflare and Fastly edges. Distinct
            // from Fastly's own `Server-Timing` use, which carries different
            // tokens.
            ConnectionProfile {
                provider: "Akamai".to_string(),
                expected_ttfb_range: (Duration::from_millis(10), Duration::from_millis(250)),
                keep_alive_pattern: None,
                connection_pattern: None,
                server_timing_pattern: Some("ak_p".to_string()),
                alt_svc_pattern: None,
                via_pattern: Some("akamai".to_string()),
                confidence: 0.78,
            },
            // Fastly: Specific server-timing and alt-svc patterns
            ConnectionProfile {
                provider: "Fastly".to_string(),
                expected_ttfb_range: (Duration::from_millis(5), Duration::from_millis(200)),
                keep_alive_pattern: None,
                connection_pattern: None,
                server_timing_pattern: None,
                alt_svc_pattern: None,
                via_pattern: None,
                confidence: 0.72,
            },
            // Azure: Via header with Azure patterns
            ConnectionProfile {
                provider: "Azure".to_string(),
                expected_ttfb_range: (Duration::from_millis(10), Duration::from_millis(300)),
                keep_alive_pattern: None,
                connection_pattern: None,
                server_timing_pattern: None,
                alt_svc_pattern: None,
                via_pattern: Some("azure".to_string()),
                confidence: 0.75,
            },
        ];
        Self { profiles }
    }

    /// Analyze connection behavior from existing HTTP response headers
    /// This does NOT make additional requests - it analyzes headers from the response
    /// already captured in the DetectionContext
    pub fn analyze_response_headers(&self, headers: &HashMap<String, String>) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Extract connection behavior from existing headers
        let behavior = self.extract_behavior(headers);

        // Match against known provider profiles
        for profile in &self.profiles {
            let mut matches = Vec::new();

            // Check server-timing header pattern
            if let Some(ref pattern) = profile.server_timing_pattern {
                if let Some(ref server_timing) = behavior.server_timing {
                    if server_timing
                        .to_lowercase()
                        .contains(&pattern.to_lowercase())
                    {
                        matches.push(format!("server-timing pattern '{}'", pattern));
                    }
                }
            }

            // Check alt-svc header pattern (HTTP/3 support)
            if let Some(ref pattern) = profile.alt_svc_pattern {
                if let Some(ref alt_svc) = behavior.alt_svc {
                    if alt_svc.to_lowercase().contains(&pattern.to_lowercase()) {
                        matches.push(format!("alt-svc pattern '{}'", pattern));
                    }
                }
            }

            // Check via header pattern (CDN hop signatures)
            if let Some(ref pattern) = profile.via_pattern {
                if let Some(ref via) = behavior.via {
                    if via.to_lowercase().contains(&pattern.to_lowercase()) {
                        matches.push(format!("via header pattern '{}'", pattern));
                    }
                }
            }

            // Check keep-alive pattern
            if let Some(ref pattern) = profile.keep_alive_pattern {
                if let Some(ref keep_alive) = behavior.keep_alive_value {
                    if keep_alive.to_lowercase().contains(&pattern.to_lowercase()) {
                        matches.push(format!("keep-alive pattern '{}'", pattern));
                    }
                }
            }

            // Check connection pattern
            if let Some(ref pattern) = profile.connection_pattern {
                if let Some(ref connection) = behavior.connection_value {
                    if connection.to_lowercase().contains(&pattern.to_lowercase()) {
                        matches.push(format!("connection pattern '{}'", pattern));
                    }
                }
            }

            // If we have at least one strong match (server-timing, via, or alt-svc), create evidence
            // These are more distinctive than generic keep-alive/connection patterns
            let strong_match = matches.iter().any(|m| {
                m.contains("server-timing") || m.contains("via header") || m.contains("alt-svc")
            });

            if strong_match || matches.len() >= 2 {
                // Calculate confidence based on number and quality of matches
                let confidence = if strong_match {
                    profile.confidence
                } else {
                    profile.confidence * 0.7 // Lower confidence for weak patterns only
                };

                evidence.push(Evidence {
                    method_type: MethodType::Header("connection-behavior".to_string()),
                    confidence,
                    description: format!(
                        "{} connection behavior detected: {}",
                        profile.provider,
                        matches.join(", ")
                    ),
                    raw_data: format!(
                        "keep-alive: {:?}, connection: {:?}, server-timing: {:?}, alt-svc: {:?}, via: {:?}",
                        behavior.keep_alive_value,
                        behavior.connection_value,
                        behavior.server_timing,
                        behavior.alt_svc,
                        behavior.via
                    ),
                    signature_matched: format!(
                        "connection-behavior-{}",
                        profile.provider.to_lowercase()
                    ),
                });
            }
        }

        evidence
    }

    /// Extract connection behavior from HTTP headers
    fn extract_behavior(&self, headers: &HashMap<String, String>) -> ConnectionBehavior {
        let mut keep_alive_value = None;
        let mut connection_value = None;
        let mut server_timing = None;
        let mut alt_svc = None;
        let mut via = None;

        // Case-insensitive header lookup
        for (key, value) in headers {
            let key_lower = key.to_lowercase();
            match key_lower.as_str() {
                "keep-alive" => keep_alive_value = Some(value.clone()),
                "connection" => connection_value = Some(value.clone()),
                "server-timing" => server_timing = Some(value.clone()),
                "alt-svc" => alt_svc = Some(value.clone()),
                "via" => via = Some(value.clone()),
                _ => {}
            }
        }

        ConnectionBehavior {
            keep_alive_value,
            connection_value,
            server_timing,
            alt_svc,
            via,
        }
    }
}

impl Default for ConnectionBehaviorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_server_timing_detection() {
        let analyzer = ConnectionBehaviorAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert(
            "server-timing".to_string(),
            "cfRequestDuration;dur=123.45".to_string(),
        );
        headers.insert("alt-svc".to_string(), "h3=\":443\"".to_string());
        headers.insert("keep-alive".to_string(), "timeout=5".to_string());

        let evidence = analyzer.analyze_response_headers(&headers);

        assert!(!evidence.is_empty());
        let cloudflare_evidence = evidence
            .iter()
            .find(|e| e.signature_matched == "connection-behavior-cloudflare");
        assert!(cloudflare_evidence.is_some());

        let ev = cloudflare_evidence.unwrap();
        assert!(ev.confidence >= 0.70);
        assert!(ev
            .description
            .contains("CloudFlare connection behavior detected"));
    }

    #[test]
    fn test_aws_cloudfront_via_detection() {
        let analyzer = ConnectionBehaviorAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert(
            "via".to_string(),
            "1.1 cloudfront.net (CloudFront)".to_string(),
        );
        headers.insert("keep-alive".to_string(), "timeout=10".to_string());

        let evidence = analyzer.analyze_response_headers(&headers);

        assert!(!evidence.is_empty());
        let aws_evidence = evidence
            .iter()
            .find(|e| e.signature_matched == "connection-behavior-aws");
        assert!(aws_evidence.is_some());

        let ev = aws_evidence.unwrap();
        assert!(ev.confidence >= 0.70);
        assert!(ev.description.contains("AWS connection behavior detected"));
    }

    #[test]
    fn test_akamai_via_detection() {
        let analyzer = ConnectionBehaviorAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert(
            "via".to_string(),
            "1.1 akamai.net (ghost) (AkamaiGHost)".to_string(),
        );
        headers.insert("connection".to_string(), "keep-alive".to_string());

        let evidence = analyzer.analyze_response_headers(&headers);

        assert!(!evidence.is_empty());
        let akamai_evidence = evidence
            .iter()
            .find(|e| e.signature_matched == "connection-behavior-akamai");
        assert!(akamai_evidence.is_some());
    }

    #[test]
    fn test_no_match_for_generic_headers() {
        let analyzer = ConnectionBehaviorAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert("connection".to_string(), "keep-alive".to_string());
        headers.insert("keep-alive".to_string(), "timeout=5".to_string());

        let evidence = analyzer.analyze_response_headers(&headers);

        // Generic keep-alive + connection without distinctive patterns should not match
        // unless we have 2+ matches including strong signals
        assert!(
            evidence.is_empty() || evidence.iter().all(|e| e.confidence < 0.70),
            "Generic patterns without strong signals should not produce high-confidence evidence"
        );
    }

    #[test]
    fn test_case_insensitive_header_matching() {
        let analyzer = ConnectionBehaviorAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert(
            "Server-Timing".to_string(),
            "cfRequestDuration;dur=100".to_string(),
        );
        headers.insert("Alt-Svc".to_string(), "h3=\":443\"".to_string());

        let evidence = analyzer.analyze_response_headers(&headers);

        assert!(!evidence.is_empty());
        let cloudflare_evidence = evidence
            .iter()
            .find(|e| e.signature_matched == "connection-behavior-cloudflare");
        assert!(cloudflare_evidence.is_some());
    }

    #[test]
    fn test_azure_via_detection() {
        let analyzer = ConnectionBehaviorAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert("via".to_string(), "1.1 Azure-Edge".to_string());
        headers.insert("connection".to_string(), "keep-alive".to_string());

        let evidence = analyzer.analyze_response_headers(&headers);

        assert!(!evidence.is_empty());
        let azure_evidence = evidence
            .iter()
            .find(|e| e.signature_matched == "connection-behavior-azure");
        assert!(azure_evidence.is_some());
    }

    #[test]
    fn test_empty_headers() {
        let analyzer = ConnectionBehaviorAnalyzer::new();
        let headers = HashMap::new();

        let evidence = analyzer.analyze_response_headers(&headers);

        assert!(
            evidence.is_empty(),
            "Empty headers should produce no evidence"
        );
    }

    #[test]
    fn test_extract_behavior() {
        let analyzer = ConnectionBehaviorAnalyzer::new();
        let mut headers = HashMap::new();
        headers.insert("keep-alive".to_string(), "timeout=5".to_string());
        headers.insert("connection".to_string(), "keep-alive".to_string());
        headers.insert(
            "server-timing".to_string(),
            "cfRequestDuration;dur=100".to_string(),
        );

        let behavior = analyzer.extract_behavior(&headers);

        assert_eq!(behavior.keep_alive_value, Some("timeout=5".to_string()));
        assert_eq!(behavior.connection_value, Some("keep-alive".to_string()));
        assert_eq!(
            behavior.server_timing,
            Some("cfRequestDuration;dur=100".to_string())
        );
        assert_eq!(behavior.alt_svc, None);
        assert_eq!(behavior.via, None);
    }
}
