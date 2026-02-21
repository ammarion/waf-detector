//! DNS analysis for WAF/CDN detection
//!
//! Provides definitive provider identification through CNAME record analysis.
//! DNS records directly reveal the infrastructure being used.

pub mod optimized;

use crate::{DnsInfo, Evidence, MethodType};
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// DNS analyzer with provider pattern matching
#[derive(Debug)]
pub struct DnsAnalyzer {
    provider_patterns: HashMap<String, Vec<DnsPattern>>,
}

/// DNS pattern for provider identification
#[derive(Debug, Clone)]
pub struct DnsPattern {
    pub pattern_name: &'static str,
    pub confidence: f64,
    pub description: String,
}

fn get_dns_regex(pattern_name: &str) -> &'static Regex {
    match pattern_name {
        "cloudflare_net" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.cloudflare\.net$").unwrap())
        }
        "cloudflaressl_com" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.cloudflaressl\.com$").unwrap())
        }
        "cf_dns_com" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.cf-dns\.com$").unwrap())
        }
        "cloudfront_net" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.cloudfront\.net$").unwrap())
        }
        "cloudfront_dist" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r"d[0-9a-z]+\.cloudfront\.net$").unwrap())
        }
        "amazonaws_com" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.amazonaws\.com$").unwrap())
        }
        "fastly_com" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.fastly\.com$").unwrap())
        }
        "fastlylb_net" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.fastlylb\.net$").unwrap())
        }
        "global_fastly_net" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.global\.fastly\.net$").unwrap())
        }
        "akamai_net" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.akamai\.net$").unwrap())
        }
        "akamaized_net" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.akamaized\.net$").unwrap())
        }
        "akamaihd_net" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.akamaihd\.net$").unwrap())
        }
        "edgesuite_net" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.edgesuite\.net$").unwrap())
        }
        "vercel_app" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.vercel\.app$").unwrap())
        }
        "vercel_dns_com" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.vercel-dns\.com$").unwrap())
        }
        "keycdn_com" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.keycdn\.com$").unwrap())
        }
        "maxcdn_com" => {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new(r".*\.maxcdn\.com$").unwrap())
        }
        _ => panic!("Unknown DNS regex pattern name: {}", pattern_name),
    }
}

impl DnsAnalyzer {
    pub fn new() -> Self {
        let mut provider_patterns = HashMap::new();

        // CloudFlare CNAME patterns
        provider_patterns.insert(
            "CloudFlare".to_string(),
            vec![
                DnsPattern {
                    pattern_name: "cloudflare_net",
                    confidence: 0.98,
                    description: "CloudFlare CDN CNAME record".to_string(),
                },
                DnsPattern {
                    pattern_name: "cloudflaressl_com",
                    confidence: 0.95,
                    description: "CloudFlare SSL CNAME record".to_string(),
                },
                DnsPattern {
                    pattern_name: "cf_dns_com",
                    confidence: 0.90,
                    description: "CloudFlare DNS CNAME record".to_string(),
                },
            ],
        );

        // AWS CloudFront patterns
        provider_patterns.insert(
            "AWS".to_string(),
            vec![
                DnsPattern {
                    pattern_name: "cloudfront_net",
                    confidence: 0.98,
                    description: "AWS CloudFront CNAME record".to_string(),
                },
                DnsPattern {
                    pattern_name: "cloudfront_dist",
                    confidence: 0.99,
                    description: "AWS CloudFront distribution CNAME".to_string(),
                },
                DnsPattern {
                    pattern_name: "amazonaws_com",
                    confidence: 0.95,
                    description: "AWS service CNAME record".to_string(),
                },
            ],
        );

        // Fastly patterns
        provider_patterns.insert(
            "Fastly".to_string(),
            vec![
                DnsPattern {
                    pattern_name: "fastly_com",
                    confidence: 0.98,
                    description: "Fastly CDN CNAME record".to_string(),
                },
                DnsPattern {
                    pattern_name: "fastlylb_net",
                    confidence: 0.95,
                    description: "Fastly load balancer CNAME".to_string(),
                },
                DnsPattern {
                    pattern_name: "global_fastly_net",
                    confidence: 0.96,
                    description: "Fastly global network CNAME".to_string(),
                },
            ],
        );

        // Akamai patterns
        provider_patterns.insert(
            "Akamai".to_string(),
            vec![
                DnsPattern {
                    pattern_name: "akamai_net",
                    confidence: 0.98,
                    description: "Akamai CDN CNAME record".to_string(),
                },
                DnsPattern {
                    pattern_name: "akamaized_net",
                    confidence: 0.95,
                    description: "Akamai edge network CNAME".to_string(),
                },
                DnsPattern {
                    pattern_name: "akamaihd_net",
                    confidence: 0.96,
                    description: "Akamai HD network CNAME".to_string(),
                },
                DnsPattern {
                    pattern_name: "edgesuite_net",
                    confidence: 0.94,
                    description: "Akamai EdgeSuite CNAME".to_string(),
                },
            ],
        );

        // Vercel patterns
        provider_patterns.insert(
            "Vercel".to_string(),
            vec![
                DnsPattern {
                    pattern_name: "vercel_app",
                    confidence: 0.99,
                    description: "Vercel deployment CNAME".to_string(),
                },
                DnsPattern {
                    pattern_name: "vercel_dns_com",
                    confidence: 0.96,
                    description: "Vercel DNS CNAME record".to_string(),
                },
            ],
        );

        // Additional common CDN patterns
        provider_patterns.insert(
            "KeyCDN".to_string(),
            vec![DnsPattern {
                pattern_name: "keycdn_com",
                confidence: 0.98,
                description: "KeyCDN CNAME record".to_string(),
            }],
        );

        provider_patterns.insert(
            "MaxCDN".to_string(),
            vec![DnsPattern {
                pattern_name: "maxcdn_com",
                confidence: 0.98,
                description: "MaxCDN CNAME record".to_string(),
            }],
        );

        Self { provider_patterns }
    }

    /// Perform analysis on already resolved DnsInfo
    pub fn analyze_from_info(&self, dns_info: &DnsInfo) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check CNAME records
        for cname in &dns_info.cnames {
            for (provider, patterns) in &self.provider_patterns {
                for pattern in patterns {
                    let regex = get_dns_regex(pattern.pattern_name);
                    if regex.is_match(cname) {
                        evidence.push(Evidence {
                            method_type: MethodType::DNS("cname".to_string()),
                            confidence: pattern.confidence,
                            description: format!(
                                "{} - {} detected via CNAME record: {}",
                                pattern.description, provider, cname
                            ),
                            raw_data: format!("CNAME -> {cname}"),
                            signature_matched: format!("dns-cname-{}", provider.to_lowercase()),
                        });
                    }
                }
            }
        }

        // Check NS records (often useful for DNS providers like Cloudflare)
        for ns in &dns_info.ns_records {
            for (provider, patterns) in &self.provider_patterns {
                for pattern in patterns {
                    let regex = get_dns_regex(pattern.pattern_name);
                    if regex.is_match(ns) {
                        evidence.push(Evidence {
                            method_type: MethodType::DNS("ns".to_string()),
                            confidence: pattern.confidence * 0.9, // Slightly lower confidence for NS than CNAME
                            description: format!(
                                "{} - {} detected via NS record: {}",
                                pattern.description, provider, ns
                            ),
                            raw_data: format!("NS -> {ns}"),
                            signature_matched: format!("dns-ns-{}", provider.to_lowercase()),
                        });
                    }
                }
            }
        }

        evidence
    }

    /// Extract clean domain from URL
    pub fn extract_domain(&self, url: &str) -> String {
        let url = url.trim();

        // Remove protocol
        let without_protocol = if url.contains("://") {
            url.split("://").nth(1).unwrap_or(url)
        } else {
            url
        };

        // Remove path, query, and fragment
        let domain_part = without_protocol
            .split('/')
            .next()
            .unwrap_or(without_protocol)
            .split('?')
            .next()
            .unwrap_or(without_protocol)
            .split('#')
            .next()
            .unwrap_or(without_protocol);

        // Remove port
        if let Some(colon_pos) = domain_part.rfind(':') {
            // Check if it's likely a port (numeric after colon)
            let after_colon = &domain_part[colon_pos + 1..];
            if after_colon.chars().all(|c| c.is_ascii_digit()) {
                return domain_part[..colon_pos].to_string();
            }
        }

        domain_part.to_string()
    }

    /// Get all supported providers and their patterns
    pub fn get_supported_providers(&self) -> Vec<String> {
        self.provider_patterns.keys().cloned().collect()
    }
}

impl Default for DnsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_analyzer_creation() {
        let analyzer = DnsAnalyzer::new();
        assert!(!analyzer.provider_patterns.is_empty());
        assert!(analyzer.provider_patterns.contains_key("CloudFlare"));
        assert!(analyzer.provider_patterns.contains_key("AWS"));
    }

    #[test]
    fn test_extract_domain() {
        let analyzer = DnsAnalyzer::new();

        assert_eq!(
            analyzer.extract_domain("https://example.com"),
            "example.com"
        );
        assert_eq!(
            analyzer.extract_domain("http://example.com/path"),
            "example.com"
        );
        assert_eq!(analyzer.extract_domain("example.com"), "example.com");
        assert_eq!(analyzer.extract_domain("example.com:8080"), "example.com");
        assert_eq!(
            analyzer.extract_domain("https://example.com:443/path?query=1"),
            "example.com"
        );
        assert_eq!(
            analyzer.extract_domain("subdomain.example.com"),
            "subdomain.example.com"
        );
    }

    #[test]
    fn test_provider_patterns() {
        let analyzer = DnsAnalyzer::new();

        // Test CloudFlare patterns
        let cf_patterns = analyzer.provider_patterns.get("CloudFlare").unwrap();
        assert!(cf_patterns
            .iter()
            .any(|p| get_dns_regex(p.pattern_name).is_match("target.cloudflare.net")));
        assert!(cf_patterns
            .iter()
            .any(|p| get_dns_regex(p.pattern_name).is_match("ssl.cloudflaressl.com")));

        // Test AWS patterns
        let aws_patterns = analyzer.provider_patterns.get("AWS").unwrap();
        assert!(aws_patterns
            .iter()
            .any(|p| get_dns_regex(p.pattern_name).is_match("d123abc.cloudfront.net")));
        assert!(aws_patterns
            .iter()
            .any(|p| get_dns_regex(p.pattern_name).is_match("example.amazonaws.com")));

        // Test Fastly patterns
        let fastly_patterns = analyzer.provider_patterns.get("Fastly").unwrap();
        assert!(fastly_patterns
            .iter()
            .any(|p| get_dns_regex(p.pattern_name).is_match("target.fastly.com")));

        // Test Akamai patterns
        let akamai_patterns = analyzer.provider_patterns.get("Akamai").unwrap();
        assert!(akamai_patterns
            .iter()
            .any(|p| get_dns_regex(p.pattern_name).is_match("target.akamai.net")));
        assert!(akamai_patterns
            .iter()
            .any(|p| get_dns_regex(p.pattern_name).is_match("target.edgesuite.net")));
    }

    #[test]
    fn test_confidence_levels() {
        let analyzer = DnsAnalyzer::new();
        // CloudFlare main pattern should have high confidence
        let cf_patterns = analyzer.provider_patterns.get("CloudFlare").unwrap();
        let main_pattern = cf_patterns
            .iter()
            .find(|p| {
                get_dns_regex(p.pattern_name)
                    .to_string()
                    .contains("cloudflare")
            })
            .unwrap();
        assert!(
            main_pattern.confidence >= 0.95,
            "CloudFlare confidence was {}",
            main_pattern.confidence
        );
        // AWS CloudFront distribution pattern should have very high confidence
        let aws_patterns = analyzer.provider_patterns.get("AWS").unwrap();
        let dist_pattern = aws_patterns
            .iter()
            .find(|p| {
                get_dns_regex(p.pattern_name)
                    .to_string()
                    .contains("cloudfront")
            })
            .unwrap();
        assert!(
            dist_pattern.confidence >= 0.95,
            "AWS CloudFront confidence was {}",
            dist_pattern.confidence
        );
    }

    #[test]
    fn test_get_supported_providers() {
        let analyzer = DnsAnalyzer::new();
        let providers = analyzer.get_supported_providers();

        assert!(providers.contains(&"CloudFlare".to_string()));
        assert!(providers.contains(&"AWS".to_string()));
        assert!(providers.contains(&"Fastly".to_string()));
        assert!(providers.contains(&"Akamai".to_string()));
        assert!(providers.contains(&"Vercel".to_string()));
    }

    #[test]
    fn test_dns_analysis() {
        let analyzer = DnsAnalyzer::new();

        // Should catch Optimizely if we had it, but for now test known ones
        let info_cf = DnsInfo {
            cnames: vec!["something.cdn.cloudflare.net".to_string()],
            ..Default::default()
        };

        let evidence = analyzer.analyze_from_info(&info_cf);
        assert!(!evidence.is_empty());
        assert!(evidence[0].description.contains("CloudFlare"));
    }
}
