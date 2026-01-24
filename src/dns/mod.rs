//! DNS analysis for WAF/CDN detection
//!
//! Provides definitive provider identification through CNAME record analysis.
//! DNS records directly reveal the infrastructure being used.

pub mod optimized;

use crate::{DnsInfo, Evidence, MethodType};
use regex::Regex;
use std::collections::HashMap;

/// DNS analyzer with provider pattern matching
#[derive(Debug)]
pub struct DnsAnalyzer {
    provider_patterns: HashMap<String, Vec<DnsPattern>>,
}

/// DNS pattern for provider identification
#[derive(Debug, Clone)]
pub struct DnsPattern {
    pub pattern: Regex,
    pub confidence: f64,
    pub description: String,
}

impl DnsAnalyzer {
    pub fn new() -> Self {
        // Use a static map to only compile regexes once
        use std::sync::OnceLock;
        static PATTERNS: OnceLock<HashMap<String, Vec<DnsPattern>>> = OnceLock::new();

        let provider_patterns = PATTERNS.get_or_init(|| {
            let mut p = HashMap::new();

            // CloudFlare CNAME patterns
            p.insert(
                "CloudFlare".to_string(),
                vec![
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.cloudflare\.net$").unwrap(),
                        confidence: 0.98,
                        description: "CloudFlare CDN CNAME record".to_string(),
                    },
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.cloudflaressl\.com$").unwrap(),
                        confidence: 0.95,
                        description: "CloudFlare SSL CNAME record".to_string(),
                    },
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.cf-dns\.com$").unwrap(),
                        confidence: 0.90,
                        description: "CloudFlare DNS CNAME record".to_string(),
                    },
                ],
            );

            // AWS CloudFront patterns
            p.insert(
                "AWS".to_string(),
                vec![
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.cloudfront\.net$").unwrap(),
                        confidence: 0.98,
                        description: "AWS CloudFront CNAME record".to_string(),
                    },
                    DnsPattern {
                        pattern: Regex::new(r"(?i)d[0-9a-z]+\.cloudfront\.net$").unwrap(),
                        confidence: 0.99,
                        description: "AWS CloudFront distribution CNAME".to_string(),
                    },
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.amazonaws\.com$").unwrap(),
                        confidence: 0.95,
                        description: "AWS service CNAME record".to_string(),
                    },
                ],
            );

            // Fastly patterns
            p.insert(
                "Fastly".to_string(),
                vec![
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.fastly\.com$").unwrap(),
                        confidence: 0.98,
                        description: "Fastly CDN CNAME record".to_string(),
                    },
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.fastlylb\.net$").unwrap(),
                        confidence: 0.95,
                        description: "Fastly load balancer CNAME".to_string(),
                    },
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.global\.fastly\.net$").unwrap(),
                        confidence: 0.96,
                        description: "Fastly global network CNAME".to_string(),
                    },
                ],
            );

            // Akamai patterns
            p.insert(
                "Akamai".to_string(),
                vec![
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.akamai\.net$").unwrap(),
                        confidence: 0.98,
                        description: "Akamai CDN CNAME record".to_string(),
                    },
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.akamaized\.net$").unwrap(),
                        confidence: 0.95,
                        description: "Akamai edge network CNAME".to_string(),
                    },
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.akamaihd\.net$").unwrap(),
                        confidence: 0.96,
                        description: "Akamai HD network CNAME".to_string(),
                    },
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.edgesuite\.net$").unwrap(),
                        confidence: 0.94,
                        description: "Akamai EdgeSuite CNAME".to_string(),
                    },
                ],
            );

            // Vercel patterns
            p.insert(
                "Vercel".to_string(),
                vec![
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.vercel\.app$").unwrap(),
                        confidence: 0.99,
                        description: "Vercel deployment CNAME".to_string(),
                    },
                    DnsPattern {
                        pattern: Regex::new(r"(?i).*\.vercel-dns\.com$").unwrap(),
                        confidence: 0.96,
                        description: "Vercel DNS CNAME record".to_string(),
                    },
                ],
            );

            // Additional common CDN patterns
            p.insert(
                "KeyCDN".to_string(),
                vec![DnsPattern {
                    pattern: Regex::new(r"(?i).*\.keycdn\.com$").unwrap(),
                    confidence: 0.98,
                    description: "KeyCDN CNAME record".to_string(),
                }],
            );

            p.insert(
                "MaxCDN".to_string(),
                vec![DnsPattern {
                    pattern: Regex::new(r"(?i).*\.maxcdn\.com$").unwrap(),
                    confidence: 0.98,
                    description: "MaxCDN CNAME record".to_string(),
                }],
            );

            p
        });

        Self {
            provider_patterns: provider_patterns.clone(),
        }
    }

    /// Perform analysis on already resolved DnsInfo
    pub fn analyze_from_info(&self, dns_info: &DnsInfo) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        // Check CNAME records
        for cname in &dns_info.cnames {
            for (provider, patterns) in &self.provider_patterns {
                for pattern in patterns {
                    if pattern.pattern.is_match(cname) {
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
                    if pattern.pattern.is_match(ns) {
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
