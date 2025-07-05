//! DNS analysis for WAF/CDN detection
//! 
//! Provides definitive provider identification through CNAME record analysis.
//! DNS records directly reveal the infrastructure being used.

use crate::{Evidence, MethodType};
use std::collections::HashMap;
use anyhow::Result;
use regex::Regex;

/// DNS analysis results
#[derive(Debug, Clone)]
pub struct DnsAnalysis {
    pub domain: String,
    pub cname_records: Vec<String>,
    pub provider_matches: Vec<ProviderMatch>,
    pub confidence: f64,
}

/// Provider match from DNS analysis
#[derive(Debug, Clone)]
pub struct ProviderMatch {
    pub provider: String,
    pub matched_pattern: String,
    pub cname_record: String,
    pub confidence: f64,
}

/// DNS resolver with provider pattern matching
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
        let mut provider_patterns = HashMap::new();
        
        // CloudFlare CNAME patterns
        provider_patterns.insert("CloudFlare".to_string(), vec![
            DnsPattern {
                pattern: Regex::new(r".*\.cloudflare\.net$").unwrap(),
                confidence: 0.98,
                description: "CloudFlare CDN CNAME record".to_string(),
            },
            DnsPattern {
                pattern: Regex::new(r".*\.cloudflaressl\.com$").unwrap(),
                confidence: 0.95,
                description: "CloudFlare SSL CNAME record".to_string(),
            },
            DnsPattern {
                pattern: Regex::new(r".*\.cf-dns\.com$").unwrap(),
                confidence: 0.90,
                description: "CloudFlare DNS CNAME record".to_string(),
            },
        ]);
        
        // AWS CloudFront patterns
        provider_patterns.insert("AWS".to_string(), vec![
            DnsPattern {
                pattern: Regex::new(r".*\.cloudfront\.net$").unwrap(),
                confidence: 0.98,
                description: "AWS CloudFront CNAME record".to_string(),
            },
            DnsPattern {
                pattern: Regex::new(r"d[0-9a-z]+\.cloudfront\.net$").unwrap(),
                confidence: 0.99,
                description: "AWS CloudFront distribution CNAME".to_string(),
            },
            DnsPattern {
                pattern: Regex::new(r".*\.amazonaws\.com$").unwrap(),
                confidence: 0.95,
                description: "AWS service CNAME record".to_string(),
            },
        ]);
        
        // Fastly patterns
        provider_patterns.insert("Fastly".to_string(), vec![
            DnsPattern {
                pattern: Regex::new(r".*\.fastly\.com$").unwrap(),
                confidence: 0.98,
                description: "Fastly CDN CNAME record".to_string(),
            },
            DnsPattern {
                pattern: Regex::new(r".*\.fastlylb\.net$").unwrap(),
                confidence: 0.95,
                description: "Fastly load balancer CNAME".to_string(),
            },
            DnsPattern {
                pattern: Regex::new(r".*\.global\.fastly\.net$").unwrap(),
                confidence: 0.96,
                description: "Fastly global network CNAME".to_string(),
            },
        ]);
        
        // Akamai patterns
        provider_patterns.insert("Akamai".to_string(), vec![
            DnsPattern {
                pattern: Regex::new(r".*\.akamai\.net$").unwrap(),
                confidence: 0.98,
                description: "Akamai CDN CNAME record".to_string(),
            },
            DnsPattern {
                pattern: Regex::new(r".*\.akamaized\.net$").unwrap(),
                confidence: 0.95,
                description: "Akamai edge network CNAME".to_string(),
            },
            DnsPattern {
                pattern: Regex::new(r".*\.akamaihd\.net$").unwrap(),
                confidence: 0.96,
                description: "Akamai HD network CNAME".to_string(),
            },
            DnsPattern {
                pattern: Regex::new(r".*\.edgesuite\.net$").unwrap(),
                confidence: 0.94,
                description: "Akamai EdgeSuite CNAME".to_string(),
            },
        ]);
        
        // Vercel patterns
        provider_patterns.insert("Vercel".to_string(), vec![
            DnsPattern {
                pattern: Regex::new(r".*\.vercel\.app$").unwrap(),
                confidence: 0.99,
                description: "Vercel deployment CNAME".to_string(),
            },
            DnsPattern {
                pattern: Regex::new(r".*\.vercel-dns\.com$").unwrap(),
                confidence: 0.96,
                description: "Vercel DNS CNAME record".to_string(),
            },
        ]);
        
        // Additional common CDN patterns
        provider_patterns.insert("KeyCDN".to_string(), vec![
            DnsPattern {
                pattern: Regex::new(r".*\.keycdn\.com$").unwrap(),
                confidence: 0.98,
                description: "KeyCDN CNAME record".to_string(),
            },
        ]);
        
        provider_patterns.insert("MaxCDN".to_string(), vec![
            DnsPattern {
                pattern: Regex::new(r".*\.maxcdn\.com$").unwrap(),
                confidence: 0.98,
                description: "MaxCDN CNAME record".to_string(),
            },
        ]);
        
        Self { provider_patterns }
    }
    
    /// Perform DNS analysis on a domain
    pub async fn analyze(&self, domain: &str) -> Result<Vec<Evidence>> {
        let mut evidence = Vec::new();
        
        // Clean the domain (remove protocol, path, etc.)
        let clean_domain = self.extract_domain(domain);
        
        // Resolve CNAME records
        let cname_records = self.resolve_cname(&clean_domain).await?;
        
        if cname_records.is_empty() {
            return Ok(evidence);
        }
        
        // Check each CNAME record against provider patterns
        for cname in &cname_records {
            for (provider, patterns) in &self.provider_patterns {
                for pattern in patterns {
                    if pattern.pattern.is_match(cname) {
                        evidence.push(Evidence {
                            method_type: MethodType::DNS("cname".to_string()),
                            confidence: pattern.confidence,
                            description: format!(
                                "{} - {} detected via CNAME record",
                                pattern.description,
                                provider
                            ),
                            raw_data: format!("{} -> {}", clean_domain, cname),
                            signature_matched: format!("dns-cname-{}", provider.to_lowercase()),
                        });
                    }
                }
            }
        }
        
        Ok(evidence)
    }
    
    /// Extract clean domain from URL
    fn extract_domain(&self, url: &str) -> String {
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
    
    /// Resolve CNAME records for a domain
    async fn resolve_cname(&self, domain: &str) -> Result<Vec<String>> {
        use tokio::process::Command;
        
        // Use system's dig command for DNS resolution
        let output = Command::new("dig")
            .args(["+short", "CNAME", domain])
            .output()
            .await;
        
        match output {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let cnames: Vec<String> = stdout
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                        .map(|line| {
                            // Remove trailing dot if present
                            let clean = line.trim();
                            if clean.ends_with('.') {
                                clean[..clean.len() - 1].to_string()
                            } else {
                                clean.to_string()
                            }
                        })
                        .collect();
                    Ok(cnames)
                } else {
                    // If dig fails, try with nslookup as fallback
                    self.resolve_cname_nslookup(domain).await
                }
            }
            Err(_) => {
                // If dig is not available, try nslookup
                self.resolve_cname_nslookup(domain).await
            }
        }
    }
    
    /// Fallback CNAME resolution using nslookup
    async fn resolve_cname_nslookup(&self, domain: &str) -> Result<Vec<String>> {
        use tokio::process::Command;
        
        let output = Command::new("nslookup")
            .args(["-type=CNAME", domain])
            .output()
            .await?;
        
        if !output.status.success() {
            return Ok(Vec::new());
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut cnames = Vec::new();
        
        // Parse nslookup output for CNAME records
        for line in stdout.lines() {
            if line.contains("canonical name") {
                if let Some(cname_part) = line.split("canonical name = ").nth(1) {
                    let cname = cname_part.trim();
                    let clean_cname = if cname.ends_with('.') {
                        cname[..cname.len() - 1].to_string()
                    } else {
                        cname.to_string()
                    };
                    cnames.push(clean_cname);
                }
            }
        }
        
        Ok(cnames)
    }
    
    /// Get all supported providers and their patterns
    pub fn get_supported_providers(&self) -> Vec<String> {
        self.provider_patterns.keys().cloned().collect()
    }
    
    /// Get pattern count for a provider
    pub fn get_pattern_count(&self, provider: &str) -> usize {
        self.provider_patterns
            .get(provider)
            .map(|patterns| patterns.len())
            .unwrap_or(0)
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
        assert!(analyzer.provider_patterns.len() > 0);
        assert!(analyzer.provider_patterns.contains_key("CloudFlare"));
        assert!(analyzer.provider_patterns.contains_key("AWS"));
    }
    
    #[test]
    fn test_extract_domain() {
        let analyzer = DnsAnalyzer::new();
        
        assert_eq!(analyzer.extract_domain("https://example.com"), "example.com");
        assert_eq!(analyzer.extract_domain("http://example.com/path"), "example.com");
        assert_eq!(analyzer.extract_domain("example.com"), "example.com");
        assert_eq!(analyzer.extract_domain("example.com:8080"), "example.com");
        assert_eq!(analyzer.extract_domain("https://example.com:443/path?query=1"), "example.com");
        assert_eq!(analyzer.extract_domain("subdomain.example.com"), "subdomain.example.com");
    }
    
    #[test]
    fn test_provider_patterns() {
        let analyzer = DnsAnalyzer::new();
        
        // Test CloudFlare patterns
        let cf_patterns = analyzer.provider_patterns.get("CloudFlare").unwrap();
        assert!(cf_patterns.iter().any(|p| p.pattern.is_match("target.cloudflare.net")));
        assert!(cf_patterns.iter().any(|p| p.pattern.is_match("ssl.cloudflaressl.com")));
        
        // Test AWS patterns
        let aws_patterns = analyzer.provider_patterns.get("AWS").unwrap();
        assert!(aws_patterns.iter().any(|p| p.pattern.is_match("d123abc.cloudfront.net")));
        assert!(aws_patterns.iter().any(|p| p.pattern.is_match("example.amazonaws.com")));
        
        // Test Fastly patterns
        let fastly_patterns = analyzer.provider_patterns.get("Fastly").unwrap();
        assert!(fastly_patterns.iter().any(|p| p.pattern.is_match("target.fastly.com")));
        
        // Test Akamai patterns
        let akamai_patterns = analyzer.provider_patterns.get("Akamai").unwrap();
        assert!(akamai_patterns.iter().any(|p| p.pattern.is_match("target.akamai.net")));
        assert!(akamai_patterns.iter().any(|p| p.pattern.is_match("target.edgesuite.net")));
    }
    
    #[test]
    fn test_confidence_levels() {
        let analyzer = DnsAnalyzer::new();
        
        // CloudFlare main pattern should have high confidence
        let cf_patterns = analyzer.provider_patterns.get("CloudFlare").unwrap();
        let main_pattern = cf_patterns.iter().find(|p| p.pattern.to_string().contains("cloudflare")).unwrap();
        assert!(main_pattern.confidence >= 0.95);
        
        // AWS CloudFront distribution pattern should have very high confidence
        let aws_patterns = analyzer.provider_patterns.get("AWS").unwrap();
        let dist_pattern = aws_patterns.iter().find(|p| p.pattern.to_string().contains("cloudfront")).unwrap();
        assert!(dist_pattern.confidence >= 0.99);
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
    fn test_get_pattern_count() {
        let analyzer = DnsAnalyzer::new();
        
        assert!(analyzer.get_pattern_count("CloudFlare") > 0);
        assert!(analyzer.get_pattern_count("AWS") > 0);
        assert_eq!(analyzer.get_pattern_count("NonExistentProvider"), 0);
    }
    
    #[tokio::test]
    async fn test_dns_analysis_mock() {
        let analyzer = DnsAnalyzer::new();
        
        // Test domain extraction works
        let domain = analyzer.extract_domain("https://example.com/test");
        assert_eq!(domain, "example.com");
        
        // Note: We can't easily test actual DNS resolution in unit tests
        // without mocking the DNS system or having known test domains
        // This would require integration tests with controlled DNS records
    }
} 