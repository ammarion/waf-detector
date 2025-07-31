//! Optimized DNS pattern matching using OnceLock
//!
//! This module provides high-performance DNS pattern matching
//! by compiling regex patterns only once at first use.

use regex::Regex;
use std::sync::OnceLock;

/// CloudFlare DNS patterns
pub mod cloudflare {
    use super::*;

    pub fn cdn_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.cloudflare\.net$").unwrap())
    }

    pub fn ssl_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.cloudflaressl\.com$").unwrap())
    }

    pub fn dns_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.cf-dns\.com$").unwrap())
    }

    pub fn check_all(cname: &str) -> Option<(&'static str, f64)> {
        if cdn_pattern().is_match(cname) {
            return Some(("CloudFlare CDN", 0.98));
        }
        if ssl_pattern().is_match(cname) {
            return Some(("CloudFlare SSL", 0.95));
        }
        if dns_pattern().is_match(cname) {
            return Some(("CloudFlare DNS", 0.90));
        }
        None
    }
}

/// AWS CloudFront patterns
pub mod aws {
    use super::*;

    pub fn cloudfront_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.cloudfront\.net$").unwrap())
    }

    pub fn distribution_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"d[0-9a-z]+\.cloudfront\.net$").unwrap())
    }

    pub fn amazonaws_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.amazonaws\.com$").unwrap())
    }

    pub fn check_all(cname: &str) -> Option<(&'static str, f64)> {
        if distribution_pattern().is_match(cname) {
            return Some(("AWS CloudFront Distribution", 0.99));
        }
        if cloudfront_pattern().is_match(cname) {
            return Some(("AWS CloudFront", 0.98));
        }
        if amazonaws_pattern().is_match(cname) {
            return Some(("AWS Service", 0.95));
        }
        None
    }
}

/// Akamai patterns
pub mod akamai {
    use super::*;

    pub fn cdn_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.akamai\.net$").unwrap())
    }

    pub fn akamaized_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.akamaized\.net$").unwrap())
    }

    pub fn hd_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.akamaihd\.net$").unwrap())
    }

    pub fn edgesuite_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.edgesuite\.net$").unwrap())
    }

    pub fn check_all(cname: &str) -> Option<(&'static str, f64)> {
        if cdn_pattern().is_match(cname) {
            return Some(("Akamai CDN", 0.98));
        }
        if hd_pattern().is_match(cname) {
            return Some(("Akamai HD", 0.96));
        }
        if akamaized_pattern().is_match(cname) {
            return Some(("Akamai Edge", 0.95));
        }
        if edgesuite_pattern().is_match(cname) {
            return Some(("Akamai EdgeSuite", 0.94));
        }
        None
    }
}

/// Fastly patterns
pub mod fastly {
    use super::*;

    pub fn cdn_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.fastly\.com$").unwrap())
    }

    pub fn lb_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.fastlylb\.net$").unwrap())
    }

    pub fn global_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.global\.fastly\.net$").unwrap())
    }

    pub fn check_all(cname: &str) -> Option<(&'static str, f64)> {
        if cdn_pattern().is_match(cname) {
            return Some(("Fastly CDN", 0.98));
        }
        if global_pattern().is_match(cname) {
            return Some(("Fastly Global", 0.96));
        }
        if lb_pattern().is_match(cname) {
            return Some(("Fastly LB", 0.95));
        }
        None
    }
}

/// Azure patterns
pub mod azure {
    use super::*;

    pub fn cdn_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.azureedge\.net$").unwrap())
    }

    pub fn frontdoor_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.azurefd\.net$").unwrap())
    }

    pub fn websites_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.azurewebsites\.net$").unwrap())
    }

    pub fn check_all(cname: &str) -> Option<(&'static str, f64)> {
        if cdn_pattern().is_match(cname) {
            return Some(("Azure CDN", 0.98));
        }
        if frontdoor_pattern().is_match(cname) {
            return Some(("Azure Front Door", 0.97));
        }
        if websites_pattern().is_match(cname) {
            return Some(("Azure Websites", 0.95));
        }
        None
    }
}

/// Vercel patterns
pub mod vercel {
    use super::*;

    pub fn app_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.vercel\.app$").unwrap())
    }

    pub fn dns_pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r".*\.vercel-dns\.com$").unwrap())
    }

    pub fn check_all(cname: &str) -> Option<(&'static str, f64)> {
        if app_pattern().is_match(cname) {
            return Some(("Vercel App", 0.99));
        }
        if dns_pattern().is_match(cname) {
            return Some(("Vercel DNS", 0.96));
        }
        None
    }
}

/// Check all providers and return the best match
pub fn check_all_providers(cname: &str) -> Option<(String, &'static str, f64)> {
    // Check each provider in priority order
    if let Some((desc, conf)) = cloudflare::check_all(cname) {
        return Some(("CloudFlare".to_string(), desc, conf));
    }
    if let Some((desc, conf)) = aws::check_all(cname) {
        return Some(("AWS".to_string(), desc, conf));
    }
    if let Some((desc, conf)) = akamai::check_all(cname) {
        return Some(("Akamai".to_string(), desc, conf));
    }
    if let Some((desc, conf)) = fastly::check_all(cname) {
        return Some(("Fastly".to_string(), desc, conf));
    }
    if let Some((desc, conf)) = azure::check_all(cname) {
        return Some(("Azure".to_string(), desc, conf));
    }
    if let Some((desc, conf)) = vercel::check_all(cname) {
        return Some(("Vercel".to_string(), desc, conf));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_patterns() {
        assert!(cloudflare::cdn_pattern().is_match("example.cloudflare.net"));
        assert!(cloudflare::ssl_pattern().is_match("example.cloudflaressl.com"));
        assert!(!cloudflare::cdn_pattern().is_match("example.com"));
    }

    #[test]
    fn test_aws_patterns() {
        assert!(aws::cloudfront_pattern().is_match("example.cloudfront.net"));
        assert!(aws::distribution_pattern().is_match("d1234567890abc.cloudfront.net"));
        assert!(!aws::distribution_pattern().is_match("example.cloudfront.net"));
    }

    #[test]
    fn test_check_all_providers() {
        let result = check_all_providers("example.cloudflare.net");
        assert!(result.is_some());
        if let Some((provider, desc, conf)) = result {
            assert_eq!(provider, "CloudFlare");
            assert_eq!(desc, "CloudFlare CDN");
            assert_eq!(conf, 0.98);
        }
    }
}
