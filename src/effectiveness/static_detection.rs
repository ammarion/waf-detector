//! Static Page Detection Module
//!
//! This module provides functionality to detect when a target URL is likely serving
//! static content rather than dynamic application endpoints, helping users understand
//! why WAF effectiveness tests might produce poor results on such pages.

use anyhow::Result;
use reqwest::Client;
use std::time::Duration;
use tracing::info;

/// Result of static page analysis
#[derive(Debug, Clone)]
pub struct StaticPageAnalysis {
    /// Whether the page appears to be static
    pub is_likely_static: bool,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Reasons why it was determined to be static
    pub indicators: Vec<StaticIndicator>,
    /// Suggested alternative endpoints
    pub suggestions: Vec<EndpointSuggestion>,
}

/// Indicators that suggest a page is static
#[derive(Debug, Clone)]
pub enum StaticIndicator {
    /// Static caching headers present
    CacheHeaders { header: String, value: String },
    /// CDN provider detected
    CdnDetected { provider: String, header: String },
    /// Content-Type indicates static HTML
    StaticContentType { content_type: String },
    /// No server-side processing headers
    NoServerHeaders,
    /// Identical responses regardless of parameters
    IdenticalResponses { similarity_percentage: f64 },
    /// Static file extension in URL
    StaticFileExtension { extension: String },
    /// Static hosting platform detected
    StaticHostingPlatform { platform: String },
}

/// Suggested alternative endpoints for testing
#[derive(Debug, Clone)]
pub struct EndpointSuggestion {
    pub endpoint: String,
    pub description: String,
    pub rationale: String,
}

/// Analyzes whether a target URL is likely serving static content
pub async fn analyze_static_page(url: &str) -> Result<StaticPageAnalysis> {
    info!(
        "Analyzing target URL for static content indicators: {}",
        url
    );

    let mut indicators = Vec::new();
    let mut confidence_score = 0.0;

    // Extract base URL and parse components
    let full_url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{url}")
    };
    let parsed_url = url::Url::parse(&full_url)?;

    let base_url = format!(
        "{}://{}",
        parsed_url.scheme(),
        parsed_url.host_str().unwrap_or("")
    );
    let path = parsed_url.path();

    // Check for static file extensions
    if let Some(extension) = check_static_extension(path) {
        indicators.push(StaticIndicator::StaticFileExtension {
            extension: extension.to_string(),
        });
        confidence_score += 0.3;
    }

    // Perform HTTP analysis
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;

    // Make initial request
    let response1 = client.get(url).send().await?;
    let headers1 = response1.headers().clone();
    let _status1 = response1.status();
    let body1 = response1.text().await?;

    // Analyze headers
    analyze_headers(&headers1, &mut indicators, &mut confidence_score);

    // Check Content-Type
    if let Some(content_type) = headers1.get("content-type") {
        if let Ok(ct_str) = content_type.to_str() {
            if is_static_content_type(ct_str) {
                indicators.push(StaticIndicator::StaticContentType {
                    content_type: ct_str.to_string(),
                });
                confidence_score += 0.2;
            }
        }
    }

    // Make request with parameters to check for dynamic behavior
    let test_url = if url.contains('?') {
        format!("{url}&test_param=waf_detector_test")
    } else {
        format!("{url}?test_param=waf_detector_test")
    };

    let response2 = client.get(&test_url).send().await?;
    let body2 = response2.text().await?;

    // Compare responses
    let similarity = calculate_similarity(&body1, &body2);
    if similarity > 0.95 {
        indicators.push(StaticIndicator::IdenticalResponses {
            similarity_percentage: similarity * 100.0,
        });
        confidence_score += 0.3;
    }

    // Check for absence of dynamic headers
    if !has_dynamic_headers(&headers1) {
        indicators.push(StaticIndicator::NoServerHeaders);
        confidence_score += 0.1;
    }

    // Determine if likely static
    let is_likely_static = confidence_score >= 0.5 || !indicators.is_empty();

    // Generate suggestions based on the domain
    let suggestions = generate_endpoint_suggestions(&base_url, path, &indicators);

    Ok(StaticPageAnalysis {
        is_likely_static,
        confidence: confidence_score.min(1.0),
        indicators,
        suggestions,
    })
}

/// Check if the path has a static file extension
fn check_static_extension(path: &str) -> Option<&str> {
    const STATIC_EXTENSIONS: &[&str] = &[
        ".html", ".htm", ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".pdf",
        ".txt", ".md", ".json", ".xml", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
        ".avi", ".mov", ".zip", ".tar", ".gz",
    ];

    STATIC_EXTENSIONS
        .iter()
        .find(|&&ext| path.to_lowercase().ends_with(ext))
        .copied()
}

/// Analyze headers for static content indicators
fn analyze_headers(
    headers: &reqwest::header::HeaderMap,
    indicators: &mut Vec<StaticIndicator>,
    confidence_score: &mut f64,
) {
    // Check for CDN headers
    let cdn_headers = [
        ("x-vercel-cache", "Vercel"),
        ("x-vercel-id", "Vercel"),
        ("cf-ray", "Cloudflare"),
        ("cf-cache-status", "Cloudflare"),
        ("x-amz-cf-id", "Amazon CloudFront"),
        ("x-amz-cf-pop", "Amazon CloudFront"),
        ("x-served-by", "Fastly"),
        ("x-cache", "Various CDNs"),
        ("x-github-request-id", "GitHub Pages"),
        ("x-nf-request-id", "Netlify"),
        ("server", "GitHub.com"), // GitHub Pages
    ];

    for (header_name, provider) in &cdn_headers {
        if let Some(value) = headers.get(*header_name) {
            if header_name == &"server" {
                if let Ok(server_str) = value.to_str() {
                    if server_str.contains("GitHub.com") {
                        indicators.push(StaticIndicator::CdnDetected {
                            provider: "GitHub Pages".to_string(),
                            header: header_name.to_string(),
                        });
                        *confidence_score += 0.3;
                    }
                }
            } else {
                indicators.push(StaticIndicator::CdnDetected {
                    provider: provider.to_string(),
                    header: header_name.to_string(),
                });
                *confidence_score += 0.3;
            }
        }
    }

    // Check for static caching headers
    if let Some(cache_control) = headers.get("cache-control") {
        if let Ok(cc_str) = cache_control.to_str() {
            if cc_str.contains("max-age")
                && !cc_str.contains("no-cache")
                && !cc_str.contains("no-store")
            {
                // Parse max-age value
                if let Some(max_age) = parse_max_age(cc_str) {
                    if max_age > 3600 {
                        // More than 1 hour suggests static content
                        indicators.push(StaticIndicator::CacheHeaders {
                            header: "cache-control".to_string(),
                            value: cc_str.to_string(),
                        });
                        *confidence_score += 0.2;
                    }
                }
            }
        }
    }

    // Check for static hosting platforms
    if let Some(server) = headers.get("server") {
        if let Ok(server_str) = server.to_str() {
            let static_platforms = [
                ("Vercel", "Vercel"),
                ("Netlify", "Netlify"),
                ("GitHub.com", "GitHub Pages"),
                ("AmazonS3", "Amazon S3"),
                ("Google", "Google Cloud Storage"),
            ];

            for (pattern, platform) in &static_platforms {
                if server_str.contains(pattern) {
                    indicators.push(StaticIndicator::StaticHostingPlatform {
                        platform: platform.to_string(),
                    });
                    *confidence_score += 0.3;
                    break;
                }
            }
        }
    }
}

/// Parse max-age value from Cache-Control header
fn parse_max_age(cache_control: &str) -> Option<u64> {
    cache_control
        .split(',')
        .map(|s| s.trim())
        .find(|s| s.starts_with("max-age="))
        .and_then(|s| s.strip_prefix("max-age="))
        .and_then(|s| s.parse::<u64>().ok())
}

/// Check if Content-Type indicates static content
fn is_static_content_type(content_type: &str) -> bool {
    let static_types = [
        "text/html",
        "text/plain",
        "text/css",
        "application/javascript",
        "application/json",
        "application/xml",
        "image/",
        "video/",
        "audio/",
        "font/",
    ];

    // Check if it's a static type without charset or other parameters
    let ct_lower = content_type.to_lowercase();
    static_types.iter().any(|&st| ct_lower.starts_with(st))
        && !ct_lower.contains("php")
        && !ct_lower.contains("asp")
        && !ct_lower.contains("jsp")
}

/// Check for presence of dynamic processing headers
fn has_dynamic_headers(headers: &reqwest::header::HeaderMap) -> bool {
    let dynamic_headers = [
        "x-powered-by",
        "x-aspnet-version",
        "x-php-version",
        "x-drupal-cache",
        "x-wordpress",
        "set-cookie",
        "x-request-id",
        "x-response-time",
    ];

    dynamic_headers.iter().any(|&h| headers.contains_key(h))
}

/// Calculate similarity between two strings (0.0 to 1.0)
pub fn calculate_similarity(s1: &str, s2: &str) -> f64 {
    if s1 == s2 {
        return 1.0;
    }

    // Simple character-based similarity
    let len1 = s1.len();
    let len2 = s2.len();

    if len1 == 0 || len2 == 0 {
        return 0.0;
    }

    // Check if lengths are very different
    let len_diff = (len1 as f64 - len2 as f64).abs() / len1.max(len2) as f64;
    if len_diff > 0.1 {
        return 1.0 - len_diff;
    }

    // Compare first 1000 characters for efficiency
    let sample1 = &s1[..s1.len().min(1000)];
    let sample2 = &s2[..s2.len().min(1000)];

    let matching_chars = sample1
        .chars()
        .zip(sample2.chars())
        .filter(|(c1, c2)| c1 == c2)
        .count();

    matching_chars as f64 / sample1.len().max(sample2.len()) as f64
}

/// Generate endpoint suggestions based on the domain and indicators
fn generate_endpoint_suggestions(
    base_url: &str,
    current_path: &str,
    indicators: &[StaticIndicator],
) -> Vec<EndpointSuggestion> {
    let mut suggestions = Vec::new();

    // Always suggest common dynamic endpoints
    suggestions.push(EndpointSuggestion {
        endpoint: format!("{base_url}/api/"),
        description: "API endpoints".to_string(),
        rationale: "API endpoints typically handle dynamic requests and are more likely to have WAF protection".to_string(),
    });

    suggestions.push(EndpointSuggestion {
        endpoint: format!("{base_url}/login"),
        description: "Login page".to_string(),
        rationale:
            "Authentication endpoints are critical security points that should have WAF protection"
                .to_string(),
    });

    suggestions.push(EndpointSuggestion {
        endpoint: format!("{base_url}/search"),
        description: "Search functionality".to_string(),
        rationale:
            "Search endpoints process user input and are common targets for injection attacks"
                .to_string(),
    });

    suggestions.push(EndpointSuggestion {
        endpoint: format!("{base_url}/contact"),
        description: "Contact form".to_string(),
        rationale: "Forms that accept user input are good targets for testing input validation and WAF rules".to_string(),
    });

    suggestions.push(EndpointSuggestion {
        endpoint: format!("{base_url}/admin"),
        description: "Admin panel".to_string(),
        rationale:
            "Administrative interfaces often have additional security measures and WAF rules"
                .to_string(),
    });

    // Add context-specific suggestions
    if current_path == "/" || current_path.ends_with("index.html") {
        suggestions.push(EndpointSuggestion {
            endpoint: format!("{base_url}/api/v1/"),
            description: "Versioned API endpoint".to_string(),
            rationale:
                "Modern applications often use versioned APIs for their dynamic functionality"
                    .to_string(),
        });
    }

    // If CDN is detected, suggest looking for the origin
    if indicators
        .iter()
        .any(|i| matches!(i, StaticIndicator::CdnDetected { .. }))
    {
        suggestions.push(EndpointSuggestion {
            endpoint: "Consider testing the origin server directly".to_string(),
            description: "Origin server endpoint".to_string(),
            rationale: "CDNs often cache static content. Testing the origin server directly may yield better results".to_string(),
        });
    }

    suggestions
}

/// Format the analysis results as a warning message
pub fn format_static_page_warning(analysis: &StaticPageAnalysis) -> String {
    let mut warning = String::new();

    warning.push_str(&format!(
        "\n⚠️  WARNING: Target appears to be serving static content (confidence: {:.0}%)\n\n",
        analysis.confidence * 100.0
    ));

    warning.push_str("Detected indicators:\n");
    for indicator in &analysis.indicators {
        match indicator {
            StaticIndicator::CacheHeaders { header, value } => {
                warning.push_str(&format!("  • Long cache duration: {header} = {value}\n"));
            }
            StaticIndicator::CdnDetected { provider, header } => {
                warning.push_str(&format!(
                    "  • CDN detected: {provider} (via {header} header)\n"
                ));
            }
            StaticIndicator::StaticContentType { content_type } => {
                warning.push_str(&format!("  • Static content type: {content_type}\n"));
            }
            StaticIndicator::NoServerHeaders => {
                warning.push_str("  • No dynamic server processing headers found\n");
            }
            StaticIndicator::IdenticalResponses {
                similarity_percentage,
            } => {
                warning.push_str(&format!(
                    "  • Identical responses to different parameters ({similarity_percentage:.1}% similar)\n"
                ));
            }
            StaticIndicator::StaticFileExtension { extension } => {
                warning.push_str(&format!("  • Static file extension: {extension}\n"));
            }
            StaticIndicator::StaticHostingPlatform { platform } => {
                warning.push_str(&format!("  • Static hosting platform: {platform}\n"));
            }
        }
    }

    warning.push_str(
        "\n💡 Testing static pages will likely show poor WAF effectiveness results because:\n",
    );
    warning.push_str("   - Static content doesn't process user input\n");
    warning.push_str("   - No server-side code execution means no injection vulnerabilities\n");
    warning.push_str("   - WAF rules may not apply to cached/static content\n");

    warning.push_str("\n📍 Suggested endpoints for better results:\n");
    for suggestion in &analysis.suggestions {
        warning.push_str(&format!(
            "   • {} - {}\n     {}\n",
            suggestion.endpoint, suggestion.description, suggestion.rationale
        ));
    }

    warning.push_str("\n❓ Do you want to continue testing this static page anyway? The results may not accurately reflect your WAF's effectiveness.\n");

    warning
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_extension_detection() {
        assert_eq!(check_static_extension("/index.html"), Some(".html"));
        assert_eq!(check_static_extension("/style.css"), Some(".css"));
        assert_eq!(check_static_extension("/script.js"), Some(".js"));
        assert_eq!(check_static_extension("/image.png"), Some(".png"));
        assert_eq!(check_static_extension("/document.pdf"), Some(".pdf"));
        assert_eq!(check_static_extension("/api/users"), None);
        assert_eq!(check_static_extension("/login"), None);
    }

    #[test]
    fn test_static_content_type() {
        assert!(is_static_content_type("text/html"));
        assert!(is_static_content_type("text/html; charset=utf-8"));
        assert!(is_static_content_type("text/css"));
        assert!(is_static_content_type("application/javascript"));
        assert!(is_static_content_type("image/png"));
        assert!(is_static_content_type("video/mp4"));

        // Dynamic content types
        assert!(!is_static_content_type("text/html; charset=utf-8; php"));
        assert!(!is_static_content_type("application/x-httpd-php"));
    }

    #[test]
    fn test_similarity_calculation() {
        assert_eq!(calculate_similarity("hello", "hello"), 1.0);
        assert_eq!(calculate_similarity("", ""), 1.0);
        assert!(calculate_similarity("hello", "hallo") > 0.5);
        assert!(calculate_similarity("hello", "world") < 0.5);

        // Test with very different lengths
        assert!(calculate_similarity("a", "a very long string") < 0.5);
    }

    #[test]
    fn test_parse_max_age() {
        assert_eq!(parse_max_age("max-age=3600"), Some(3600));
        assert_eq!(parse_max_age("public, max-age=86400"), Some(86400));
        assert_eq!(parse_max_age("max-age=0"), Some(0));
        assert_eq!(parse_max_age("no-cache"), None);
        assert_eq!(parse_max_age("max-age=invalid"), None);
    }

    #[test]
    fn test_endpoint_suggestions() {
        let suggestions = generate_endpoint_suggestions("https://example.com", "/", &[]);

        // Should always suggest common endpoints
        assert!(suggestions.iter().any(|s| s.endpoint.contains("/api/")));
        assert!(suggestions.iter().any(|s| s.endpoint.contains("/login")));
        assert!(suggestions.iter().any(|s| s.endpoint.contains("/search")));
        assert!(suggestions.iter().any(|s| s.endpoint.contains("/contact")));
        assert!(suggestions.iter().any(|s| s.endpoint.contains("/admin")));

        // Check that suggestions have descriptions and rationale
        for suggestion in &suggestions {
            assert!(!suggestion.description.is_empty());
            assert!(!suggestion.rationale.is_empty());
        }
    }

    #[test]
    fn test_static_indicator_formatting() {
        use StaticIndicator::*;

        let indicators = vec![
            CacheHeaders {
                header: "cache-control".to_string(),
                value: "max-age=86400".to_string(),
            },
            CdnDetected {
                provider: "Cloudflare".to_string(),
                header: "cf-ray".to_string(),
            },
            StaticContentType {
                content_type: "text/html".to_string(),
            },
            NoServerHeaders,
            IdenticalResponses {
                similarity_percentage: 98.5,
            },
            StaticFileExtension {
                extension: ".html".to_string(),
            },
            StaticHostingPlatform {
                platform: "Vercel".to_string(),
            },
        ];

        let analysis = StaticPageAnalysis {
            is_likely_static: true,
            confidence: 0.85,
            indicators,
            suggestions: vec![],
        };

        let warning = format_static_page_warning(&analysis);

        // Check that warning contains key information
        assert!(warning.contains("85%"));
        assert!(warning.contains("cache-control"));
        assert!(warning.contains("Cloudflare"));
        assert!(warning.contains("text/html"));
        assert!(warning.contains("No dynamic server processing headers"));
        assert!(warning.contains("98.5% similar"));
        assert!(warning.contains(".html"));
        assert!(warning.contains("Vercel"));
    }
}
