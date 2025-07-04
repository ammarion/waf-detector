use url::Url;
use std::time::Duration;

/// Validate and normalize URL
pub fn validate_url(url: &str) -> anyhow::Result<String> {
    let parsed = Url::parse(url)
        .map_err(|e| anyhow::anyhow!("Invalid URL '{}': {}", url, e))?;
    
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(anyhow::anyhow!("URL must use http or https scheme"));
    }
    
    if parsed.host().is_none() {
        return Err(anyhow::anyhow!("URL must have a host"));
    }
    
    Ok(parsed.to_string())
}

/// Parse timeout from seconds to Duration
pub fn parse_timeout(seconds: u64) -> Duration {
    Duration::from_secs(seconds.max(1).min(300)) // 1 second to 5 minutes
}

/// Sanitize header value for display
pub fn sanitize_header_value(value: &str) -> String {
    // Remove control characters and limit length
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect()
}

/// Extract domain from URL
pub fn extract_domain(url: &str) -> anyhow::Result<String> {
    let parsed = Url::parse(url)?;
    parsed.host_str()
        .map(|host| host.to_lowercase())
        .ok_or_else(|| anyhow::anyhow!("Could not extract domain from URL"))
}

/// Format duration in human-readable format
pub fn format_duration(duration: Duration) -> String {
    let ms = duration.as_millis();
    if ms < 1000 {
        format!("{}ms", ms)
    } else {
        format!("{:.1}s", duration.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("http://example.com").is_ok());
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("invalid-url").is_err());
    }

    #[test]
    fn test_parse_timeout() {
        assert_eq!(parse_timeout(5), Duration::from_secs(5));
        assert_eq!(parse_timeout(0), Duration::from_secs(1)); // Min 1 second
        assert_eq!(parse_timeout(500), Duration::from_secs(300)); // Max 5 minutes
    }

    #[test]
    fn test_sanitize_header_value() {
        assert_eq!(sanitize_header_value("normal-value"), "normal-value");
        assert_eq!(sanitize_header_value("value\nwith\tcontrol"), "valuewithcontrol");
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("https://Example.COM/path").unwrap(), "example.com");
        assert_eq!(extract_domain("http://sub.example.com").unwrap(), "sub.example.com");
        assert!(extract_domain("invalid-url").is_err());
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(format_duration(Duration::from_secs(2)), "2.0s");
    }
} 