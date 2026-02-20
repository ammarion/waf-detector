//! Error Page Behavioral Fingerprinting
//!
//! Identifies WAF/CDN providers by analyzing error page characteristics.
//! Different WAFs produce distinct error pages for different block conditions.

use crate::{Evidence, MethodType};
use std::collections::HashMap;

/// An error page profile for a specific provider
#[derive(Debug, Clone)]
pub struct ErrorProfile {
    pub provider: String,
    pub patterns: Vec<ErrorPagePattern>,
}

/// A specific error page pattern
#[derive(Debug, Clone)]
pub struct ErrorPagePattern {
    /// Human-readable name
    pub name: String,
    /// HTTP status code(s) this pattern applies to
    pub status_codes: Vec<u16>,
    /// Required strings in the response body (all must match, case-insensitive)
    pub body_markers: Vec<String>,
    /// Optional header indicators
    pub header_markers: Vec<(String, String)>, // (header_name, substring_match)
    /// Confidence when this pattern matches
    pub confidence: f64,
    /// Signature ID for evidence tracking
    pub signature: String,
}

#[derive(Debug)]
pub struct ErrorProfileDatabase {
    profiles: Vec<ErrorProfile>,
}

impl ErrorProfileDatabase {
    pub fn new() -> Self {
        let profiles = vec![
            // CloudFlare error profiles
            ErrorProfile {
            provider: "CloudFlare".to_string(),
            patterns: vec![
                ErrorPagePattern {
                    name: "CloudFlare 403 Block Page".to_string(),
                    status_codes: vec![403],
                    body_markers: vec![
                        "attention required".to_string(),
                        "cloudflare".to_string(),
                        "ray id".to_string(),
                    ],
                    header_markers: vec![("cf-ray".to_string(), "".to_string())],
                    confidence: 0.95,
                    signature: "error-profile-cloudflare-403-block".to_string(),
                },
                ErrorPagePattern {
                    name: "CloudFlare 503 Challenge".to_string(),
                    status_codes: vec![503],
                    body_markers: vec![
                        "just a moment".to_string(),
                        "cloudflare".to_string(),
                        "cf-browser-verification".to_string(),
                    ],
                    header_markers: vec![("cf-ray".to_string(), "".to_string())],
                    confidence: 0.95,
                    signature: "error-profile-cloudflare-503-challenge".to_string(),
                },
                ErrorPagePattern {
                    name: "CloudFlare 1xxx Error".to_string(),
                    status_codes: vec![403, 502, 503, 520, 521, 522, 523, 524, 525, 526],
                    body_markers: vec!["error 10".to_string(), "cloudflare".to_string()],
                    header_markers: vec![],
                    confidence: 0.90,
                    signature: "error-profile-cloudflare-1xxx".to_string(),
                },
                ErrorPagePattern {
                    name: "CloudFlare Rate Limit".to_string(),
                    status_codes: vec![429],
                    body_markers: vec!["cloudflare".to_string(), "rate limit".to_string()],
                    header_markers: vec![("cf-ray".to_string(), "".to_string())],
                    confidence: 0.95,
                    signature: "error-profile-cloudflare-rate-limit".to_string(),
                },
            ],
            },
            // AWS WAF error profiles
            ErrorProfile {
            provider: "AWS".to_string(),
            patterns: vec![
                ErrorPagePattern {
                    name: "AWS WAF Block".to_string(),
                    status_codes: vec![403],
                    body_markers: vec!["request blocked".to_string(), "aws waf".to_string()],
                    header_markers: vec![],
                    confidence: 0.90,
                    signature: "error-profile-aws-waf-block".to_string(),
                },
                ErrorPagePattern {
                    name: "AWS WAF Custom Block".to_string(),
                    status_codes: vec![403],
                    body_markers: vec!["this request has been blocked".to_string()],
                    header_markers: vec![
                        ("x-amzn-requestid".to_string(), "".to_string()),
                        ("x-amzn-errortype".to_string(), "".to_string()),
                    ],
                    confidence: 0.85,
                    signature: "error-profile-aws-custom-block".to_string(),
                },
            ],
            },
            //Akamai error profiles
        ErrorProfile {
            provider: "Akamai".to_string(),
            patterns: vec![
                ErrorPagePattern {
                    name: "Akamai Access Denied".to_string(),
                    status_codes: vec![403],
                    body_markers: vec![
                        "access denied".to_string(),
                        "reference #".to_string(),
                    ],
                    header_markers: vec![],
                    confidence: 0.85,
                    signature: "error-profile-akamai-403".to_string(),
                },
                ErrorPagePattern {
                    name: "Akamai Bot Detection".to_string(),
                    status_codes: vec![403, 429],
                    body_markers: vec!["are you a human".to_string(), "bot".to_string()],
                    header_markers: vec![],
                    confidence: 0.80,
                    signature: "error-profile-akamai-bot".to_string(),
                },
            ],
            },
            //Imperva/Incapsula error profiles
        ErrorProfile {
            provider: "Imperva".to_string(),
            patterns: vec![
                ErrorPagePattern {
                    name: "Imperva Block Page".to_string(),
                    status_codes: vec![403],
                    body_markers: vec!["incapsula".to_string(), "incident id".to_string()],
                    header_markers: vec![("x-iinfo".to_string(), "".to_string())],
                    confidence: 0.95,
                    signature: "error-profile-imperva-block".to_string(),
                },
                ErrorPagePattern {
                    name: "Imperva Bot Challenge".to_string(),
                    status_codes: vec![403],
                    body_markers: vec![
                        "request unsuccessful".to_string(),
                        "incapsula".to_string(),
                    ],
                    header_markers: vec![],
                    confidence: 0.90,
                    signature: "error-profile-imperva-bot".to_string(),
                },
                ErrorPagePattern {
                    name: "Imperva CAPTCHA".to_string(),
                    status_codes: vec![403],
                    body_markers: vec!["incapsula".to_string(), "verify".to_string()],
                    header_markers: vec![],
                    confidence: 0.90,
                    signature: "error-profile-imperva-captcha".to_string(),
                },
            ],
            },
            //Sucuri error profiles
        ErrorProfile {
            provider: "Sucuri".to_string(),
            patterns: vec![
                ErrorPagePattern {
                    name: "Sucuri Access Denied".to_string(),
                    status_codes: vec![403],
                    body_markers: vec!["access denied".to_string(), "sucuri".to_string()],
                    header_markers: vec![("x-sucuri-id".to_string(), "".to_string())],
                    confidence: 0.95,
                    signature: "error-profile-sucuri-403".to_string(),
                },
                ErrorPagePattern {
                    name: "Sucuri Firewall Block".to_string(),
                    status_codes: vec![403],
                    body_markers: vec![
                        "website firewall".to_string(),
                        "sucuri cloudproxy".to_string(),
                    ],
                    header_markers: vec![],
                    confidence: 0.90,
                    signature: "error-profile-sucuri-firewall".to_string(),
                },
            ],
            },
            //F5 BIG-IP ASM error profiles
        ErrorProfile {
            provider: "F5".to_string(),
            patterns: vec![
                ErrorPagePattern {
                    name: "F5 BIG-IP ASM Block".to_string(),
                    status_codes: vec![403],
                    body_markers: vec![
                        "the requested url was rejected".to_string(),
                        "support id".to_string(),
                    ],
                    header_markers: vec![],
                    confidence: 0.90,
                    signature: "error-profile-f5-asm-block".to_string(),
                },
                ErrorPagePattern {
                    name: "F5 Custom Block".to_string(),
                    status_codes: vec![403],
                    body_markers: vec!["please consult with your administrator".to_string()],
                    header_markers: vec![],
                    confidence: 0.70,
                    signature: "error-profile-f5-custom".to_string(),
                },
            ],
            },
            //ModSecurity error profiles
        ErrorProfile {
            provider: "ModSecurity".to_string(),
            patterns: vec![
                ErrorPagePattern {
                    name: "ModSecurity Block".to_string(),
                    status_codes: vec![403],
                    body_markers: vec!["modsecurity".to_string(), "not acceptable".to_string()],
                    header_markers: vec![],
                    confidence: 0.90,
                    signature: "error-profile-modsecurity-403".to_string(),
                },
                ErrorPagePattern {
                    name: "ModSecurity 406".to_string(),
                    status_codes: vec![406],
                    body_markers: vec!["not acceptable".to_string(), "mod_security".to_string()],
                    header_markers: vec![],
                    confidence: 0.90,
                    signature: "error-profile-modsecurity-406".to_string(),
                },
                ErrorPagePattern {
                    name: "ModSecurity Generic".to_string(),
                    status_codes: vec![403, 406],
                    body_markers: vec!["this error was generated by mod_security".to_string()],
                    header_markers: vec![],
                    confidence: 0.95,
                    signature: "error-profile-modsecurity-generic".to_string(),
                },
            ],
            },
            //FortiWeb error profiles
        ErrorProfile {
            provider: "FortiWeb".to_string(),
            patterns: vec![
                ErrorPagePattern {
                    name: "FortiWeb Block".to_string(),
                    status_codes: vec![403],
                    body_markers: vec!["fortiweb".to_string(), "web page blocked".to_string()],
                    header_markers: vec![],
                    confidence: 0.95,
                    signature: "error-profile-fortiweb-block".to_string(),
                },
                ErrorPagePattern {
                    name: "FortiWeb Attack Block".to_string(),
                    status_codes: vec![403],
                    body_markers: vec!["fortinet".to_string(), "attack blocked".to_string()],
                    header_markers: vec![],
                    confidence: 0.90,
                    signature: "error-profile-fortiweb-attack".to_string(),
                },
            ],
            },
            //Radware error profiles
        ErrorProfile {
            provider: "Radware".to_string(),
            patterns: vec![ErrorPagePattern {
                name: "Radware AppWall Block".to_string(),
                status_codes: vec![403],
                body_markers: vec!["appwall".to_string(), "blocked".to_string()],
                header_markers: vec![],
                confidence: 0.90,
                signature: "error-profile-radware-block".to_string(),
            }],
            },
        ];

        Self { profiles }
    }

    /// Match a response against all error profiles
    pub fn match_response(
        &self,
        status_code: u16,
        body: &str,
        headers: &HashMap<String, String>,
    ) -> Vec<Evidence> {
        let mut evidence = Vec::new();
        let body_lower = body.to_lowercase();

        // Convert headers to lowercase for case-insensitive matching
        let headers_lower: HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        for profile in &self.profiles {
            for pattern in &profile.patterns {
                // Check if status code matches
                if !pattern.status_codes.contains(&status_code) {
                    continue;
                }

                // Check if all body markers are present
                let body_match = pattern
                    .body_markers
                    .iter()
                    .all(|marker| body_lower.contains(&marker.to_lowercase()));

                if !body_match {
                    continue;
                }

                // Check header markers (if any)
                let header_match = if pattern.header_markers.is_empty() {
                    true
                } else {
                    pattern.header_markers.iter().any(|(header_name, substring)| {
                        if let Some(header_value) = headers_lower.get(&header_name.to_lowercase()) {
                            if substring.is_empty() {
                                // Just checking for header existence
                                return true;
                            }
                            // Check if substring is in header value
                            return header_value
                                .to_lowercase()
                                .contains(&substring.to_lowercase());
                        }
                        false
                    })
                };

                if !header_match {
                    continue;
                }

                // Pattern matched - create evidence
                evidence.push(Evidence {
                    method_type: MethodType::Body(format!(
                        "error-profile-{}-{}",
                        profile.provider.to_lowercase(),
                        status_code
                    )),
                    confidence: pattern.confidence,
                    description: format!(
                        "{} - {} (status {})",
                        profile.provider, pattern.name, status_code
                    ),
                    raw_data: format!(
                        "status={}, markers={:?}",
                        status_code, pattern.body_markers
                    ),
                    signature_matched: pattern.signature.clone(),
                });
            }
        }

        evidence
    }
}

impl Default for ErrorProfileDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_403_block() {
        let db = ErrorProfileDatabase::new();
        let body = "Attention Required! | Cloudflare\n\
                    This page requires JavaScript. Ray ID: 1234567890abcdef";
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "1234567890abcdef-SEA".to_string());

        let evidence = db.match_response(403, body, &headers);
        assert!(!evidence.is_empty());
        assert!(evidence[0]
            .signature_matched
            .contains("cloudflare-403-block"));
        assert_eq!(evidence[0].confidence, 0.95);
    }

    #[test]
    fn test_aws_waf_block() {
        let db = ErrorProfileDatabase::new();
        let body = "Request blocked by AWS WAF\n\
                    This request has been blocked by our security systems.";
        let headers = HashMap::new();

        let evidence = db.match_response(403, body, &headers);
        assert!(!evidence.is_empty());
        assert!(evidence[0].signature_matched.contains("aws-waf-block"));
    }

    #[test]
    fn test_f5_asm_block() {
        let db = ErrorProfileDatabase::new();
        let body = "The requested URL was rejected. Please consult with your administrator.\n\
                    Support ID: 12345678901234567890";
        let headers = HashMap::new();

        let evidence = db.match_response(403, body, &headers);
        assert!(!evidence.is_empty());
        assert!(evidence[0].signature_matched.contains("f5-asm-block"));
        assert_eq!(evidence[0].confidence, 0.90);
    }

    #[test]
    fn test_imperva_block() {
        let db = ErrorProfileDatabase::new();
        let body = "Request unsuccessful. Incapsula incident ID: 123000000012345678";
        let mut headers = HashMap::new();
        headers.insert("x-iinfo".to_string(), "5-12345-0".to_string());

        let evidence = db.match_response(403, body, &headers);
        assert!(!evidence.is_empty());
        assert!(evidence[0].signature_matched.contains("imperva-block"));
        assert_eq!(evidence[0].confidence, 0.95);
    }

    #[test]
    fn test_modsecurity_block() {
        let db = ErrorProfileDatabase::new();
        let body = "Not Acceptable - ModSecurity\n\
                    An error occurred with the ModSecurity rules.";
        let headers = HashMap::new();

        let evidence = db.match_response(403, body, &headers);
        assert!(!evidence.is_empty());
        assert!(evidence[0].signature_matched.contains("modsecurity"));
    }

    #[test]
    fn test_no_match() {
        let db = ErrorProfileDatabase::new();
        let body = "Generic 404 Not Found";
        let headers = HashMap::new();

        let evidence = db.match_response(404, body, &headers);
        assert!(evidence.is_empty());
    }

    #[test]
    fn test_case_insensitive_matching() {
        let db = ErrorProfileDatabase::new();
        let body = "ATTENTION REQUIRED! | CLOUDFLARE\n\
                    Ray ID: 1234567890abcdef";
        let mut headers = HashMap::new();
        headers.insert("CF-RAY".to_string(), "1234567890abcdef-SEA".to_string());

        let evidence = db.match_response(403, body, &headers);
        assert!(!evidence.is_empty());
    }

    #[test]
    fn test_sucuri_firewall_block() {
        let db = ErrorProfileDatabase::new();
        let body = "Website Firewall\n\
                    Your access to this site has been limited by Sucuri CloudProxy.";
        let headers = HashMap::new();

        let evidence = db.match_response(403, body, &headers);
        assert!(!evidence.is_empty());
        assert!(evidence[0].signature_matched.contains("sucuri-firewall"));
    }

    #[test]
    fn test_fortiweb_block() {
        let db = ErrorProfileDatabase::new();
        let body = "Web Page Blocked!\n\
                    This request has been blocked by FortiWeb.";
        let headers = HashMap::new();

        let evidence = db.match_response(403, body, &headers);
        assert!(!evidence.is_empty());
        assert!(evidence[0].signature_matched.contains("fortiweb-block"));
        assert_eq!(evidence[0].confidence, 0.95);
    }
}
