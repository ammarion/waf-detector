//! Testing Techniques for WAF Effectiveness
//!
//! This module contains various techniques used to test WAF detection capabilities.
//! Techniques are categorized by intensity level and attack type.

use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A testing technique with payload and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestingTechnique {
    pub name: String,
    pub category: String,
    pub method: String,
    pub payload: String,
    pub headers: HashMap<String, String>,
    pub severity: String,
    pub remediation: String,
}

/// Get testing techniques appropriate for the given intensity level
pub fn get_techniques_for_level(level: u8) -> Vec<TestingTechnique> {
    let mut techniques = Vec::new();

    // Level 1-2: Basic detection tests
    if level >= 1 {
        techniques.extend(get_basic_techniques());
    }

    // Level 3: Standard attack patterns
    if level >= 3 {
        techniques.extend(get_standard_techniques());
    }

    // Level 4: Advanced patterns
    if level >= 4 {
        techniques.extend(get_advanced_techniques());
    }

    // Level 5: Evasion included (handled separately)

    techniques
}

/// Get benign testing techniques for false positive testing
pub fn get_benign_techniques() -> Vec<TestingTechnique> {
    vec![
        TestingTechnique {
            name: "Blog post with SQL keywords".to_string(),
            category: "Benign".to_string(),
            method: "POST".to_string(),
            payload:
                "content=Today I learned how to SELECT data FROM a database using WHERE clauses"
                    .to_string(),
            headers: HashMap::from([(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )]),
            severity: "NONE".to_string(),
            remediation: "Benign content should not be blocked".to_string(),
        },
        TestingTechnique {
            name: "Valid path traversal".to_string(),
            category: "Benign".to_string(),
            method: "GET".to_string(),
            payload: "path=/docs/../images/logo.png".to_string(),
            headers: HashMap::new(),
            severity: "NONE".to_string(),
            remediation: "Valid path navigation should be allowed".to_string(),
        },
        TestingTechnique {
            name: "JSON with angle brackets".to_string(),
            category: "Benign".to_string(),
            method: "POST".to_string(),
            payload: r#"{"message": "<b>Hello</b> World"}"#.to_string(),
            headers: HashMap::from([("Content-Type".to_string(), "application/json".to_string())]),
            severity: "NONE".to_string(),
            remediation: "Legitimate HTML in JSON should be allowed".to_string(),
        },
        TestingTechnique {
            name: "Search query with boolean keywords".to_string(),
            category: "Benign".to_string(),
            method: "GET".to_string(),
            payload: "search=red OR blue AND green".to_string(),
            headers: HashMap::new(),
            severity: "NONE".to_string(),
            remediation: "Natural language searches should be allowed".to_string(),
        },
        TestingTechnique {
            name: "HTML tutorial comment".to_string(),
            category: "Benign".to_string(),
            method: "POST".to_string(),
            payload: "comment=I love the <script> tag in HTML tutorials".to_string(),
            headers: HashMap::from([(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )]),
            severity: "NONE".to_string(),
            remediation: "Educational content about HTML should be allowed".to_string(),
        },
        TestingTechnique {
            name: "Valid percent-encoded name".to_string(),
            category: "Benign".to_string(),
            method: "GET".to_string(),
            payload: "name=O%27Brien".to_string(),
            headers: HashMap::new(),
            severity: "NONE".to_string(),
            remediation: "Properly encoded legitimate names should be allowed".to_string(),
        },
        TestingTechnique {
            name: "Mathematical expression".to_string(),
            category: "Benign".to_string(),
            method: "GET".to_string(),
            payload: "calc=1+1=2 OR 2+2=4".to_string(),
            headers: HashMap::new(),
            severity: "NONE".to_string(),
            remediation: "Math expressions should be allowed".to_string(),
        },
        TestingTechnique {
            name: "Legitimate XML content".to_string(),
            category: "Benign".to_string(),
            method: "POST".to_string(),
            payload: r#"data=<note><to>User</to><from>Admin</from></note>"#.to_string(),
            headers: HashMap::from([("Content-Type".to_string(), "application/xml".to_string())]),
            severity: "NONE".to_string(),
            remediation: "Valid XML without external entities should be allowed".to_string(),
        },
    ]
}

/// Basic detection techniques (safe for production)
fn get_basic_techniques() -> Vec<TestingTechnique> {
    vec![
        TestingTechnique {
            name: "Basic SQL Injection".to_string(),
            category: "SQL Injection".to_string(),
            method: "GET".to_string(),
            payload: "id=1'".to_string(),
            headers: HashMap::new(),
            severity: "LOW".to_string(),
            remediation: "Enable basic SQL injection detection rules".to_string(),
        },
        TestingTechnique {
            name: "Simple XSS".to_string(),
            category: "XSS".to_string(),
            method: "GET".to_string(),
            payload: "search=<script>".to_string(),
            headers: HashMap::new(),
            severity: "LOW".to_string(),
            remediation: "Enable XSS detection filters".to_string(),
        },
        TestingTechnique {
            name: "Directory Traversal".to_string(),
            category: "Path Traversal".to_string(),
            method: "GET".to_string(),
            payload: "file=../etc/passwd".to_string(),
            headers: HashMap::new(),
            severity: "MEDIUM".to_string(),
            remediation: "Block directory traversal patterns".to_string(),
        },
    ]
}

/// Standard attack techniques
fn get_standard_techniques() -> Vec<TestingTechnique> {
    vec![
        TestingTechnique {
            name: "Union SQL Injection".to_string(),
            category: "SQL Injection".to_string(),
            method: "GET".to_string(),
            payload: "id=1 UNION SELECT 1,2,3--".to_string(),
            headers: HashMap::new(),
            severity: "HIGH".to_string(),
            remediation: "Detect UNION-based SQL injection attempts".to_string(),
        },
        TestingTechnique {
            name: "Stored XSS Attempt".to_string(),
            category: "XSS".to_string(),
            method: "POST".to_string(),
            payload: "comment=<script>alert(document.cookie)</script>".to_string(),
            headers: HashMap::from([
                ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ]),
            severity: "HIGH".to_string(),
            remediation: "Filter XSS in POST data and stored content".to_string(),
        },
        TestingTechnique {
            name: "Command Injection".to_string(),
            category: "Command Injection".to_string(),
            method: "GET".to_string(),
            payload: "ping=127.0.0.1;id".to_string(),
            headers: HashMap::new(),
            severity: "CRITICAL".to_string(),
            remediation: "Block command injection patterns including semicolons and pipes".to_string(),
        },
        TestingTechnique {
            name: "XXE Attempt".to_string(),
            category: "XXE".to_string(),
            method: "POST".to_string(),
            payload: r#"<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>"#.to_string(),
            headers: HashMap::from([
                ("Content-Type".to_string(), "application/xml".to_string()),
            ]),
            severity: "HIGH".to_string(),
            remediation: "Disable external entity processing in XML parsers".to_string(),
        },
    ]
}

/// Advanced testing techniques
fn get_advanced_techniques() -> Vec<TestingTechnique> {
    vec![
        TestingTechnique {
            name: "Blind SQL Injection".to_string(),
            category: "SQL Injection".to_string(),
            method: "GET".to_string(),
            payload: "id=1 AND SLEEP(5)--".to_string(),
            headers: HashMap::new(),
            severity: "HIGH".to_string(),
            remediation: "Detect time-based SQL injection patterns".to_string(),
        },
        TestingTechnique {
            name: "Polyglot XSS".to_string(),
            category: "XSS".to_string(),
            method: "GET".to_string(),
            payload: r#"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"#.to_string(),
            headers: HashMap::new(),
            severity: "HIGH".to_string(),
            remediation: "Implement context-aware XSS filtering".to_string(),
        },
        TestingTechnique {
            name: "SSRF Attempt".to_string(),
            category: "SSRF".to_string(),
            method: "POST".to_string(),
            payload: "url=http://169.254.169.254/latest/meta-data/".to_string(),
            headers: HashMap::from([
                ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ]),
            severity: "HIGH".to_string(),
            remediation: "Block requests to internal IP ranges and metadata endpoints".to_string(),
        },
        TestingTechnique {
            name: "Template Injection".to_string(),
            category: "Template Injection".to_string(),
            method: "GET".to_string(),
            payload: "name={{7*7}}".to_string(),
            headers: HashMap::new(),
            severity: "HIGH".to_string(),
            remediation: "Sanitize template expressions and block evaluation syntax".to_string(),
        },
    ]
}

/// Get evasion techniques (only for level 5)
pub fn get_evasion_techniques() -> Vec<TestingTechnique> {
    vec![
        TestingTechnique {
            name: "Case Variation SQL Injection".to_string(),
            category: "SQL Injection".to_string(),
            method: "GET".to_string(),
            payload: "id=1 UnIoN SeLeCt 1,2,3--".to_string(),
            headers: HashMap::new(),
            severity: "HIGH".to_string(),
            remediation: "Implement case-insensitive pattern matching".to_string(),
        },
        TestingTechnique {
            name: "Unicode Encoded XSS".to_string(),
            category: "XSS".to_string(),
            method: "GET".to_string(),
            payload:
                "search=%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"
                    .to_string(),
            headers: HashMap::new(),
            severity: "HIGH".to_string(),
            remediation: "Decode all encodings before pattern matching".to_string(),
        },
        TestingTechnique {
            name: "HTTP Parameter Pollution".to_string(),
            category: "HPP".to_string(),
            method: "GET".to_string(),
            payload: "id=1&id=' OR '1'='1".to_string(),
            headers: HashMap::new(),
            severity: "MEDIUM".to_string(),
            remediation: "Handle duplicate parameters correctly".to_string(),
        },
        TestingTechnique {
            name: "Chunked Encoding Bypass".to_string(),
            category: "Protocol".to_string(),
            method: "POST".to_string(),
            payload: "data=normal".to_string(),
            headers: HashMap::from([("Transfer-Encoding".to_string(), "chunked".to_string())]),
            severity: "MEDIUM".to_string(),
            remediation: "Inspect chunked request bodies properly".to_string(),
        },
    ]
}

#[derive(Debug, Clone, Copy)]
pub struct BrowserFingerprint {
    pub user_agent: &'static str,
    pub accept: &'static str,
    pub accept_language: &'static str,
    pub accept_encoding: &'static str,
    pub sec_ch_ua: Option<&'static str>,
    pub sec_ch_ua_mobile: Option<&'static str>,
    pub sec_ch_ua_platform: Option<&'static str>,
}

const BROWSER_FINGERPRINTS: &[BrowserFingerprint] = &[
    BrowserFingerprint {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br",
        sec_ch_ua: Some("\"Chromium\";v=\"122\", \"Not:A-Brand\";v=\"99\", \"Google Chrome\";v=\"122\""),
        sec_ch_ua_mobile: Some("?0"),
        sec_ch_ua_platform: Some("\"Windows\""),
    },
    BrowserFingerprint {
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br",
        sec_ch_ua: Some("\"Chromium\";v=\"122\", \"Not:A-Brand\";v=\"99\", \"Google Chrome\";v=\"122\""),
        sec_ch_ua_mobile: Some("?0"),
        sec_ch_ua_platform: Some("\"macOS\""),
    },
    BrowserFingerprint {
        user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br",
        sec_ch_ua: None,
        sec_ch_ua_mobile: None,
        sec_ch_ua_platform: None,
    },
    BrowserFingerprint {
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br",
        sec_ch_ua: None,
        sec_ch_ua_mobile: None,
        sec_ch_ua_platform: None,
    },
    BrowserFingerprint {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/122.0.0.0 Safari/537.36",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br",
        sec_ch_ua: Some("\"Chromium\";v=\"122\", \"Not:A-Brand\";v=\"99\", \"Microsoft Edge\";v=\"122\""),
        sec_ch_ua_mobile: Some("?0"),
        sec_ch_ua_platform: Some("\"Windows\""),
    },
];

/// User agent strings for diversification
pub fn get_user_agents() -> Vec<&'static str> {
    BROWSER_FINGERPRINTS
        .iter()
        .map(|fp| fp.user_agent)
        .collect()
}

pub fn random_browser_fingerprint() -> BrowserFingerprint {
    let mut rng = rand::thread_rng();
    BROWSER_FINGERPRINTS
        .choose(&mut rng)
        .copied()
        .unwrap_or(BROWSER_FINGERPRINTS[0])
}

pub fn apply_browser_fingerprint_headers(
    headers: &mut HashMap<String, String>,
    fingerprint: BrowserFingerprint,
) {
    fn has_header(headers: &HashMap<String, String>, name: &str) -> bool {
        headers.keys().any(|key| key.eq_ignore_ascii_case(name))
    }

    if !has_header(headers, "User-Agent") {
        headers.insert("User-Agent".to_string(), fingerprint.user_agent.to_string());
    }
    if !has_header(headers, "Accept") {
        headers.insert("Accept".to_string(), fingerprint.accept.to_string());
    }
    if !has_header(headers, "Accept-Language") {
        headers.insert(
            "Accept-Language".to_string(),
            fingerprint.accept_language.to_string(),
        );
    }
    if !has_header(headers, "Accept-Encoding") {
        headers.insert(
            "Accept-Encoding".to_string(),
            fingerprint.accept_encoding.to_string(),
        );
    }
    if let Some(value) = fingerprint.sec_ch_ua {
        if !has_header(headers, "Sec-CH-UA") {
            headers.insert("Sec-CH-UA".to_string(), value.to_string());
        }
    }
    if let Some(value) = fingerprint.sec_ch_ua_mobile {
        if !has_header(headers, "Sec-CH-UA-Mobile") {
            headers.insert("Sec-CH-UA-Mobile".to_string(), value.to_string());
        }
    }
    if let Some(value) = fingerprint.sec_ch_ua_platform {
        if !has_header(headers, "Sec-CH-UA-Platform") {
            headers.insert("Sec-CH-UA-Platform".to_string(), value.to_string());
        }
    }
}

/// Generate random headers for request diversification
pub fn generate_random_headers() -> HashMap<String, String> {
    let mut rng = rand::thread_rng();
    let mut headers = HashMap::new();

    // Realistic browser fingerprint headers
    let fingerprint = random_browser_fingerprint();
    apply_browser_fingerprint_headers(&mut headers, fingerprint);

    // Optional: minor language variation to avoid hardcoding a single locale
    if rng.gen_bool(0.2) {
        let languages = [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "fr-FR,fr;q=0.9",
            "de-DE,de;q=0.9",
        ];
        if let Some(lang) = languages.choose(&mut rng) {
            headers.insert("Accept-Language".to_string(), lang.to_string());
        }
    }

    // Random referer (sometimes)
    if rng.gen_bool(0.7) {
        let referers = [
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://duckduckgo.com/",
            "https://www.yahoo.com/",
        ];
        if let Some(referer) = referers.choose(&mut rng) {
            headers.insert("Referer".to_string(), referer.to_string());
        }
    }

    headers
}

/// Apply timing variations to simulate human behavior
pub fn get_human_like_delay() -> std::time::Duration {
    let mut rng = rand::thread_rng();
    let millis = rng.gen_range(500..3000);
    std::time::Duration::from_millis(millis)
}
