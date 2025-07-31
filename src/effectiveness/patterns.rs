//! Attack Patterns for WAF Testing
//!
//! This module contains categorized attack patterns used for testing WAF effectiveness.
//! Patterns are organized by attack type and include metadata for proper reporting.

use serde::{Deserialize, Serialize};

/// Categories of attack patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternCategory {
    SqlInjection,
    CrossSiteScripting,
    CommandInjection,
    PathTraversal,
    XmlExternalEntity,
    ServerSideRequestForgery,
    TemplateInjection,
    HttpParameterPollution,
}

/// An attack pattern with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub id: String,
    pub name: String,
    pub category: PatternCategory,
    pub pattern: String,
    pub description: String,
    pub risk_level: String,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
}

/// Get all patterns for a category
pub fn get_patterns_by_category(category: PatternCategory) -> Vec<AttackPattern> {
    match category {
        PatternCategory::SqlInjection => sql_injection_patterns(),
        PatternCategory::CrossSiteScripting => xss_patterns(),
        PatternCategory::CommandInjection => command_injection_patterns(),
        PatternCategory::PathTraversal => path_traversal_patterns(),
        PatternCategory::XmlExternalEntity => xxe_patterns(),
        PatternCategory::ServerSideRequestForgery => ssrf_patterns(),
        PatternCategory::TemplateInjection => template_injection_patterns(),
        PatternCategory::HttpParameterPollution => hpp_patterns(),
    }
}

/// SQL Injection patterns
fn sql_injection_patterns() -> Vec<AttackPattern> {
    vec![
        AttackPattern {
            id: "sqli-001".to_string(),
            name: "Basic SQL Injection".to_string(),
            category: PatternCategory::SqlInjection,
            pattern: "' OR '1'='1".to_string(),
            description: "Classic SQL injection attempting to bypass authentication".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "sqli-002".to_string(),
            name: "Union-based SQL Injection".to_string(),
            category: PatternCategory::SqlInjection,
            pattern: "' UNION SELECT NULL,NULL,NULL--".to_string(),
            description: "Attempts to extract data using UNION clause".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "sqli-003".to_string(),
            name: "Time-based Blind SQL Injection".to_string(),
            category: PatternCategory::SqlInjection,
            pattern: "'; WAITFOR DELAY '00:00:05'--".to_string(),
            description: "Blind SQL injection using time delays".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
    ]
}

/// Cross-Site Scripting patterns
fn xss_patterns() -> Vec<AttackPattern> {
    vec![
        AttackPattern {
            id: "xss-001".to_string(),
            name: "Basic Script Tag".to_string(),
            category: PatternCategory::CrossSiteScripting,
            pattern: "<script>alert('XSS')</script>".to_string(),
            description: "Simple XSS using script tags".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-79".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "xss-002".to_string(),
            name: "Event Handler XSS".to_string(),
            category: PatternCategory::CrossSiteScripting,
            pattern: "<img src=x onerror=alert('XSS')>".to_string(),
            description: "XSS using event handlers".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-79".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "xss-003".to_string(),
            name: "SVG-based XSS".to_string(),
            category: PatternCategory::CrossSiteScripting,
            pattern: "<svg onload=alert('XSS')>".to_string(),
            description: "XSS using SVG elements".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-79".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
    ]
}

/// Command Injection patterns
fn command_injection_patterns() -> Vec<AttackPattern> {
    vec![
        AttackPattern {
            id: "cmdi-001".to_string(),
            name: "Basic Command Injection".to_string(),
            category: PatternCategory::CommandInjection,
            pattern: "; ls -la".to_string(),
            description: "Attempts to execute system commands".to_string(),
            risk_level: "CRITICAL".to_string(),
            cwe_id: Some("CWE-78".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "cmdi-002".to_string(),
            name: "Pipe Command Injection".to_string(),
            category: PatternCategory::CommandInjection,
            pattern: "| whoami".to_string(),
            description: "Command injection using pipe operator".to_string(),
            risk_level: "CRITICAL".to_string(),
            cwe_id: Some("CWE-78".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "cmdi-003".to_string(),
            name: "Backtick Command Injection".to_string(),
            category: PatternCategory::CommandInjection,
            pattern: "`id`".to_string(),
            description: "Command injection using backticks".to_string(),
            risk_level: "CRITICAL".to_string(),
            cwe_id: Some("CWE-78".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
    ]
}

/// Path Traversal patterns
fn path_traversal_patterns() -> Vec<AttackPattern> {
    vec![
        AttackPattern {
            id: "path-001".to_string(),
            name: "Basic Path Traversal".to_string(),
            category: PatternCategory::PathTraversal,
            pattern: "../../../etc/passwd".to_string(),
            description: "Attempts to access system files".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-22".to_string()),
            owasp_category: Some("A01:2021".to_string()),
        },
        AttackPattern {
            id: "path-002".to_string(),
            name: "Encoded Path Traversal".to_string(),
            category: PatternCategory::PathTraversal,
            pattern: "..%2F..%2F..%2Fetc%2Fpasswd".to_string(),
            description: "URL encoded path traversal".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-22".to_string()),
            owasp_category: Some("A01:2021".to_string()),
        },
    ]
}

/// XXE patterns
fn xxe_patterns() -> Vec<AttackPattern> {
    vec![AttackPattern {
        id: "xxe-001".to_string(),
        name: "Basic XXE".to_string(),
        category: PatternCategory::XmlExternalEntity,
        pattern: r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#
            .to_string(),
        description: "XML External Entity injection".to_string(),
        risk_level: "HIGH".to_string(),
        cwe_id: Some("CWE-611".to_string()),
        owasp_category: Some("A05:2021".to_string()),
    }]
}

/// SSRF patterns
fn ssrf_patterns() -> Vec<AttackPattern> {
    vec![
        AttackPattern {
            id: "ssrf-001".to_string(),
            name: "AWS Metadata SSRF".to_string(),
            category: PatternCategory::ServerSideRequestForgery,
            pattern: "http://169.254.169.254/latest/meta-data/".to_string(),
            description: "Attempts to access AWS metadata endpoint".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-918".to_string()),
            owasp_category: Some("A10:2021".to_string()),
        },
        AttackPattern {
            id: "ssrf-002".to_string(),
            name: "Internal Network SSRF".to_string(),
            category: PatternCategory::ServerSideRequestForgery,
            pattern: "http://192.168.1.1/admin".to_string(),
            description: "Attempts to access internal network".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-918".to_string()),
            owasp_category: Some("A10:2021".to_string()),
        },
    ]
}

/// Template Injection patterns
fn template_injection_patterns() -> Vec<AttackPattern> {
    vec![AttackPattern {
        id: "ssti-001".to_string(),
        name: "Basic Template Injection".to_string(),
        category: PatternCategory::TemplateInjection,
        pattern: "{{7*7}}".to_string(),
        description: "Server-side template injection test".to_string(),
        risk_level: "HIGH".to_string(),
        cwe_id: Some("CWE-1336".to_string()),
        owasp_category: Some("A03:2021".to_string()),
    }]
}

/// HTTP Parameter Pollution patterns
fn hpp_patterns() -> Vec<AttackPattern> {
    vec![AttackPattern {
        id: "hpp-001".to_string(),
        name: "Duplicate Parameter".to_string(),
        category: PatternCategory::HttpParameterPollution,
        pattern: "id=1&id=2".to_string(),
        description: "HTTP Parameter Pollution with duplicate parameters".to_string(),
        risk_level: "MEDIUM".to_string(),
        cwe_id: Some("CWE-235".to_string()),
        owasp_category: Some("A03:2021".to_string()),
    }]
}
