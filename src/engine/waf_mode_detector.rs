//! WAF Mode Detection Engine
//! 
//! This module implements active probing to determine WAF behavior:
//! - Blocking Mode: WAF actively blocks malicious requests
//! - Monitoring Mode: WAF logs but allows requests through
//! - Mixed Mode: WAF blocks some but not all malicious requests

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use crate::http::HttpClient;

/// WAF operational mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WafMode {
    /// WAF is actively blocking malicious requests
    Blocking,
    /// WAF is logging but not blocking requests  
    Monitoring,
    /// WAF blocks some requests but allows others
    Mixed,
    /// Unable to determine WAF behavior
    Unknown,
}

impl std::fmt::Display for WafMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WafMode::Blocking => write!(f, "Blocking"),
            WafMode::Monitoring => write!(f, "Monitoring"),
            WafMode::Mixed => write!(f, "Mixed"),
            WafMode::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Types of payloads for testing WAF behavior
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PayloadType {
    XssBasic,
    XssAdvanced,
    SqlInjectionBasic,
    SqlInjectionAdvanced,
    PathTraversal,
    CommandInjection,
    FileUpload,
    ScannerDetection,
    Enumeration,
}

impl std::fmt::Display for PayloadType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadType::XssBasic => write!(f, "XSS Basic"),
            PayloadType::XssAdvanced => write!(f, "XSS Advanced"),
            PayloadType::SqlInjectionBasic => write!(f, "SQL Injection Basic"),
            PayloadType::SqlInjectionAdvanced => write!(f, "SQL Injection Advanced"),
            PayloadType::PathTraversal => write!(f, "Path Traversal"),
            PayloadType::CommandInjection => write!(f, "Command Injection"),
            PayloadType::FileUpload => write!(f, "File Upload"),
            PayloadType::ScannerDetection => write!(f, "Scanner Detection"),
            PayloadType::Enumeration => write!(f, "Enumeration"),
        }
    }
}

/// Result of a single probe test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub payload_type: PayloadType,
    pub payload: String,
    pub response_status: u16,
    pub blocked: bool,
    pub evidence: Vec<String>,
    pub response_time_ms: u64,
}

/// Complete WAF mode detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafModeResult {
    pub mode: WafMode,
    pub confidence: f64,
    pub test_results: Vec<ProbeResult>,
    pub detection_time_ms: u64,
}

/// WAF Mode Detector
#[derive(Debug, Clone)]
pub struct WafModeDetector {
    http_client: HttpClient,
    payloads: HashMap<PayloadType, Vec<String>>,
}

impl WafModeDetector {
    pub fn new() -> Self {
        let http_client = HttpClient::new().expect("Failed to create HTTP client");
        let payloads = Self::initialize_payloads();

        Self {
            http_client,
            payloads,
        }
    }

    /// Initialize test payloads for different attack vectors
    fn initialize_payloads() -> HashMap<PayloadType, Vec<String>> {
        let mut payloads = HashMap::new();

        // XSS Payloads
        payloads.insert(PayloadType::XssBasic, vec![
            "<script>alert('XSS')</script>".to_string(),
            "<img src=x onerror=alert('XSS')>".to_string(),
            "javascript:alert('XSS')".to_string(),
        ]);

        payloads.insert(PayloadType::XssAdvanced, vec![
            "<svg onload=alert('XSS')>".to_string(),
            "';alert('XSS');//".to_string(),
            "\"><script>alert('XSS')</script>".to_string(),
        ]);

        // SQL Injection Payloads
        payloads.insert(PayloadType::SqlInjectionBasic, vec![
            "' OR '1'='1".to_string(),
            "'; DROP TABLE users; --".to_string(),
            "1' UNION SELECT NULL,NULL,NULL--".to_string(),
        ]);

        payloads.insert(PayloadType::SqlInjectionAdvanced, vec![
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--".to_string(),
            "'; WAITFOR DELAY '00:00:05'--".to_string(),
            "' OR 1=1 LIMIT 1 OFFSET 0--".to_string(),
        ]);

        // Path Traversal
        payloads.insert(PayloadType::PathTraversal, vec![
            "../../../etc/passwd".to_string(),
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts".to_string(),
            "....//....//....//etc/passwd".to_string(),
        ]);

        // Command Injection
        payloads.insert(PayloadType::CommandInjection, vec![
            "; cat /etc/passwd".to_string(),
            "| whoami".to_string(),
            "`id`".to_string(),
        ]);

        // File Upload
        payloads.insert(PayloadType::FileUpload, vec![
            "shell.php".to_string(),
            "test.php%00.jpg".to_string(),
            "../../../shell.php".to_string(),
        ]);

        // Scanner Detection
        payloads.insert(PayloadType::ScannerDetection, vec![
            "sqlmap".to_string(),
            "nikto".to_string(),
            "nessus".to_string(),
        ]);

        // Enumeration
        payloads.insert(PayloadType::Enumeration, vec![
            "admin".to_string(),
            "administrator".to_string(),
            "config.php".to_string(),
        ]);

        payloads
    }

    /// Detect WAF mode by sending test payloads
    pub async fn detect_mode(&self, url: &str, custom_headers: Option<HashMap<String, String>>) -> Result<WafModeResult> {
        let start_time = Instant::now();
        let mut test_results = Vec::new();

        // Test each payload type
        for (payload_type, payloads) in &self.payloads {
            for payload in payloads {
                let result = self.test_payload(url, payload_type.clone(), payload, &custom_headers).await?;
                test_results.push(result);
            }
        }

        let detection_time = start_time.elapsed();

        // Analyze results to determine mode
        let (mode, confidence) = self.analyze_results(&test_results);

        Ok(WafModeResult {
            mode,
            confidence,
            test_results,
            detection_time_ms: detection_time.as_millis() as u64,
        })
    }

    /// Test a single payload against the target
    async fn test_payload(
        &self,
        base_url: &str,
        payload_type: PayloadType,
        payload: &str,
        _custom_headers: &Option<HashMap<String, String>>,
    ) -> Result<ProbeResult> {
        let start_time = Instant::now();

        // URL encode the payload
        let encoded_payload = urlencoding::encode(payload);
        let test_url = format!("{}?test={}", base_url, encoded_payload);

        let response = self.http_client.get(&test_url).await?;
        let response_time = start_time.elapsed();

        // Determine if request was blocked
        let (blocked, evidence) = self.analyze_response(&response, payload);

        Ok(ProbeResult {
            payload_type,
            payload: payload.to_string(),
            response_status: response.status,
            blocked,
            evidence,
            response_time_ms: response_time.as_millis() as u64,
        })
    }

    /// Analyze HTTP response to determine if request was blocked
    fn analyze_response(&self, response: &crate::http::HttpResponse, payload: &str) -> (bool, Vec<String>) {
        let mut evidence = Vec::new();
        let mut blocked = false;

        // Check status codes that typically indicate blocking
        match response.status {
            403 | 406 | 418 | 429 | 503 => {
                blocked = true;
                evidence.push(format!("Blocking status code: {}", response.status));
            }
            _ => {}
        }

        // Check response headers for WAF indicators
        for (name, value) in &response.headers {
            let name_lower = name.to_lowercase();
            let value_lower = value.to_lowercase();

            if name_lower.contains("x-blocked") || 
               name_lower.contains("x-denied") ||
               value_lower.contains("blocked") ||
               value_lower.contains("denied") ||
               value_lower.contains("forbidden") {
                blocked = true;
                evidence.push(format!("Blocking header: {}: {}", name, value));
            }
        }

        // Check response body for blocking indicators
        let body_lower = response.body.to_lowercase();
        let blocking_keywords = [
            "access denied", "blocked", "forbidden", "not allowed",
            "security violation", "malicious request", "attack detected",
            "waf", "firewall", "protection", "security policy"
        ];

        for keyword in &blocking_keywords {
            if body_lower.contains(keyword) {
                blocked = true;
                evidence.push(format!("Blocking keyword in body: {}", keyword));
                break;
            }
        }

        // Check if the payload is reflected (might indicate monitoring mode)
        if !blocked && response.body.contains(payload) {
            evidence.push("Payload reflected in response (possible monitoring mode)".to_string());
        }

        (blocked, evidence)
    }

    /// Analyze all test results to determine overall WAF mode
    fn analyze_results(&self, results: &[ProbeResult]) -> (WafMode, f64) {
        if results.is_empty() {
            return (WafMode::Unknown, 0.0);
        }

        let total_tests = results.len();
        let blocked_tests = results.iter().filter(|r| r.blocked).count();
        let block_rate = blocked_tests as f64 / total_tests as f64;

        // Determine mode based on block rate
        let (mode, confidence) = match block_rate {
            rate if rate >= 0.8 => (WafMode::Blocking, 0.9),
            rate if rate >= 0.3 => (WafMode::Mixed, 0.7),
            rate if rate > 0.0 => (WafMode::Mixed, 0.6),
            _ => {
                // Check if any responses indicate monitoring
                let has_monitoring_indicators = results.iter().any(|r| {
                    r.evidence.iter().any(|e| e.contains("monitoring") || e.contains("reflected"))
                });
                
                if has_monitoring_indicators {
                    (WafMode::Monitoring, 0.7)
                } else {
                    (WafMode::Unknown, 0.3)
                }
            }
        };

        (mode, confidence)
    }
}

impl Default for WafModeDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_initialization() {
        let detector = WafModeDetector::new();
        assert!(!detector.payloads.is_empty());
        assert!(detector.payloads.contains_key(&PayloadType::XssBasic));
        assert!(detector.payloads.contains_key(&PayloadType::SqlInjectionBasic));
    }

    #[test]
    fn test_mode_analysis() {
        let detector = WafModeDetector::new();
        
        // Test blocking mode
        let blocking_results = vec![
            ProbeResult {
                payload_type: PayloadType::XssBasic,
                payload: "test".to_string(),
                response_status: 403,
                blocked: true,
                evidence: vec!["Blocked".to_string()],
                response_time_ms: 100,
            },
            ProbeResult {
                payload_type: PayloadType::SqlInjectionBasic,
                payload: "test".to_string(),
                response_status: 403,
                blocked: true,
                evidence: vec!["Blocked".to_string()],
                response_time_ms: 100,
            },
        ];
        
        let (mode, confidence) = detector.analyze_results(&blocking_results);
        assert_eq!(mode, WafMode::Blocking);
        assert!(confidence > 0.8);
    }
}
