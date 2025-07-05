//! Payload-based probing for WAF detection
//! 
//! This module implements wafw00f-style detection using malicious payloads
//! to trigger WAF responses and analyze the differences.

pub mod waf_smoke_test;

use crate::{Evidence, MethodType};
use crate::http::HttpClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Payload-based probing analyzer
#[derive(Debug, Clone)]
pub struct PayloadAnalyzer {
    http_client: Arc<HttpClient>,
    config: PayloadConfig,
}

/// Configuration for payload analysis
#[derive(Debug, Clone)]
pub struct PayloadConfig {
    /// Maximum number of payloads to test per category
    pub max_payloads_per_category: usize,
    /// Timeout for each payload request
    pub request_timeout: Duration,
    /// Delay between payload requests to avoid overwhelming servers
    pub request_delay: Duration,
    /// Enable aggressive testing (more payloads)
    pub aggressive_mode: bool,
}

/// Categories of payloads for different attack types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PayloadCategory {
    XSS,
    SQLInjection,
    CommandInjection,
    PathTraversal,
    RemoteFileInclusion,
    XMLInjection,
    NoSQLInjection,
}

/// Individual payload definition
#[derive(Debug, Clone)]
pub struct Payload {
    pub category: PayloadCategory,
    pub payload: String,
    pub description: String,
    pub expected_blocks: Vec<String>, // Expected WAF blocking patterns
}

/// Result of payload analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadAnalysisResult {
    pub detected_waf: Option<String>,
    pub confidence: f64,
    pub blocked_payloads: Vec<BlockedPayload>,
    pub baseline_response: BaselineInfo,
    pub analysis_time_ms: u64,
}

/// Information about a blocked payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedPayload {
    pub category: PayloadCategory,
    pub payload: String,
    pub response_status: u16,
    pub response_headers: HashMap<String, String>,
    pub response_body_sample: String,
    pub block_reason: String,
}

/// Baseline response information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineInfo {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body_length: usize,
    pub response_time_ms: u64,
}

impl Default for PayloadConfig {
    fn default() -> Self {
        Self {
            max_payloads_per_category: 3,
            request_timeout: Duration::from_secs(10),
            request_delay: Duration::from_millis(500),
            aggressive_mode: false,
        }
    }
}

impl PayloadAnalyzer {
    pub fn new() -> Self {
        Self {
            http_client: Arc::new(HttpClient::default()),
            config: PayloadConfig::default(),
        }
    }

    pub fn with_config(mut self, config: PayloadConfig) -> Self {
        self.config = config;
        self
    }

    /// Analyze URL using payload-based probing
    pub async fn analyze(&self, url: &str) -> Result<PayloadAnalysisResult, anyhow::Error> {
        let start_time = Instant::now();

        // Step 1: Get baseline response
        let baseline = self.get_baseline_response(url).await?;

        // Step 2: Test payloads
        let blocked_payloads = self.test_payloads(url, &baseline).await?;

        // Step 3: Analyze results and determine WAF
        let (detected_waf, confidence) = self.analyze_blocked_payloads(&blocked_payloads);

        let analysis_time = start_time.elapsed().as_millis() as u64;

        Ok(PayloadAnalysisResult {
            detected_waf,
            confidence,
            blocked_payloads,
            baseline_response: baseline,
            analysis_time_ms: analysis_time,
        })
    }

    /// Get baseline response for comparison
    async fn get_baseline_response(&self, url: &str) -> Result<BaselineInfo, anyhow::Error> {
        let start_time = Instant::now();
        
        let response = self.http_client.get(url).await?;
        let response_time = start_time.elapsed().as_millis() as u64;

        Ok(BaselineInfo {
            status: response.status,
            headers: response.headers.clone(),
            body_length: response.body.len(),
            response_time_ms: response_time,
        })
    }

    /// Test various payloads against the target
    async fn test_payloads(&self, base_url: &str, baseline: &BaselineInfo) -> Result<Vec<BlockedPayload>, anyhow::Error> {
        let mut blocked_payloads = Vec::new();
        let payloads = self.get_test_payloads();

        for payload in payloads {
            // Add delay to avoid overwhelming the server
            tokio::time::sleep(self.config.request_delay).await;

            if let Ok(blocked_payload) = self.test_single_payload(base_url, &payload, baseline).await {
                if let Some(blocked) = blocked_payload {
                    blocked_payloads.push(blocked);
                }
            }
        }

        Ok(blocked_payloads)
    }

    /// Test a single payload
    async fn test_single_payload(
        &self,
        base_url: &str,
        payload: &Payload,
        baseline: &BaselineInfo,
    ) -> Result<Option<BlockedPayload>, anyhow::Error> {
        
        // Construct URL with payload as query parameter
        let test_url = format!("{}?test={}", base_url, urlencoding::encode(&payload.payload));

        match self.http_client.get(&test_url).await {
            Ok(response) => {
                // Check if response indicates blocking
                if self.is_blocked_response(&response, baseline, payload) {
                    let block_reason = self.determine_block_reason(&response, payload);
                    
                    let blocked = BlockedPayload {
                        category: payload.category.clone(),
                        payload: payload.payload.clone(),
                        response_status: response.status,
                        response_headers: response.headers.clone(),
                        response_body_sample: response.body.chars().take(200).collect(),
                        block_reason,
                    };
                    
                    return Ok(Some(blocked));
                }
            }
            Err(_) => {
                // Connection errors might indicate blocking
                if baseline.status == 200 {
                    let blocked = BlockedPayload {
                        category: payload.category.clone(),
                        payload: payload.payload.clone(),
                        response_status: 0,
                        response_headers: HashMap::new(),
                        response_body_sample: "Connection refused".to_string(),
                        block_reason: "Connection refused - likely blocked".to_string(),
                    };
                    
                    return Ok(Some(blocked));
                }
            }
        }

        Ok(None)
    }

    /// Check if response indicates the request was blocked
    fn is_blocked_response(
        &self,
        response: &crate::http::HttpResponse,
        baseline: &BaselineInfo,
        payload: &Payload,
    ) -> bool {
        // Status code differences
        if response.status != baseline.status && 
           (response.status == 403 || response.status == 406 || 
            response.status == 429 || response.status == 503) {
            return true;
        }

        // Check for WAF-specific blocking indicators in headers
        for (key, value) in &response.headers {
            let key_lower = key.to_lowercase();
            let value_lower = value.to_lowercase();
            
            if key_lower.contains("blocked") || key_lower.contains("security") ||
               value_lower.contains("blocked") || value_lower.contains("forbidden") ||
               value_lower.contains("violation") || value_lower.contains("waf") {
                return true;
            }
        }

        // Check for blocking patterns in response body
        let body_lower = response.body.to_lowercase();
        let blocking_indicators = [
            "access denied", "blocked", "forbidden", "security violation",
            "malicious request", "attack detected", "suspicious activity",
            "request blocked", "security alert", "threat detected"
        ];

        for indicator in &blocking_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        // Check for expected blocking patterns specific to this payload
        for expected_block in &payload.expected_blocks {
            if body_lower.contains(&expected_block.to_lowercase()) {
                return true;
            }
        }

        // Significant body length differences might indicate blocking
        let body_length_diff = (response.body.len() as i64 - baseline.body_length as i64).abs();
        if body_length_diff > 1000 && response.body.len() < baseline.body_length / 2 {
            return true;
        }

        false
    }

    /// Determine the reason for blocking
    fn determine_block_reason(
        &self,
        response: &crate::http::HttpResponse,
        payload: &Payload,
    ) -> String {
        if response.status == 403 {
            return "HTTP 403 Forbidden - Access blocked".to_string();
        }
        
        if response.status == 406 {
            return "HTTP 406 Not Acceptable - Request blocked".to_string();
        }

        if response.status == 429 {
            return "HTTP 429 Too Many Requests - Rate limited".to_string();
        }

        // Check response body for specific error messages
        let body_lower = response.body.to_lowercase();
        if body_lower.contains("cloudflare") {
            return "CloudFlare security check".to_string();
        }
        if body_lower.contains("akamai") {
            return "Akamai security block".to_string();
        }
        if body_lower.contains("aws") && body_lower.contains("waf") {
            return "AWS WAF block".to_string();
        }

        format!("Payload blocked: {} attack detected", 
                format!("{:?}", payload.category))
    }

    /// Analyze blocked payloads to determine WAF type
    fn analyze_blocked_payloads(&self, blocked_payloads: &[BlockedPayload]) -> (Option<String>, f64) {
        if blocked_payloads.is_empty() {
            return (None, 0.0);
        }

        let mut waf_indicators: HashMap<String, f64> = HashMap::new();
        
        for blocked in blocked_payloads {
            // Analyze response headers for WAF signatures
            for (key, value) in &blocked.response_headers {
                if let Some(waf) = self.identify_waf_from_header(key, value) {
                    *waf_indicators.entry(waf).or_insert(0.0) += 0.3;
                }
            }

            // Analyze response body for WAF signatures  
            if let Some(waf) = self.identify_waf_from_body(&blocked.response_body_sample) {
                *waf_indicators.entry(waf).or_insert(0.0) += 0.2;
            }

            // Analyze status codes
            match blocked.response_status {
                403 => *waf_indicators.entry("Generic WAF".to_string()).or_insert(0.0) += 0.1,
                406 => *waf_indicators.entry("ModSecurity".to_string()).or_insert(0.0) += 0.15,
                _ => {}
            }
        }

        // Add confidence based on number of blocked payloads
        let block_confidence = (blocked_payloads.len() as f64 * 0.1).min(0.5);
        for value in waf_indicators.values_mut() {
            *value += block_confidence;
        }

        // Find the most likely WAF
        if let Some((waf, confidence)) = waf_indicators.iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal)) {
            (Some(waf.clone()), *confidence)
        } else {
            (Some("Unknown WAF".to_string()), 0.3)
        }
    }

    /// Identify WAF from response headers
    fn identify_waf_from_header(&self, key: &str, value: &str) -> Option<String> {
        let key_lower = key.to_lowercase();
        let value_lower = value.to_lowercase();

        if key_lower.contains("cf-") || value_lower.contains("cloudflare") {
            return Some("CloudFlare".to_string());
        }
        if key_lower.contains("x-amz") || value_lower.contains("aws") {
            return Some("AWS WAF".to_string());
        }
        if key_lower.contains("akamai") || value_lower.contains("akamai") {
            return Some("Akamai".to_string());
        }
        if key_lower.contains("x-sucuri") || value_lower.contains("sucuri") {
            return Some("Sucuri".to_string());
        }
        if key_lower.contains("x-denied-reason") || key_lower.contains("x-wzws") {
            return Some("WebZealots".to_string());
        }

        None
    }

    /// Identify WAF from response body
    fn identify_waf_from_body(&self, body: &str) -> Option<String> {
        let body_lower = body.to_lowercase();

        if body_lower.contains("cloudflare") || body_lower.contains("cf-ray") {
            return Some("CloudFlare".to_string());
        }
        if body_lower.contains("akamai") {
            return Some("Akamai".to_string());
        }
        if body_lower.contains("aws") && body_lower.contains("waf") {
            return Some("AWS WAF".to_string());
        }
        if body_lower.contains("modsecurity") {
            return Some("ModSecurity".to_string());
        }
        if body_lower.contains("f5") || body_lower.contains("bigip") {
            return Some("F5 BIG-IP".to_string());
        }

        None
    }

    /// Get test payloads for different attack categories
    fn get_test_payloads(&self) -> Vec<Payload> {
        let mut payloads = Vec::new();

        // XSS payloads
        payloads.extend(vec![
            Payload {
                category: PayloadCategory::XSS,
                payload: "<script>alert('XSS')</script>".to_string(),
                description: "Basic XSS payload".to_string(),
                expected_blocks: vec!["xss".to_string(), "script".to_string()],
            },
            Payload {
                category: PayloadCategory::XSS,
                payload: "javascript:alert('XSS')".to_string(),
                description: "JavaScript URI XSS".to_string(),
                expected_blocks: vec!["javascript".to_string()],
            },
            Payload {
                category: PayloadCategory::XSS,
                payload: "<img src=x onerror=alert('XSS')>".to_string(),
                description: "Image onerror XSS".to_string(),
                expected_blocks: vec!["onerror".to_string(), "img".to_string()],
            },
        ]);

        // SQL Injection payloads
        payloads.extend(vec![
            Payload {
                category: PayloadCategory::SQLInjection,
                payload: "' OR '1'='1".to_string(),
                description: "Basic SQL injection".to_string(),
                expected_blocks: vec!["sql".to_string(), "injection".to_string()],
            },
            Payload {
                category: PayloadCategory::SQLInjection,
                payload: "1; DROP TABLE users--".to_string(),
                description: "SQL DROP TABLE".to_string(),
                expected_blocks: vec!["drop".to_string(), "table".to_string()],
            },
            Payload {
                category: PayloadCategory::SQLInjection,
                payload: "UNION SELECT * FROM users".to_string(),
                description: "SQL UNION attack".to_string(),
                expected_blocks: vec!["union".to_string(), "select".to_string()],
            },
        ]);

        // Command Injection payloads  
        payloads.extend(vec![
            Payload {
                category: PayloadCategory::CommandInjection,
                payload: "; cat /etc/passwd".to_string(),
                description: "Unix command injection".to_string(),
                expected_blocks: vec!["command".to_string(), "injection".to_string()],
            },
            Payload {
                category: PayloadCategory::CommandInjection,
                payload: "| whoami".to_string(),
                description: "Pipe command injection".to_string(),
                expected_blocks: vec!["whoami".to_string()],
            },
        ]);

        // Path Traversal payloads
        payloads.extend(vec![
            Payload {
                category: PayloadCategory::PathTraversal,
                payload: "../../../etc/passwd".to_string(),
                description: "Path traversal attack".to_string(),
                expected_blocks: vec!["traversal".to_string(), "directory".to_string()],
            },
            Payload {
                category: PayloadCategory::PathTraversal,
                payload: "....//....//....//etc/passwd".to_string(),
                description: "Double dot traversal".to_string(),
                expected_blocks: vec!["traversal".to_string()],
            },
        ]);

        if self.config.aggressive_mode {
            // Add more aggressive payloads
            payloads.extend(self.get_aggressive_payloads());
        }

        // Limit payloads per category
        let mut limited_payloads = Vec::new();
        let mut category_counts: HashMap<PayloadCategory, usize> = HashMap::new();

        for payload in payloads {
            let count = category_counts.entry(payload.category.clone()).or_insert(0);
            if *count < self.config.max_payloads_per_category {
                limited_payloads.push(payload);
                *count += 1;
            }
        }

        limited_payloads
    }

    /// Get aggressive payloads for more thorough testing
    fn get_aggressive_payloads(&self) -> Vec<Payload> {
        vec![
            Payload {
                category: PayloadCategory::XMLInjection,
                payload: "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY test SYSTEM \"file:///etc/passwd\">]><test>&test;</test>".to_string(),
                description: "XXE injection".to_string(),
                expected_blocks: vec!["xxe".to_string(), "xml".to_string()],
            },
            Payload {
                category: PayloadCategory::NoSQLInjection,
                payload: "'; return db.users.find(); var dummy='".to_string(),
                description: "NoSQL injection".to_string(),
                expected_blocks: vec!["nosql".to_string()],
            },
        ]
    }

    /// Convert analysis to Evidence for integration with detection system
    pub fn to_evidence(&self, analysis: &PayloadAnalysisResult) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        if let Some(waf_name) = &analysis.detected_waf {
            evidence.push(Evidence {
                method_type: MethodType::Payload,
                confidence: analysis.confidence,
                description: format!("Payload-based detection: {} blocked {} payloads", 
                                   waf_name, analysis.blocked_payloads.len()),
                raw_data: format!("Blocked categories: {:?}", 
                                analysis.blocked_payloads.iter()
                                .map(|b| &b.category)
                                .collect::<Vec<_>>()),
                signature_matched: format!("payload_detection_{}", 
                                         waf_name.to_lowercase().replace(" ", "_")),
            });

            // Add specific evidence for each blocked payload
            for (i, blocked) in analysis.blocked_payloads.iter().enumerate() {
                if i < 3 { // Limit to first 3 for brevity
                    evidence.push(Evidence {
                        method_type: MethodType::Payload,
                        confidence: 0.7,
                        description: format!("Blocked {:?} payload: {}", 
                                           blocked.category, blocked.block_reason),
                        raw_data: format!("Status: {}, Payload: {}", 
                                        blocked.response_status, 
                                        blocked.payload.chars().take(50).collect::<String>()),
                        signature_matched: format!("blocked_{:?}_payload", blocked.category)
                            .to_lowercase(),
                    });
                }
            }
        }

        evidence
    }
}

impl Default for PayloadAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
