use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

pub mod engine;
pub mod providers;
pub mod confidence;
pub mod http;
pub mod registry;
pub mod cli;
pub mod utils;
pub mod web;
pub mod script_executor;

// NEW: Advanced confidence and validation modules
pub mod testing;
pub mod timing;
pub mod dns;
pub mod payload;

#[derive(Debug, Clone)]
pub struct DetectionContext {
    pub url: String,
    pub response: Option<http::HttpResponse>,
    pub dns_info: Option<DnsInfo>,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    pub ip_addresses: Vec<String>,
    pub nameservers: Vec<String>,
}

#[async_trait::async_trait]
pub trait DetectionProvider: Send + Sync {
    fn name(&self) -> &str;
    fn provider_type(&self) -> ProviderType;
    fn version(&self) -> &str;
    fn description(&self) -> Option<String>;
    fn confidence_base(&self) -> f64;
    fn priority(&self) -> u32;
    fn enabled(&self) -> bool;
    
    async fn detect(&self, context: &DetectionContext) -> anyhow::Result<Vec<Evidence>>;
    
    async fn passive_detect(&self, _response: &http::HttpResponse) -> anyhow::Result<Vec<Evidence>> {
        Ok(vec![])
    }
    
    async fn active_detect(&self, _client: &http::HttpClient, _url: &str) -> anyhow::Result<Vec<Evidence>> {
        Ok(vec![])
    }
    
    async fn dns_detect(&self, _dns_info: &DnsInfo) -> anyhow::Result<Vec<Evidence>> {
        Ok(vec![])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProviderType {
    WAF,
    CDN,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub method_type: DetectionMethod,
    pub confidence: f64,
    pub description: String,
    pub raw_data: String,
    pub signature_matched: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectionMethod {
    Header(String),
    Body(String),
    StatusCode(u16),
    DNS(String),
    Timing,
    Certificate,
    Payload,
}

// Alias for backward compatibility
pub type MethodType = DetectionMethod;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub url: String,
    pub detected_waf: Option<ProviderDetection>,
    pub detected_cdn: Option<ProviderDetection>,
    pub provider_scores: HashMap<String, f64>,
    pub evidence_map: HashMap<String, Vec<Evidence>>,
    pub detection_time_ms: u64,
    pub metadata: DetectionMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderDetection {
    pub name: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMetadata {
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub user_agent: String,
}

impl DetectionResult {
    pub fn has_waf(&self) -> bool {
        self.detected_waf.is_some()
    }
    
    pub fn has_cdn(&self) -> bool {
        self.detected_cdn.is_some()
    }
    
    pub fn detected(&self) -> bool {
        self.has_waf() || self.has_cdn()
    }
    
    pub fn waf_name(&self) -> Option<&str> {
        self.detected_waf.as_ref().map(|w| w.name.as_str())
    }
    
    pub fn cdn_name(&self) -> Option<&str> {
        self.detected_cdn.as_ref().map(|c| c.name.as_str())
    }
    
    pub fn waf_confidence(&self) -> Option<f64> {
        self.detected_waf.as_ref().map(|w| w.confidence)
    }
    
    pub fn cdn_confidence(&self) -> Option<f64> {
        self.detected_cdn.as_ref().map(|c| c.confidence)
    }
    
    pub fn analysis_time_ms(&self) -> u64 {
        self.detection_time_ms
    }
    
    /// Get all evidence as a flat list for web display
    pub fn evidence(&self) -> Vec<Evidence> {
        self.evidence_map.values().flatten().cloned().collect()
    }
    
    pub fn format_as_table(&self) -> String {
        let mut table = String::new();
        
        // Table header
        table.push_str("┌─────────────────────────────────────────────────────────────────────────┐\n");
        table.push_str("│                            WAF/CDN Detection Results                    │\n");
        table.push_str("├─────────────────────────────────────────────────────────────────────────┤\n");
        
        // URL
        let url_display = if self.url.len() > 67 {
            format!("{}...", &self.url[..64])
        } else {
            self.url.clone()
        };
        table.push_str(&format!("│ URL: {:<67} │\n", url_display));
        table.push_str("├─────────────────────────────────────────────────────────────────────────┤\n");
        
        // WAF Detection
        if let Some(waf) = &self.detected_waf {
            table.push_str(&format!("│ WAF: {:<20} Confidence: {:<6.1}%                    │\n", 
                waf.name, waf.confidence * 100.0));
        } else {
            table.push_str("│ WAF: Not Detected                                                      │\n");
        }
        
        // CDN Detection
        if let Some(cdn) = &self.detected_cdn {
            table.push_str(&format!("│ CDN: {:<20} Confidence: {:<6.1}%                    │\n", 
                cdn.name, cdn.confidence * 100.0));
        } else {
            table.push_str("│ CDN: Not Detected                                                      │\n");
        }
        
        table.push_str("├─────────────────────────────────────────────────────────────────────────┤\n");
        table.push_str(&format!("│ Detection Time: {:<8} ms                                          │\n", 
            self.detection_time_ms));
        table.push_str("├─────────────────────────────────────────────────────────────────────────┤\n");
        
        // Evidence Summary
        table.push_str("│ Evidence Summary:                                                       │\n");
        for (provider, evidence_list) in &self.evidence_map {
            if !evidence_list.is_empty() {
                table.push_str(&format!("│ • {:<20} Evidence Count: {:<3}                          │\n", 
                    provider, evidence_list.len()));
                
                for (i, evidence) in evidence_list.iter().enumerate() {
                    if i < 3 { // Show first 3 evidence items
                        let desc = if evidence.description.len() > 45 {
                            format!("{}...", &evidence.description[..42])
                        } else {
                            evidence.description.clone()
                        };
                        table.push_str(&format!("│   - {:<65} │\n", desc));
                        
                        // Show the raw data if it's short enough
                        if evidence.raw_data.len() <= 50 {
                            table.push_str(&format!("│     Data: {:<59} │\n", evidence.raw_data));
                        }
                    }
                }
                if evidence_list.len() > 3 {
                    table.push_str(&format!("│   ... and {} more evidence items                                     │\n", 
                        evidence_list.len() - 3));
                }
            }
        }
        
        table.push_str("└─────────────────────────────────────────────────────────────────────────┘\n");
        
        table
    }
    
    pub fn format_pretty(&self) -> String {
        let mut output = String::new();
        
        output.push_str(&format!("🔍 Scanning: {}\n\n", self.url));
        output.push_str(&format!("🎯 Detection Results for: {}\n", self.url));
        output.push_str(&format!("⏱️  Detection time: {}ms\n\n", self.detection_time_ms));
        
        if let Some(waf) = &self.detected_waf {
            output.push_str(&format!("🛡️  WAF Detected: {} (Confidence: {:.1}%)\n", 
                waf.name, waf.confidence * 100.0));
        }
        
        if let Some(cdn) = &self.detected_cdn {
            output.push_str(&format!("🌐 CDN Detected: {} (Confidence: {:.1}%)\n", 
                cdn.name, cdn.confidence * 100.0));
        }
        
        output.push_str("\n📊 Evidence Details:\n\n");
        
        for (provider, evidence_list) in &self.evidence_map {
            if !evidence_list.is_empty() {
                output.push_str(&format!("  {} Evidence:\n", provider));
                for evidence in evidence_list {
                    output.push_str(&format!("    • {} (Confidence: {:.1}%)\n", 
                        evidence.description, evidence.confidence * 100.0));
                    output.push_str(&format!("      Data: {}\n", evidence.raw_data));
                }
                output.push('\n');
            }
        }
        
        output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Pretty,
    Table,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "pretty" => Ok(OutputFormat::Pretty),
            "table" => Ok(OutputFormat::Table),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}
