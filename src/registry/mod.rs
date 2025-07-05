//! Provider registry for managing detection providers

use crate::providers::{Provider, ProviderMetadata};
use crate::{DetectionContext, DetectionResult, ProviderDetection, DetectionMetadata};
use crate::confidence::AdvancedScoring; // NEW: Import advanced scoring
use crate::timing::{TimingAnalyzer, TimingConfig}; // NEW: Import timing analysis
use crate::dns::DnsAnalyzer; // NEW: Import DNS analysis
use crate::payload::PayloadAnalyzer; // NEW: Import payload analysis
use dashmap::DashMap;
use std::sync::Arc;
use std::collections::HashMap;
use anyhow::Result;

/// Registry for managing detection providers
#[derive(Debug, Clone)]
pub struct ProviderRegistry {
    providers: Arc<DashMap<String, Provider>>,
    provider_metadata: Arc<DashMap<String, ProviderMetadata>>,
    advanced_scoring: Arc<AdvancedScoring>, // NEW: Advanced confidence scoring
    timing_analyzer: Arc<TimingAnalyzer>, // NEW: Timing analysis
    dns_analyzer: Arc<DnsAnalyzer>, // NEW: DNS analysis
    payload_analyzer: Arc<PayloadAnalyzer>, // NEW: Payload analysis
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: Arc::new(DashMap::new()),
            provider_metadata: Arc::new(DashMap::new()),
            advanced_scoring: Arc::new(AdvancedScoring::new()), // NEW: Initialize advanced scoring
            timing_analyzer: Arc::new(TimingAnalyzer::new(TimingConfig::default())), // NEW: Initialize timing analysis
            dns_analyzer: Arc::new(DnsAnalyzer::new()), // NEW: Initialize DNS analysis
            payload_analyzer: Arc::new(PayloadAnalyzer::new()), // NEW: Initialize payload analysis
        }
    }

    pub fn register_provider(&self, provider: Provider) -> Result<()> {
        let name = provider.name().to_string();
        
        if self.providers.contains_key(&name) {
            return Err(anyhow::anyhow!("Provider '{}' is already registered", name));
        }

        let metadata = ProviderMetadata::from(&provider);
        self.providers.insert(name.clone(), provider);
        self.provider_metadata.insert(name, metadata);
        
        Ok(())
    }

    pub fn get_provider(&self, name: &str) -> Option<Provider> {
        self.providers.get(name).map(|entry| entry.value().clone())
    }

    /// Detect using all registered providers - matches working binary structure
    pub async fn detect_all(&self, context: &DetectionContext) -> Result<DetectionResult> {
        let start_time = std::time::Instant::now();
        
        // Filter enabled providers and sort by priority
        let mut providers: Vec<_> = self.providers
            .iter()
            .filter(|entry| {
                self.provider_metadata
                    .get(entry.key())
                    .map(|meta| meta.enabled)
                    .unwrap_or(false)
            })
            .map(|entry| {
                let provider = entry.value().clone();
                let name = entry.key().clone();
                let priority = self.provider_metadata
                    .get(&name)
                    .map(|meta| meta.priority)
                    .unwrap_or(0);
                (name, provider, priority)
            })
            .collect();
        
        providers.sort_by(|a, b| b.2.cmp(&a.2)); // Sort by priority descending

        let futures: Vec<_> = providers
            .into_iter()
            .map(|(name, provider, _)| {
                let context = context.clone();
                async move {
                    match provider.detect(&context).await {
                        Ok(evidence) => Some((name, evidence, provider.confidence_base())),
                        Err(e) => {
                            eprintln!("Provider '{}' failed: {}", name, e);
                            None
                        }
                    }
                }
            })
            .collect();

        // NEW: Run timing analysis in parallel with provider detection
        let timing_future = {
            let url = context.url.clone();
            let timing_analyzer = Arc::clone(&self.timing_analyzer);
            async move {
                match timing_analyzer.analyze(&url).await {
                    Ok(timing_evidence) => {
                        if !timing_evidence.is_empty() {
                            Some(("TimingAnalysis".to_string(), timing_evidence, 0.85))
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        eprintln!("Timing analysis failed: {}", e);
                        None
                    }
                }
            }
        };

        // NEW: Run DNS analysis in parallel with provider detection
        let dns_future = {
            let url = context.url.clone();
            let dns_analyzer = Arc::clone(&self.dns_analyzer);
            async move {
                match dns_analyzer.analyze(&url).await {
                    Ok(dns_evidence) => {
                        if !dns_evidence.is_empty() {
                            Some(("DnsAnalysis".to_string(), dns_evidence, 0.95))
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        eprintln!("DNS analysis failed: {}", e);
                        None
                    }
                }
            }
        };

        // NEW: Run payload analysis in parallel with provider detection
        let payload_future = {
            let url = context.url.clone();
            let payload_analyzer = Arc::clone(&self.payload_analyzer);
            async move {
                match payload_analyzer.analyze(&url).await {
                    Ok(payload_result) => {
                        let evidence = payload_analyzer.to_evidence(&payload_result);
                        if !evidence.is_empty() {
                            Some(("PayloadAnalysis".to_string(), evidence, payload_result.confidence))
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        eprintln!("Payload analysis failed: {}", e);
                        None
                    }
                }
            }
        };

        // Run all detection techniques in parallel
        let (provider_results, timing_result, dns_result, payload_result) = futures::future::join4(
            futures::future::join_all(futures),
            timing_future,
            dns_future,
            payload_future
        ).await;

        let mut results = provider_results;
        if let Some(timing_result) = timing_result {
            results.push(Some(timing_result));
        }
        if let Some(dns_result) = dns_result {
            results.push(Some(dns_result));
        }
        if let Some(payload_result) = payload_result {
            results.push(Some(payload_result));
        }
        
        let mut provider_scores = HashMap::new();
        let mut evidence_map = HashMap::new();
        let mut best_waf = None;
        let mut best_cdn = None;
        let mut max_confidence = 0.0;

        // Initialize evidence map for all providers (matches working binary)
        for provider_name in self.providers.iter().map(|entry| entry.key().clone()) {
            evidence_map.insert(provider_name, Vec::new());
        }
        
        // Initialize evidence map for additional analysis types
        evidence_map.insert("TimingAnalysis".to_string(), Vec::new());
        evidence_map.insert("DnsAnalysis".to_string(), Vec::new());
        evidence_map.insert("PayloadAnalysis".to_string(), Vec::new());

        // Track best WAF and CDN separately to support multi-vendor scenarios
        let mut best_waf_confidence = 0.0;
        let mut best_cdn_confidence = 0.0;

        for result in results.into_iter().flatten() {
            let (name, evidence, _base_confidence) = result;
            
            // Always insert evidence (even if empty) to match working binary structure
            evidence_map.insert(name.clone(), evidence.clone());
            
            if !evidence.is_empty() {
                // NEW: Use advanced confidence scoring instead of simple average
                let response_headers = context.response
                    .as_ref()
                    .map(|r| r.headers.clone())
                    .unwrap_or_default();
                let confidence_result = self.advanced_scoring.calculate_confidence(&name, &evidence, &response_headers);
                let final_confidence = confidence_result.score;
                
                provider_scores.insert(name.clone(), final_confidence);
                
                // Update max_confidence for backward compatibility
                if final_confidence > max_confidence {
                    max_confidence = final_confidence;
                }
                
                // Determine best WAF and CDN providers separately
                if let Some(metadata) = self.provider_metadata.get(&name) {
                    match metadata.provider_type.as_str() {
                        "WAF Only" => {
                            if final_confidence > best_waf_confidence {
                                best_waf_confidence = final_confidence;
                                best_waf = Some(ProviderDetection {
                                    name: name.clone(),
                                    confidence: final_confidence,
                                });
                            }
                        }
                        "CDN Only" => {
                            if final_confidence > best_cdn_confidence {
                                best_cdn_confidence = final_confidence;
                                best_cdn = Some(ProviderDetection {
                                    name: name.clone(),
                                    confidence: final_confidence,
                                });
                            }
                        }
                        "Both" => {
                            // Provider that can do both - compete for both roles
                            if final_confidence > best_waf_confidence {
                                best_waf_confidence = final_confidence;
                                best_waf = Some(ProviderDetection {
                                    name: name.clone(),
                                    confidence: final_confidence,
                                });
                            }
                            if final_confidence > best_cdn_confidence {
                                best_cdn_confidence = final_confidence;
                                best_cdn = Some(ProviderDetection {
                                    name: name.clone(),
                                    confidence: final_confidence,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        let detection_time = start_time.elapsed().as_millis() as u64;

        // Create metadata matching working binary
        let metadata = DetectionMetadata {
            timestamp: chrono::Utc::now(),
            version: "0.1.0".to_string(),
            user_agent: "WAF-Detector/1.0".to_string(),
        };

        Ok(DetectionResult {
            url: context.url.clone(),
            detected_waf: best_waf,
            detected_cdn: best_cdn,
            provider_scores,
            evidence_map,
            detection_time_ms: detection_time,
            metadata,
        })
    }

    pub fn list_providers(&self) -> Vec<ProviderMetadata> {
        let mut providers: Vec<_> = self.provider_metadata
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        providers.sort_by(|a, b| b.priority.cmp(&a.priority));
        providers
    }

    pub fn get_provider_count(&self) -> usize {
        self.providers.len()
    }

    pub fn is_provider_registered(&self, name: &str) -> bool {
        self.providers.contains_key(name)
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}
