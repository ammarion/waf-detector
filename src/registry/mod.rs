//! Provider registry for managing detection providers

use crate::confidence::AdvancedScoring; // NEW: Import advanced scoring
use crate::dns::DnsAnalyzer; // NEW: Import DNS analysis
use crate::payload::PayloadAnalyzer; // NEW: Import payload analysis
use crate::providers::{Provider, ProviderMetadata};
use crate::timing::{TimingAnalyzer, TimingConfig}; // NEW: Import timing analysis
use crate::tls::TlsAnalyzer;
use crate::{DetectionContext, DetectionMetadata, DetectionResult, ProviderDetection};
use anyhow::Result;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Registry for managing detection providers
#[derive(Debug, Clone)]
pub struct ProviderRegistry {
    providers: Arc<DashMap<String, Provider>>,
    provider_metadata: Arc<DashMap<String, ProviderMetadata>>,
    advanced_scoring: Arc<AdvancedScoring>, // NEW: Advanced confidence scoring
    timing_analyzer: Arc<TimingAnalyzer>,   // NEW: Timing analysis
    dns_analyzer: Arc<DnsAnalyzer>,         // NEW: DNS analysis
    payload_analyzer: Arc<PayloadAnalyzer>, // NEW: Payload analysis
    tls_analyzer: Arc<TlsAnalyzer>,
    payload_analysis_enabled: Arc<AtomicBool>,
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
            tls_analyzer: Arc::new(TlsAnalyzer::new()),
            payload_analysis_enabled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_payload_analysis_enabled(&self, enabled: bool) {
        self.payload_analysis_enabled
            .store(enabled, Ordering::Relaxed);
    }

    pub fn payload_analysis_enabled(&self) -> bool {
        self.payload_analysis_enabled.load(Ordering::Relaxed)
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
        let mut providers: Vec<_> = self
            .providers
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
                let priority = self
                    .provider_metadata
                    .get(&name)
                    .map(|meta| meta.priority)
                    .unwrap_or(0);
                (name, provider, priority)
            })
            .collect();

        providers.sort_by(|a, b| b.2.cmp(&a.2)); // Sort by priority descending

        let provider_futures: Vec<_> = providers
            .into_iter()
            .map(|(name, provider, _)| {
                let context = context.clone();
                async move {
                    match provider.detect(&context).await {
                        Ok(evidence) => Some((name, evidence, provider.confidence_base())),
                        Err(e) => {
                            eprintln!("Provider '{name}' failed: {e}");
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
                        eprintln!("Timing analysis failed: {e}");
                        None
                    }
                }
            }
        };

        // NEW: Run DNS analysis in parallel with provider detection
        let dns_future = {
            let dns_info = context.dns_info.clone();
            let dns_analyzer = Arc::clone(&self.dns_analyzer);
            async move {
                if let Some(info) = dns_info {
                    let dns_evidence = dns_analyzer.analyze_from_info(&info);
                    if !dns_evidence.is_empty() {
                        Some(("DnsAnalysis".to_string(), dns_evidence, 0.95))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        // NEW: Run payload analysis in parallel with provider detection (opt-in)
        let payload_future = {
            let url = context.url.clone();
            let payload_analyzer = Arc::clone(&self.payload_analyzer);
            async move {
                if !self.payload_analysis_enabled() {
                    return None;
                }
                match payload_analyzer.analyze(&url).await {
                    Ok(payload_result) => {
                        let evidence = payload_analyzer.to_evidence(&payload_result);
                        if !evidence.is_empty() {
                            Some((
                                "PayloadAnalysis".to_string(),
                                evidence,
                                payload_result.confidence,
                            ))
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        eprintln!("Payload analysis failed: {e}");
                        None
                    }
                }
            }
        };

        // NEW: Run TLS analysis in parallel with provider detection
        let tls_future = {
            let url = context.url.clone();
            let tls_analyzer = Arc::clone(&self.tls_analyzer);
            async move {
                match tls_analyzer.analyze(&url).await {
                    Ok(tls_evidence) => {
                        if !tls_evidence.is_empty() {
                            Some(("TlsAnalysis".to_string(), tls_evidence, 0.95))
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        eprintln!("TLS analysis failed: {e}");
                        None
                    }
                }
            }
        };

        // Run all detection techniques in parallel
        let (provider_results, timing_result, dns_result, payload_result, tls_result) =
            tokio::join!(
                futures::future::join_all(provider_futures),
                timing_future,
                dns_future,
                payload_future,
                tls_future
            );

        let mut provider_scores = HashMap::new();
        let mut evidence_map: HashMap<String, Vec<crate::Evidence>> = HashMap::new();
        let mut best_waf = None;
        let mut best_cdn = None;

        // Initialize evidence map for all providers (matches working binary)
        for provider_name in self.providers.iter().map(|entry| entry.key().clone()) {
            evidence_map.insert(provider_name, Vec::new());
        }

        // Initialize evidence map for additional analysis types
        evidence_map.insert("TimingAnalysis".to_string(), Vec::new());
        evidence_map.insert("DnsAnalysis".to_string(), Vec::new());
        evidence_map.insert("PayloadAnalysis".to_string(), Vec::new());
        evidence_map.insert("TlsAnalysis".to_string(), Vec::new());
        evidence_map.insert("GenericWAF".to_string(), Vec::new());

        // Track best WAF and CDN separately to support multi-vendor scenarios
        let mut best_waf_confidence = 0.0;
        let mut best_cdn_confidence = 0.0;

        // Add provider evidence
        for result in provider_results.into_iter().flatten() {
            let (name, evidence, _base_confidence) = result;
            evidence_map.insert(name, evidence);
        }

        // Add analysis evidence and map to providers
        let mut analysis_results = Vec::new();
        if let Some(timing_result) = timing_result {
            analysis_results.push(timing_result);
        }
        if let Some(dns_result) = dns_result {
            analysis_results.push(dns_result);
        }
        if let Some(payload_result) = payload_result {
            analysis_results.push(payload_result);
        }
        if let Some(tls_result) = tls_result {
            analysis_results.push(tls_result);
        }

        for (analysis_name, evidence, _confidence) in analysis_results {
            evidence_map.insert(analysis_name, evidence.clone());
            self.map_analysis_evidence(&mut evidence_map, &evidence);
        }

        // Compute scores per provider using merged evidence (provider + analysis)
        let response_headers = context
            .response
            .as_ref()
            .map(|r| r.headers.clone())
            .unwrap_or_default();

        for provider_name in self.providers.iter().map(|entry| entry.key().clone()) {
            if let Some(evidence) = evidence_map.get(&provider_name) {
                if evidence.is_empty() {
                    continue;
                }

                let confidence_result = self
                    .advanced_scoring
                    .calculate_confidence(&provider_name, evidence, &response_headers);
                let final_confidence = confidence_result.score;

                provider_scores.insert(provider_name.clone(), final_confidence);

                if let Some(metadata) = self.provider_metadata.get(&provider_name) {
                    match metadata.provider_type.as_str() {
                        "WAF Only" => {
                            if final_confidence > best_waf_confidence {
                                best_waf_confidence = final_confidence;
                                best_waf = Some(ProviderDetection {
                                    name: provider_name.clone(),
                                    confidence: final_confidence,
                                });
                            }
                        }
                        "CDN Only" => {
                            if final_confidence > best_cdn_confidence {
                                best_cdn_confidence = final_confidence;
                                best_cdn = Some(ProviderDetection {
                                    name: provider_name.clone(),
                                    confidence: final_confidence,
                                });
                            }
                        }
                        "Both" => {
                            if final_confidence > best_waf_confidence {
                                best_waf_confidence = final_confidence;
                                best_waf = Some(ProviderDetection {
                                    name: provider_name.clone(),
                                    confidence: final_confidence,
                                });
                            }
                            if final_confidence > best_cdn_confidence {
                                best_cdn_confidence = final_confidence;
                                best_cdn = Some(ProviderDetection {
                                    name: provider_name.clone(),
                                    confidence: final_confidence,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Generic WAF fallback if we have behavioral evidence but no provider match
        if best_waf.is_none() {
            if let Some(generic_evidence) = evidence_map.get("GenericWAF") {
                if !generic_evidence.is_empty() {
                    let generic_confidence = self
                        .advanced_scoring
                        .calculate_confidence("Generic WAF", generic_evidence, &response_headers)
                        .score;
                    if generic_confidence >= 0.60 {
                        best_waf = Some(ProviderDetection {
                            name: "Generic WAF".to_string(),
                            confidence: generic_confidence,
                        });
                    }
                }
            }
        }

        let detection_time = start_time.elapsed().as_millis() as u64;
        let flat_evidence: Vec<crate::Evidence> =
            evidence_map.values().flatten().cloned().collect();

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
            evidence: flat_evidence,
            detection_time_ms: detection_time,
            metadata,
        })
    }

    pub fn list_providers(&self) -> Vec<ProviderMetadata> {
        let mut providers: Vec<_> = self
            .provider_metadata
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

    fn map_analysis_evidence(
        &self,
        evidence_map: &mut HashMap<String, Vec<crate::Evidence>>,
        evidence: &[crate::Evidence],
    ) {
        for ev in evidence {
            if let Some(provider_name) = self.provider_from_signature(&ev.signature_matched) {
                if provider_name == "Generic WAF" {
                    evidence_map
                        .entry("GenericWAF".to_string())
                        .or_default()
                        .push(ev.clone());
                    continue;
                }

                if evidence_map.contains_key(&provider_name) {
                    evidence_map
                        .entry(provider_name)
                        .or_default()
                        .push(ev.clone());
                }
            }
        }
    }

    fn provider_from_signature(&self, signature: &str) -> Option<String> {
        let sig = signature.to_lowercase();

        if sig.starts_with("timing-") {
            return Some("Generic WAF".to_string());
        }

        let provider_key = if let Some(rest) = sig.strip_prefix("dns-cname-") {
            Some(rest)
        } else if let Some(rest) = sig.strip_prefix("dns-ns-") {
            Some(rest)
        } else if let Some(rest) = sig.strip_prefix("tls-") {
            rest.split('-').next()
        } else if let Some(rest) = sig.strip_prefix("payload_detection_") {
            Some(rest)
        } else {
            None
        }?;

        let normalized = match provider_key {
            "cloudflare" => "CloudFlare",
            "aws" => "AWS",
            "aws_waf" => "AWS",
            "akamai" => "Akamai",
            "fastly" => "Fastly",
            "vercel" => "Vercel",
            "azure" => "Azure",
            "f5" => "F5",
            "generic_waf" => "Generic WAF",
            _ => return None,
        };

        Some(normalized.to_string())
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Evidence, MethodType};

    #[test]
    fn test_provider_from_signature_mapping() {
        let registry = ProviderRegistry::new();

        assert_eq!(
            registry.provider_from_signature("dns-cname-cloudflare"),
            Some("CloudFlare".to_string())
        );
        assert_eq!(
            registry.provider_from_signature("dns-ns-akamai"),
            Some("Akamai".to_string())
        );
        assert_eq!(
            registry.provider_from_signature("tls-aws-issuer"),
            Some("AWS".to_string())
        );
        assert_eq!(
            registry.provider_from_signature("payload_detection_aws_waf"),
            Some("AWS".to_string())
        );
        assert_eq!(
            registry.provider_from_signature("timing-waf-delay"),
            Some("Generic WAF".to_string())
        );
    }

    #[test]
    fn test_map_analysis_evidence_routes_to_provider() {
        let registry = ProviderRegistry::new();
        let mut evidence_map: HashMap<String, Vec<Evidence>> = HashMap::new();

        evidence_map.insert("CloudFlare".to_string(), Vec::new());
        evidence_map.insert("AWS".to_string(), Vec::new());
        evidence_map.insert("Akamai".to_string(), Vec::new());
        evidence_map.insert("GenericWAF".to_string(), Vec::new());

        let evidence = vec![
            Evidence {
                method_type: MethodType::DNS("cname".to_string()),
                confidence: 0.98,
                description: "CloudFlare CNAME".to_string(),
                raw_data: "CNAME -> example.cloudflare.net".to_string(),
                signature_matched: "dns-cname-cloudflare".to_string(),
            },
            Evidence {
                method_type: MethodType::Payload,
                confidence: 0.70,
                description: "Generic WAF timing".to_string(),
                raw_data: "timing".to_string(),
                signature_matched: "timing-waf-delay".to_string(),
            },
            Evidence {
                method_type: MethodType::Payload,
                confidence: 0.80,
                description: "AWS WAF payload detection".to_string(),
                raw_data: "blocked".to_string(),
                signature_matched: "payload_detection_aws_waf".to_string(),
            },
        ];

        registry.map_analysis_evidence(&mut evidence_map, &evidence);

        assert_eq!(evidence_map.get("CloudFlare").unwrap().len(), 1);
        assert_eq!(evidence_map.get("AWS").unwrap().len(), 1);
        assert_eq!(evidence_map.get("GenericWAF").unwrap().len(), 1);
    }
}
