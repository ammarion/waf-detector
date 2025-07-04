//! Detection engine for coordinating WAF/CDN detection

use crate::{DetectionContext, DetectionResult, registry::ProviderRegistry, http::HttpClient};
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;


pub mod waf_mode_detector;
use waf_mode_detector::WafModeDetector;

/// Main detection engine
#[derive(Debug, Clone)]
pub struct DetectionEngine {
    registry: ProviderRegistry,
    http_client: Arc<HttpClient>,
    waf_mode_detector: Option<WafModeDetector>,
}

impl DetectionEngine {
    pub fn new(registry: ProviderRegistry) -> Self {
        Self {
            registry,
            http_client: Arc::new(HttpClient::default()),
            waf_mode_detector: None,
        }
    }

    pub fn with_waf_mode_detection(mut self) -> Self {
        self.waf_mode_detector = Some(WafModeDetector::new());
        self
    }

    pub async fn detect(&self, url: &str) -> Result<DetectionResult> {
        // Make HTTP request
        let response = self.http_client.get(url).await?;
        
        // Create detection context
        let context = DetectionContext {
            url: url.to_string(),
            response: Some(response),
            dns_info: None,
            user_agent: "WAF-Detector/1.0".to_string(),
        };

        // Run detection through registry
        self.registry.detect_all(&context).await
    }

    pub async fn detect_batch(&self, urls: &[&str], workers: usize) -> Result<HashMap<String, DetectionResult>> {
        use futures::stream::{self, StreamExt};
        use tokio::time::{sleep, Duration};
        
        let results = stream::iter(urls)
            .map(|&url| async move {
                // Add small delay to prevent overwhelming servers
                sleep(Duration::from_millis(100)).await;
                
                match self.detect(url).await {
                    Ok(result) => Some((url.to_string(), result)),
                    Err(e) => {
                        eprintln!("⚠️  Failed to detect {}: {}", url, e);
                        
                        // Create a failed result instead of None so we maintain the URL in output
                        let failed_result = DetectionResult {
                            url: url.to_string(),
                            detected_waf: None,
                            detected_cdn: None,
                            provider_scores: std::collections::HashMap::new(),
                            evidence_map: std::collections::HashMap::new(),
                            detection_time_ms: 0,
                            metadata: crate::DetectionMetadata {
                                timestamp: chrono::Utc::now(),
                                version: "1.0.0".to_string(),
                                user_agent: "WAF-Detector/1.0".to_string(),
                            },
                        };
                        Some((url.to_string(), failed_result))
                    }
                }
            })
            .buffer_unordered(workers)
            .collect::<Vec<_>>()
            .await;

        Ok(results.into_iter().flatten().collect())
    }

    pub async fn detect_with_mode_analysis(&self, url: &str) -> Result<(DetectionResult, Option<waf_mode_detector::WafModeResult>)> {
        let detection_result = self.detect(url).await?;
        
        let mode_result = if let Some(detector) = &self.waf_mode_detector {
            if detection_result.detected() {
                Some(detector.detect_mode(url, None).await?)
            } else {
                None
            }
        } else {
            None
        };

        Ok((detection_result, mode_result))
    }

    pub fn list_providers(&self) -> Vec<crate::providers::ProviderMetadata> {
        self.registry.list_providers()
    }

    pub fn get_provider_count(&self) -> usize {
        self.registry.get_provider_count()
    }
}
