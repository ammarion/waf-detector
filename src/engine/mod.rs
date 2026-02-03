//! Detection engine for coordinating WAF/CDN detection

use crate::{http::HttpClient, registry::ProviderRegistry, DetectionContext, DetectionResult};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

pub mod waf_mode_detector;
use waf_mode_detector::WafModeDetector;

/// Main detection engine
use crate::dns::optimized::DnsResolver;

/// Main detection engine
#[derive(Debug, Clone)]
pub struct DetectionEngine {
    registry: ProviderRegistry,
    http_client: Arc<HttpClient>,
    dns_resolver: Arc<DnsResolver>,
    waf_mode_detector: Option<WafModeDetector>,
}

impl DetectionEngine {
    pub fn new(registry: ProviderRegistry) -> Self {
        let dns_resolver = DnsResolver::new().expect("Failed to initialize DNS resolver");
        Self {
            registry,
            http_client: Arc::new(HttpClient::new().expect("Failed to initialize HTTP client")),
            dns_resolver: Arc::new(dns_resolver),
            waf_mode_detector: None,
        }
    }

    pub fn with_waf_mode_detection(mut self) -> Self {
        self.waf_mode_detector = Some(WafModeDetector::new());
        self
    }

    pub async fn detect(&self, url: &str) -> Result<DetectionResult> {
        // Run HTTP and DNS concurrently
        let http_future = self.http_client.get(url);
        let dns_future = self.dns_resolver.resolve(url);

        let (http_result, dns_result) = tokio::join!(http_future, dns_future);

        // Handle results (gracefully continue if one fails, but log it)
        let response = match http_result {
            Ok(res) => Some(res),
            Err(e) => {
                eprintln!("⚠️  HTTP request failed for {url}: {e}");
                None
            }
        };

        let dns_info = match dns_result {
            Ok(info) => Some(info),
            Err(e) => {
                eprintln!("⚠️  DNS resolution failed for {url}: {e}");
                None
            }
        };

        if response.is_none() && dns_info.is_none() {
            return Err(anyhow::anyhow!("Both HTTP and DNS failed for {url}"));
        }

        // Create detection context
        let context = DetectionContext {
            url: url.to_string(),
            response,
            dns_info,
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                .to_string(),
        };

        // Run detection through registry
        self.registry.detect_all(&context).await
    }

    pub async fn detect_batch(
        &self,
        urls: &[&str],
        workers: usize,
    ) -> Result<HashMap<String, DetectionResult>> {
        use futures::stream::{self, StreamExt};

        // Use a semaphore to limit concurrent valid checks if strictly needed,
        // but buffer_unordered(workers) mostly handles this concurrency limit.
        // We remove the naive 'sleep(100)' which slowed things down unnecessarily.

        let results = stream::iter(urls)
            .map(|&url| async move {
                match self.detect(url).await {
                    Ok(result) => Some((url.to_string(), result)),
                    Err(e) => {
                        eprintln!("⚠️  Failed to detect {url}: {e}");

                        // Create a failed result instead of None so we maintain the URL in output
                        let failed_result = DetectionResult {
                            url: url.to_string(),
                            detected_waf: None,
                            detected_cdn: None,
                            provider_scores: std::collections::HashMap::new(),
                            evidence_map: std::collections::HashMap::new(),
                            evidence: Vec::new(),
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

    pub async fn detect_with_mode_analysis(
        &self,
        url: &str,
    ) -> Result<(DetectionResult, Option<waf_mode_detector::WafModeResult>)> {
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
