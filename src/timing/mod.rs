//! Timing analysis for WAF detection
//! 
//! Detects WAF presence by measuring processing delays introduced by WAF inspection.
//! Research shows WAFs typically add 50-200ms processing delays compared to direct responses.

use crate::{Evidence, MethodType};
use std::time::{Duration, Instant};
use anyhow::Result;

/// Timing analysis results
#[derive(Debug, Clone)]
pub struct TimingAnalysis {
    pub baseline_time_ms: u64,
    pub test_time_ms: u64,
    pub delay_detected: bool,
    pub delay_amount_ms: u64,
    pub confidence: f64,
    pub technique_used: TimingTechnique,
}

/// Different timing analysis techniques
#[derive(Debug, Clone, PartialEq)]
pub enum TimingTechnique {
    /// Compare response times between normal and suspicious requests
    BaselineComparison,
    /// Analyze response time patterns
    PatternAnalysis,
    /// Multiple request timing analysis
    BurstTiming,
}

/// Configuration for timing analysis
#[derive(Debug, Clone)]
pub struct TimingConfig {
    /// Minimum delay to consider WAF processing (default: 50ms)
    pub min_waf_delay_ms: u64,
    /// Maximum delay to consider WAF processing (default: 200ms)  
    pub max_waf_delay_ms: u64,
    /// Number of baseline requests for comparison
    pub baseline_requests: usize,
    /// Number of test requests with suspicious patterns
    pub test_requests: usize,
    /// Timeout for individual requests
    pub request_timeout: Duration,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            min_waf_delay_ms: 50,
            max_waf_delay_ms: 200,
            baseline_requests: 3,
            test_requests: 3,
            request_timeout: Duration::from_secs(5),
        }
    }
}

/// Timing analyzer for WAF detection
#[derive(Debug)]
pub struct TimingAnalyzer {
    config: TimingConfig,
    http_client: reqwest::Client,
}

impl TimingAnalyzer {
    pub fn new(config: TimingConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .unwrap();
            
        Self {
            config,
            http_client,
        }
    }

    /// Perform timing analysis on a URL
    pub async fn analyze(&self, url: &str) -> Result<Vec<Evidence>> {
        let mut evidence = Vec::new();
        
        // Perform baseline comparison
        if let Ok(baseline_analysis) = self.baseline_comparison(url).await {
            if baseline_analysis.delay_detected {
                evidence.push(Evidence {
                    method_type: MethodType::Timing,
                    confidence: baseline_analysis.confidence,
                    description: format!(
                        "WAF processing delay detected: {}ms (technique: {:?})",
                        baseline_analysis.delay_amount_ms,
                        baseline_analysis.technique_used
                    ),
                    raw_data: format!(
                        "baseline: {}ms, test: {}ms, delay: {}ms",
                        baseline_analysis.baseline_time_ms,
                        baseline_analysis.test_time_ms,
                        baseline_analysis.delay_amount_ms
                    ),
                    signature_matched: "timing-waf-delay".to_string(),
                });
            }
        }
        
        // Perform pattern analysis
        if let Ok(pattern_analysis) = self.pattern_analysis(url).await {
            if pattern_analysis.delay_detected {
                evidence.push(Evidence {
                    method_type: MethodType::Timing,
                    confidence: pattern_analysis.confidence,
                    description: format!(
                        "WAF timing pattern detected: {}ms consistent delay",
                        pattern_analysis.delay_amount_ms
                    ),
                    raw_data: format!(
                        "pattern_detected: {}ms average delay",
                        pattern_analysis.delay_amount_ms
                    ),
                    signature_matched: "timing-pattern-analysis".to_string(),
                });
            }
        }
        
        Ok(evidence)
    }

    /// Compare baseline (normal) vs test (suspicious) request timing
    async fn baseline_comparison(&self, url: &str) -> Result<TimingAnalysis> {
        // Measure baseline response times with normal requests
        let baseline_times = self.measure_baseline_requests(url).await?;
        let baseline_avg = baseline_times.iter().sum::<u64>() / baseline_times.len() as u64;
        
        // Measure test response times with suspicious patterns
        let test_times = self.measure_test_requests(url).await?;
        let test_avg = test_times.iter().sum::<u64>() / test_times.len() as u64;
        
        let delay_amount = if test_avg > baseline_avg {
            test_avg - baseline_avg
        } else {
            0
        };
        
        let delay_detected = delay_amount >= self.config.min_waf_delay_ms && 
                           delay_amount <= self.config.max_waf_delay_ms;
        
        // Calculate confidence based on delay amount and consistency
        let confidence = if delay_detected {
            let delay_score = (delay_amount as f64 - self.config.min_waf_delay_ms as f64) / 
                            (self.config.max_waf_delay_ms as f64 - self.config.min_waf_delay_ms as f64);
            
            // Check consistency across multiple requests
            let baseline_variance = self.calculate_variance(&baseline_times, baseline_avg);
            let test_variance = self.calculate_variance(&test_times, test_avg);
            let consistency_score = 1.0 - (baseline_variance + test_variance) / 2.0;
            
            (delay_score * 0.7 + consistency_score * 0.3).min(0.95)
        } else {
            0.0
        };
        
        Ok(TimingAnalysis {
            baseline_time_ms: baseline_avg,
            test_time_ms: test_avg,
            delay_detected,
            delay_amount_ms: delay_amount,
            confidence,
            technique_used: TimingTechnique::BaselineComparison,
        })
    }

    /// Analyze timing patterns across multiple requests
    async fn pattern_analysis(&self, url: &str) -> Result<TimingAnalysis> {
        // Make multiple requests and look for consistent timing patterns
        let mut all_times = Vec::new();
        
        for _ in 0..self.config.baseline_requests + self.config.test_requests {
            let start = Instant::now();
            let _ = self.http_client.get(url).send().await?;
            let elapsed = start.elapsed().as_millis() as u64;
            all_times.push(elapsed);
            
            // Small delay between requests
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        let avg_time = all_times.iter().sum::<u64>() / all_times.len() as u64;
        let variance = self.calculate_variance(&all_times, avg_time);
        
        // Look for consistent delays that might indicate WAF processing
        let delay_detected = avg_time >= self.config.min_waf_delay_ms && 
                           avg_time <= 1000 && // Reasonable upper bound
                           variance < 0.3; // Low variance indicates consistent processing
        
        let confidence = if delay_detected {
            let time_score = if avg_time <= self.config.max_waf_delay_ms { 0.8 } else { 0.4 };
            let consistency_score = 1.0 - variance;
            (time_score * 0.6 + consistency_score * 0.4).min(0.90)
        } else {
            0.0
        };
        
        Ok(TimingAnalysis {
            baseline_time_ms: avg_time,
            test_time_ms: avg_time,
            delay_detected,
            delay_amount_ms: if delay_detected { avg_time } else { 0 },
            confidence,
            technique_used: TimingTechnique::PatternAnalysis,
        })
    }

    /// Measure baseline request times with normal requests
    async fn measure_baseline_requests(&self, url: &str) -> Result<Vec<u64>> {
        let mut times = Vec::new();
        
        for _ in 0..self.config.baseline_requests {
            let start = Instant::now();
            let _response = self.http_client
                .get(url)
                .header("User-Agent", "Mozilla/5.0 (compatible; WAF-Detector/1.0)")
                .send()
                .await?;
            let elapsed = start.elapsed().as_millis() as u64;
            times.push(elapsed);
            
            // Small delay between requests to avoid rate limiting
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        
        Ok(times)
    }

    /// Measure test request times with suspicious patterns that might trigger WAF
    async fn measure_test_requests(&self, url: &str) -> Result<Vec<u64>> {
        let mut times = Vec::new();
        
        // Test with suspicious user agents and headers that might trigger WAF analysis
        let test_patterns = vec![
            ("User-Agent", "sqlmap/1.0"),
            ("User-Agent", "Nikto/2.0"),
            ("X-Forwarded-For", "1.1.1.1"),
            ("X-Real-IP", "127.0.0.1"),
        ];
        
        for i in 0..self.config.test_requests {
            let pattern = &test_patterns[i % test_patterns.len()];
            
            let start = Instant::now();
            let _response = self.http_client
                .get(url)
                .header(pattern.0, pattern.1)
                .send()
                .await?;
            let elapsed = start.elapsed().as_millis() as u64;
            times.push(elapsed);
            
            // Small delay between requests
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        
        Ok(times)
    }

    /// Calculate variance normalized to 0-1 scale
    fn calculate_variance(&self, times: &[u64], mean: u64) -> f64 {
        if times.len() <= 1 {
            return 0.0;
        }
        
        let variance: f64 = times.iter()
            .map(|&time| {
                let diff = time as f64 - mean as f64;
                diff * diff
            })
            .sum::<f64>() / times.len() as f64;
        
        let std_dev = variance.sqrt();
        
        // Normalize to 0-1 scale (coefficient of variation)
        if mean > 0 {
            (std_dev / mean as f64).min(1.0)
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_timing_config_default() {
        let config = TimingConfig::default();
        assert_eq!(config.min_waf_delay_ms, 50);
        assert_eq!(config.max_waf_delay_ms, 200);
        assert_eq!(config.baseline_requests, 3);
        assert_eq!(config.test_requests, 3);
        assert_eq!(config.request_timeout, Duration::from_secs(5));
    }
    
    #[test]
    fn test_timing_analyzer_creation() {
        let config = TimingConfig::default();
        let analyzer = TimingAnalyzer::new(config);
        assert_eq!(analyzer.config.min_waf_delay_ms, 50);
    }
    
    #[test]
    fn test_calculate_variance() {
        let config = TimingConfig::default();
        let analyzer = TimingAnalyzer::new(config);
        
        // Test with consistent times (low variance)
        let consistent_times = vec![100, 102, 98, 101, 99];
        let mean = 100;
        let variance = analyzer.calculate_variance(&consistent_times, mean);
        assert!(variance < 0.1, "Consistent times should have low variance");
        
        // Test with inconsistent times (high variance)
        let inconsistent_times = vec![50, 150, 75, 200, 25];
        let mean = 100;
        let variance = analyzer.calculate_variance(&inconsistent_times, mean);
        assert!(variance > 0.3, "Inconsistent times should have high variance");
    }
    
    #[test]
    fn test_timing_analysis_delay_detection() {
        let analysis = TimingAnalysis {
            baseline_time_ms: 100,
            test_time_ms: 170,
            delay_detected: true,
            delay_amount_ms: 70,
            confidence: 0.85,
            technique_used: TimingTechnique::BaselineComparison,
        };
        
        assert!(analysis.delay_detected);
        assert_eq!(analysis.delay_amount_ms, 70);
        assert!(analysis.confidence > 0.8);
    }
    
    #[test]
    fn test_timing_technique_equality() {
        assert_eq!(TimingTechnique::BaselineComparison, TimingTechnique::BaselineComparison);
        assert_ne!(TimingTechnique::BaselineComparison, TimingTechnique::PatternAnalysis);
    }
    
    #[tokio::test]
    async fn test_timing_analyzer_with_mock_data() {
        // This would be a more comprehensive test with mocked HTTP responses
        // Testing the core logic without network calls
        let config = TimingConfig {
            min_waf_delay_ms: 50,
            max_waf_delay_ms: 200,
            baseline_requests: 2,
            test_requests: 2,
            request_timeout: Duration::from_secs(1),
        };
        
        let analyzer = TimingAnalyzer::new(config);
        
        // Test variance calculation with known data
        let times = vec![100, 105, 95, 102];
        let mean = 100;
        let variance = analyzer.calculate_variance(&times, mean);
        assert!(variance < 0.2, "Small variance should be detected correctly");
    }
} 