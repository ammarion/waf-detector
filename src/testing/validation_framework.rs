//! Validation framework for testing WAF/CDN detection accuracy

use crate::DetectionResult;
use crate::engine::DetectionEngine;
use std::collections::HashMap;
use anyhow::Result;

/// Ground truth data for validation
#[derive(Debug, Clone)]
pub struct GroundTruth {
    pub url: String,
    pub known_waf: Option<String>,
    pub known_cdn: Option<String>,
    pub confidence_level: f64,
    pub notes: Option<String>,
}

/// Test outcome classification
#[derive(Debug, Clone, PartialEq)]
pub enum TestOutcome {
    TruePositive,
    FalsePositive,
    TrueNegative,
    FalseNegative,
}

/// Validation result for a single test
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub ground_truth: GroundTruth,
    pub detection_result: DetectionResult,
    pub waf_outcome: TestOutcome,
    pub cdn_outcome: TestOutcome,
    pub notes: Vec<String>,
}

/// Confidence analysis for different ranges
#[derive(Debug, Clone)]
pub struct ConfidenceAnalysis {
    pub range: String,
    pub accuracy: f64,
    pub count: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_negatives: usize,
}

/// Provider-specific metrics
#[derive(Debug, Clone)]
pub struct ProviderMetrics {
    pub provider_name: String,
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub total_tests: usize,
}

/// Complete validation report
#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub overall_accuracy: f64,
    pub overall_precision: f64,
    pub overall_recall: f64,
    pub overall_f1_score: f64,
    pub total_tests: usize,
    pub provider_metrics: Vec<ProviderMetrics>,
    pub confidence_analysis: Vec<ConfidenceAnalysis>,
    pub failed_tests: Vec<ValidationResult>,
}

/// Validation framework for testing detection accuracy
pub struct ValidationFramework {
    ground_truth_data: Vec<GroundTruth>,
    detection_engine: DetectionEngine,
}

impl ValidationFramework {
    pub fn new(detection_engine: DetectionEngine) -> Self {
        let ground_truth_data = Self::build_ground_truth_dataset();
        
        Self {
            ground_truth_data,
            detection_engine,
        }
    }
    
    /// Build ground truth dataset with known WAF/CDN providers
    fn build_ground_truth_dataset() -> Vec<GroundTruth> {
        vec![
            // CloudFlare sites
            GroundTruth {
                url: "https://cloudflare.com".to_string(),
                known_waf: Some("CloudFlare".to_string()),
                known_cdn: Some("CloudFlare".to_string()),
                confidence_level: 0.98,
                notes: Some("Official CloudFlare site".to_string()),
            },
            GroundTruth {
                url: "https://discord.com".to_string(),
                known_waf: Some("CloudFlare".to_string()),
                known_cdn: Some("CloudFlare".to_string()),
                confidence_level: 0.95,
                notes: Some("Known CloudFlare user".to_string()),
            },
            
            // AWS CloudFront sites
            GroundTruth {
                url: "https://aws.amazon.com".to_string(),
                known_waf: Some("AWS".to_string()),
                known_cdn: Some("AWS".to_string()),
                confidence_level: 0.98,
                notes: Some("Official AWS site".to_string()),
            },
            GroundTruth {
                url: "https://netflix.com".to_string(),
                known_waf: Some("AWS".to_string()),
                known_cdn: Some("AWS".to_string()),
                confidence_level: 0.90,
                notes: Some("Known AWS CloudFront user".to_string()),
            },
            
            // Fastly sites
            GroundTruth {
                url: "https://github.com".to_string(),
                known_waf: Some("Fastly".to_string()),
                known_cdn: Some("Fastly".to_string()),
                confidence_level: 0.95,
                notes: Some("Known Fastly user".to_string()),
            },
            
            // Akamai sites
            GroundTruth {
                url: "https://nike.com".to_string(),
                known_waf: Some("Akamai".to_string()),
                known_cdn: Some("Akamai".to_string()),
                confidence_level: 0.90,
                notes: Some("Known Akamai user".to_string()),
            },
            
            // Sites with no WAF/CDN (negative cases)
            GroundTruth {
                url: "https://example.com".to_string(),
                known_waf: None,
                known_cdn: None,
                confidence_level: 0.85,
                notes: Some("Simple test site".to_string()),
            },
        ]
    }
    
    /// Add custom ground truth data
    pub fn add_ground_truth(&mut self, ground_truth: GroundTruth) {
        self.ground_truth_data.push(ground_truth);
    }
    
    /// Run validation tests on all ground truth data
    pub async fn validate_all(&self) -> Result<ValidationReport> {
        let mut results = Vec::new();
        
        for ground_truth in &self.ground_truth_data {
            let detection_result = self.detection_engine.detect(&ground_truth.url).await?;
            let validation_result = self.evaluate_result(ground_truth, detection_result);
            results.push(validation_result);
        }
        
        Ok(self.generate_report(results))
    }
    
    /// Evaluate detection result against ground truth
    fn evaluate_result(&self, ground_truth: &GroundTruth, detection_result: DetectionResult) -> ValidationResult {
        let mut notes = Vec::new();
        
        // Evaluate WAF detection
        let waf_outcome = match (&ground_truth.known_waf, &detection_result.detected_waf) {
            (Some(expected), Some(detected)) => {
                if expected == &detected.name {
                    TestOutcome::TruePositive
                } else {
                    notes.push(format!("Expected WAF: {}, Detected: {}", expected, detected.name));
                    TestOutcome::FalsePositive
                }
            }
            (Some(expected), None) => {
                notes.push(format!("Expected WAF: {}, but none detected", expected));
                TestOutcome::FalseNegative
            }
            (None, Some(detected)) => {
                notes.push(format!("No WAF expected, but detected: {}", detected.name));
                TestOutcome::FalsePositive
            }
            (None, None) => TestOutcome::TrueNegative,
        };
        
        // Evaluate CDN detection
        let cdn_outcome = match (&ground_truth.known_cdn, &detection_result.detected_cdn) {
            (Some(expected), Some(detected)) => {
                if expected == &detected.name {
                    TestOutcome::TruePositive
                } else {
                    notes.push(format!("Expected CDN: {}, Detected: {}", expected, detected.name));
                    TestOutcome::FalsePositive
                }
            }
            (Some(expected), None) => {
                notes.push(format!("Expected CDN: {}, but none detected", expected));
                TestOutcome::FalseNegative
            }
            (None, Some(detected)) => {
                notes.push(format!("No CDN expected, but detected: {}", detected.name));
                TestOutcome::FalsePositive
            }
            (None, None) => TestOutcome::TrueNegative,
        };
        
        ValidationResult {
            ground_truth: ground_truth.clone(),
            detection_result,
            waf_outcome,
            cdn_outcome,
            notes,
        }
    }
    
    /// Generate comprehensive validation report
    fn generate_report(&self, results: Vec<ValidationResult>) -> ValidationReport {
        let total_tests = results.len();
        let mut provider_stats: HashMap<String, (usize, usize, usize, usize)> = HashMap::new();
        let _confidence_ranges: HashMap<String, (usize, usize, usize, usize)> = HashMap::new();
        let mut failed_tests = Vec::new();
        
        // Calculate overall metrics
        let mut overall_tp = 0;
        let mut overall_fp = 0;
        let mut overall_tn = 0;
        let mut overall_fn = 0;
        
        for result in &results {
            // Count overall outcomes
            match result.waf_outcome {
                TestOutcome::TruePositive => overall_tp += 1,
                TestOutcome::FalsePositive => overall_fp += 1,
                TestOutcome::TrueNegative => overall_tn += 1,
                TestOutcome::FalseNegative => overall_fn += 1,
            }
            
            match result.cdn_outcome {
                TestOutcome::TruePositive => overall_tp += 1,
                TestOutcome::FalsePositive => overall_fp += 1,
                TestOutcome::TrueNegative => overall_tn += 1,
                TestOutcome::FalseNegative => overall_fn += 1,
            }
            
            // Track failed tests
            if result.waf_outcome == TestOutcome::FalsePositive || 
               result.waf_outcome == TestOutcome::FalseNegative ||
               result.cdn_outcome == TestOutcome::FalsePositive ||
               result.cdn_outcome == TestOutcome::FalseNegative {
                failed_tests.push(result.clone());
            }
            
            // Provider-specific statistics
            if let Some(waf) = &result.detection_result.detected_waf {
                let stats = provider_stats.entry(waf.name.clone()).or_insert((0, 0, 0, 0));
                match result.waf_outcome {
                    TestOutcome::TruePositive => stats.0 += 1,
                    TestOutcome::FalsePositive => stats.1 += 1,
                    TestOutcome::TrueNegative => stats.2 += 1,
                    TestOutcome::FalseNegative => stats.3 += 1,
                }
            }
            
            if let Some(cdn) = &result.detection_result.detected_cdn {
                let stats = provider_stats.entry(cdn.name.clone()).or_insert((0, 0, 0, 0));
                match result.cdn_outcome {
                    TestOutcome::TruePositive => stats.0 += 1,
                    TestOutcome::FalsePositive => stats.1 += 1,
                    TestOutcome::TrueNegative => stats.2 += 1,
                    TestOutcome::FalseNegative => stats.3 += 1,
                }
            }
        }
        
        // Calculate overall metrics
        let overall_accuracy = (overall_tp + overall_tn) as f64 / (overall_tp + overall_fp + overall_tn + overall_fn) as f64;
        let overall_precision = if overall_tp + overall_fp > 0 { overall_tp as f64 / (overall_tp + overall_fp) as f64 } else { 0.0 };
        let overall_recall = if overall_tp + overall_fn > 0 { overall_tp as f64 / (overall_tp + overall_fn) as f64 } else { 0.0 };
        let overall_f1_score = if overall_precision + overall_recall > 0.0 { 2.0 * overall_precision * overall_recall / (overall_precision + overall_recall) } else { 0.0 };
        
        // Calculate provider metrics
        let provider_metrics = provider_stats.into_iter().map(|(name, (tp, fp, tn, fn_count))| {
            let accuracy = (tp + tn) as f64 / (tp + fp + tn + fn_count) as f64;
            let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 0.0 };
            let recall = if tp + fn_count > 0 { tp as f64 / (tp + fn_count) as f64 } else { 0.0 };
            let f1_score = if precision + recall > 0.0 { 2.0 * precision * recall / (precision + recall) } else { 0.0 };
            
            ProviderMetrics {
                provider_name: name,
                accuracy,
                precision,
                recall,
                f1_score,
                total_tests: (tp + fp + tn + fn_count),
            }
        }).collect();
        
        // Create confidence analysis ranges
        let confidence_analysis = vec![
            ConfidenceAnalysis {
                range: "95%+".to_string(),
                accuracy: 0.0,
                count: 0,
                true_positives: 0,
                false_positives: 0,
                true_negatives: 0,
                false_negatives: 0,
            },
            ConfidenceAnalysis {
                range: "90-95%".to_string(),
                accuracy: 0.0,
                count: 0,
                true_positives: 0,
                false_positives: 0,
                true_negatives: 0,
                false_negatives: 0,
            },
            ConfidenceAnalysis {
                range: "60-90%".to_string(),
                accuracy: 0.0,
                count: 0,
                true_positives: 0,
                false_positives: 0,
                true_negatives: 0,
                false_negatives: 0,
            },
        ];
        
        ValidationReport {
            overall_accuracy,
            overall_precision,
            overall_recall,
            overall_f1_score,
            total_tests,
            provider_metrics,
            confidence_analysis,
            failed_tests,
        }
    }
}

impl ValidationReport {
    /// Print validation report to console
    pub fn print_report(&self) {
        println!("\n🔍 WAF/CDN Detection Validation Report");
        println!("=====================================");
        println!("Total Tests: {}", self.total_tests);
        println!("Overall Accuracy: {:.2}%", self.overall_accuracy * 100.0);
        println!("Overall Precision: {:.2}%", self.overall_precision * 100.0);
        println!("Overall Recall: {:.2}%", self.overall_recall * 100.0);
        println!("Overall F1 Score: {:.2}%", self.overall_f1_score * 100.0);
        
        println!("\n📊 Provider Performance:");
        for provider in &self.provider_metrics {
            println!("  {} - Accuracy: {:.2}%, Precision: {:.2}%, Recall: {:.2}%, F1: {:.2}%",
                provider.provider_name,
                provider.accuracy * 100.0,
                provider.precision * 100.0,
                provider.recall * 100.0,
                provider.f1_score * 100.0);
        }
        
        if !self.failed_tests.is_empty() {
            println!("\n❌ Failed Tests ({}):", self.failed_tests.len());
            for failed in &self.failed_tests {
                println!("  {} - WAF: {:?}, CDN: {:?}", 
                    failed.ground_truth.url, 
                    failed.waf_outcome, 
                    failed.cdn_outcome);
                for note in &failed.notes {
                    println!("    - {}", note);
                }
            }
        }
    }
    
    /// Check if validation meets target thresholds
    pub fn meets_targets(&self, min_accuracy: f64, min_precision: f64, min_recall: f64) -> bool {
        self.overall_accuracy >= min_accuracy &&
        self.overall_precision >= min_precision &&
        self.overall_recall >= min_recall
    }
} 