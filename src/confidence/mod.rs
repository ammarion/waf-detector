//! Confidence scoring engine using Bayesian inference

use std::collections::HashMap;

pub mod advanced_scoring;

pub use advanced_scoring::{
    AdvancedScoring, 
    EvidenceWeight, 
    EvidenceCategory, 
    ConfidenceResult, 
    ConfidenceLevel,
    ConfidenceThresholds
};

#[derive(Debug, Clone)]
pub struct ConfidenceEngine {
    base_confidence: f64,
    provider_weights: HashMap<String, f64>,
}

impl ConfidenceEngine {
    pub fn new() -> Self {
        let mut provider_weights = HashMap::new();
        provider_weights.insert("CloudFlare".to_string(), 0.95);
        provider_weights.insert("Akamai".to_string(), 0.92);

        Self {
            base_confidence: 0.5,
            provider_weights,
        }
    }

    pub fn calculate_confidence(&self, provider_name: &str, evidence_count: usize, evidence_strength: f64) -> f64 {
        let provider_weight = *self.provider_weights.get(provider_name).unwrap_or(&0.8);
        
        // Bayesian-inspired calculation
        let prior = self.base_confidence;
        let likelihood = evidence_strength * provider_weight;
        let evidence_factor = 1.0 + (evidence_count as f64 * 0.1);
        
        let posterior = (prior * likelihood * evidence_factor) / 
                       (prior * likelihood * evidence_factor + (1.0 - prior) * (1.0 - likelihood));
        
        posterior.min(1.0).max(0.0)
    }

    pub fn combine_confidences(&self, confidences: &[f64]) -> f64 {
        if confidences.is_empty() {
            return 0.0;
        }

        // Use probability combination: 1 - ∏(1 - pi)
        let combined = 1.0 - confidences.iter()
            .map(|&c| 1.0 - c)
            .product::<f64>();

        combined.min(1.0).max(0.0)
    }

    pub fn adjust_for_false_positives(&self, confidence: f64, false_positive_indicators: usize) -> f64 {
        let penalty = false_positive_indicators as f64 * 0.1;
        (confidence - penalty).max(0.0)
    }
}

impl Default for ConfidenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_calculation() {
        let engine = ConfidenceEngine::new();
        let confidence = engine.calculate_confidence("CloudFlare", 3, 0.9);
        assert!(confidence > 0.5);
        assert!(confidence <= 1.0);
    }

    #[test]
    fn test_combine_confidences() {
        let engine = ConfidenceEngine::new();
        let confidences = vec![0.8, 0.7, 0.9];
        let combined = engine.combine_confidences(&confidences);
        assert!(combined > 0.8);
        assert!(combined <= 1.0);
    }

    #[test]
    fn test_false_positive_adjustment() {
        let engine = ConfidenceEngine::new();
        let confidence = engine.adjust_for_false_positives(0.9, 2);
        assert_eq!(confidence, 0.7);
    }
}
