use crate::{Evidence, MethodType};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Advanced confidence scoring system for WAF/CDN detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedScoring {
    /// Evidence weights by type and specificity
    evidence_weights: HashMap<String, EvidenceWeight>,
    /// Minimum evidence requirements for high confidence
    confidence_thresholds: ConfidenceThresholds,
    /// Negative evidence that rules out providers
    negative_evidence_patterns: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceWeight {
    /// Base weight for this evidence type
    pub base_weight: f64,
    /// Specificity multiplier (how unique this is to the provider)
    pub specificity: f64,
    /// Reliability factor (how often this evidence is correct)
    pub reliability: f64,
    /// Evidence category for grouping
    pub category: EvidenceCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub enum EvidenceCategory {
    /// HTTP headers (highest reliability)
    Headers,
    /// Server response patterns
    Server,
    /// Body content patterns (lowest reliability)
    Body,
    /// Status code patterns
    StatusCode,
    /// Timing and behavioral patterns
    Behavioral,
    /// Error response patterns
    ErrorPage,
    /// DNS and network patterns
    Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceThresholds {
    /// Minimum score for "detected" (60%)
    pub minimum: f64,
    /// High confidence threshold (90%)
    pub high: f64,
    /// Very high confidence threshold (95%)
    pub very_high: f64,
    /// Absolute confidence threshold (98%)
    pub absolute: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceResult {
    /// Final confidence score (0.0 - 1.0)
    pub score: f64,
    /// Confidence level description
    pub level: ConfidenceLevel,
    /// Evidence breakdown by category
    pub evidence_breakdown: HashMap<EvidenceCategory, f64>,
    /// Positive evidence count
    pub positive_evidence_count: usize,
    /// Negative evidence (contradictory) count
    pub negative_evidence_count: usize,
    /// Required evidence still missing
    pub missing_evidence: Vec<String>,
    /// Explanation of scoring logic
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    None,           // 0-20%
    Low,            // 20-60%
    Moderate,       // 60-80%
    High,           // 80-90%
    VeryHigh,       // 90-95%
    NearCertain,    // 95-98%
    Absolute,       // 98%+
}

impl AdvancedScoring {
    pub fn new() -> Self {
        let mut evidence_weights = HashMap::new();
        
        // CloudFlare patterns
        evidence_weights.insert("cf-ray-header".to_string(), EvidenceWeight {
            base_weight: 0.95,
            specificity: 0.98,    // Very CloudFlare-specific
            reliability: 0.99,    // Almost always reliable
            category: EvidenceCategory::Headers,
        });
        
        evidence_weights.insert("cf-cache-status-header".to_string(), EvidenceWeight {
            base_weight: 0.90,
            specificity: 0.95,
            reliability: 0.95,
            category: EvidenceCategory::Headers,
        });
        
        evidence_weights.insert("cloudflare-server-header".to_string(), EvidenceWeight {
            base_weight: 0.85,
            specificity: 0.90,
            reliability: 0.92,
            category: EvidenceCategory::Server,
        });
        
        // CloudFlare body patterns (much lower weight)
        evidence_weights.insert("cf-challenge-body".to_string(), EvidenceWeight {
            base_weight: 0.70,
            specificity: 0.60,    // Can be false positive
            reliability: 0.75,    // Less reliable than headers
            category: EvidenceCategory::Body,
        });
        
        evidence_weights.insert("cf-error-body".to_string(), EvidenceWeight {
            base_weight: 0.65,
            specificity: 0.55,    // Can be false positive
            reliability: 0.70,    // Less reliable than headers
            category: EvidenceCategory::Body,
        });
        
        evidence_weights.insert("cf-js-body".to_string(), EvidenceWeight {
            base_weight: 0.60,
            specificity: 0.50,    // Can be false positive
            reliability: 0.65,    // Less reliable than headers
            category: EvidenceCategory::Body,
        });
        
        // CloudFlare other headers
        evidence_weights.insert("cf-connecting-ip-header".to_string(), EvidenceWeight {
            base_weight: 0.80,
            specificity: 0.85,
            reliability: 0.90,
            category: EvidenceCategory::Headers,
        });
        
        evidence_weights.insert("cf-ipcountry-header".to_string(), EvidenceWeight {
            base_weight: 0.75,
            specificity: 0.80,
            reliability: 0.85,
            category: EvidenceCategory::Headers,
        });
        
        evidence_weights.insert("cf-visitor-header".to_string(), EvidenceWeight {
            base_weight: 0.75,
            specificity: 0.80,
            reliability: 0.85,
            category: EvidenceCategory::Headers,
        });
        
        evidence_weights.insert("cf-request-id-header".to_string(), EvidenceWeight {
            base_weight: 0.85,
            specificity: 0.90,
            reliability: 0.92,
            category: EvidenceCategory::Headers,
        });
        
        // CloudFlare status codes
        evidence_weights.insert("cf-403-status".to_string(), EvidenceWeight {
            base_weight: 0.75,
            specificity: 0.70,
            reliability: 0.80,
            category: EvidenceCategory::StatusCode,
        });
        
        evidence_weights.insert("cf-429-status".to_string(), EvidenceWeight {
            base_weight: 0.80,
            specificity: 0.75,
            reliability: 0.85,
            category: EvidenceCategory::StatusCode,
        });
        
        // AWS CloudFront patterns
        evidence_weights.insert("x-amz-cf-id-header".to_string(), EvidenceWeight {
            base_weight: 0.95,
            specificity: 0.99,    // Highly AWS-specific
            reliability: 0.98,
            category: EvidenceCategory::Headers,
        });
        
        evidence_weights.insert("x-amz-cf-pop-header".to_string(), EvidenceWeight {
            base_weight: 0.90,
            specificity: 0.95,
            reliability: 0.96,
            category: EvidenceCategory::Headers,
        });
        
        evidence_weights.insert("cloudfront-server-header".to_string(), EvidenceWeight {
            base_weight: 0.88,
            specificity: 0.92,
            reliability: 0.94,
            category: EvidenceCategory::Server,
        });
        
        evidence_weights.insert("cloudfront-via-header".to_string(), EvidenceWeight {
            base_weight: 0.85,
            specificity: 0.88,
            reliability: 0.90,
            category: EvidenceCategory::Headers,
        });
        
        // Akamai patterns
        evidence_weights.insert("akamai-grn-header".to_string(), EvidenceWeight {
            base_weight: 0.92,
            specificity: 0.96,    // Very Akamai-specific
            reliability: 0.95,
            category: EvidenceCategory::Headers,
        });
        
        evidence_weights.insert("x-akamai-header".to_string(), EvidenceWeight {
            base_weight: 0.90,
            specificity: 0.94,
            reliability: 0.93,
            category: EvidenceCategory::Headers,
        });
        
        // Fastly patterns
        evidence_weights.insert("fastly-header".to_string(), EvidenceWeight {
            base_weight: 0.90,
            specificity: 0.93,
            reliability: 0.92,
            category: EvidenceCategory::Headers,
        });
        
        evidence_weights.insert("x-served-by-fastly".to_string(), EvidenceWeight {
            base_weight: 0.88,
            specificity: 0.90,
            reliability: 0.89,
            category: EvidenceCategory::Headers,
        });
        
        // Vercel patterns
        evidence_weights.insert("x-vercel-id-header".to_string(), EvidenceWeight {
            base_weight: 0.95,
            specificity: 0.98,
            reliability: 0.96,
            category: EvidenceCategory::Headers,
        });
        
        evidence_weights.insert("vercel-server-header".to_string(), EvidenceWeight {
            base_weight: 0.90,
            specificity: 0.95,
            reliability: 0.93,
            category: EvidenceCategory::Server,
        });
        
        // === TIMING EVIDENCE WEIGHTS ===
        // Timing-based detections (high reliability for WAF delays)
        evidence_weights.insert("timing-waf-delay".to_string(), EvidenceWeight {
            base_weight: 0.85,
            specificity: 0.90,    // Very specific to WAF processing
            reliability: 0.88,    // Reliable when consistent
            category: EvidenceCategory::Behavioral,
        });
        
        evidence_weights.insert("timing-pattern-analysis".to_string(), EvidenceWeight {
            base_weight: 0.80,
            specificity: 0.85,    // Pattern-based timing
            reliability: 0.82,    // Good reliability for consistent patterns
            category: EvidenceCategory::Behavioral,
        });
        
        evidence_weights.insert("timing-baseline-comparison".to_string(), EvidenceWeight {
            base_weight: 0.83,
            specificity: 0.87,    // Baseline comparison is very specific
            reliability: 0.85,    // High reliability when controlled
            category: EvidenceCategory::Behavioral,
        });
        
        // === DNS EVIDENCE WEIGHTS ===
        // DNS-based detections (highest reliability - infrastructure level)
        evidence_weights.insert("dns-cname-cloudflare".to_string(), EvidenceWeight {
            base_weight: 0.98,
            specificity: 0.99,    // CNAME records are definitive
            reliability: 0.98,    // DNS is highly reliable
            category: EvidenceCategory::Network,
        });
        
        evidence_weights.insert("dns-cname-aws".to_string(), EvidenceWeight {
            base_weight: 0.98,
            specificity: 0.99,    // CloudFront CNAMEs are definitive
            reliability: 0.98,    // DNS is highly reliable
            category: EvidenceCategory::Network,
        });
        
        evidence_weights.insert("dns-cname-fastly".to_string(), EvidenceWeight {
            base_weight: 0.98,
            specificity: 0.99,    // Fastly CNAMEs are definitive
            reliability: 0.98,    // DNS is highly reliable
            category: EvidenceCategory::Network,
        });
        
        evidence_weights.insert("dns-cname-akamai".to_string(), EvidenceWeight {
            base_weight: 0.98,
            specificity: 0.99,    // Akamai CNAMEs are definitive
            reliability: 0.98,    // DNS is highly reliable
            category: EvidenceCategory::Network,
        });
        
        evidence_weights.insert("dns-cname-vercel".to_string(), EvidenceWeight {
            base_weight: 0.99,
            specificity: 0.99,    // Vercel CNAMEs are very specific
            reliability: 0.98,    // DNS is highly reliable
            category: EvidenceCategory::Network,
        });
        
        evidence_weights.insert("dns-cname-keycdn".to_string(), EvidenceWeight {
            base_weight: 0.98,
            specificity: 0.99,    // KeyCDN CNAMEs are definitive
            reliability: 0.98,    // DNS is highly reliable
            category: EvidenceCategory::Network,
        });
        
        evidence_weights.insert("dns-cname-maxcdn".to_string(), EvidenceWeight {
            base_weight: 0.98,
            specificity: 0.99,    // MaxCDN CNAMEs are definitive
            reliability: 0.98,    // DNS is highly reliable
            category: EvidenceCategory::Network,
        });
        
        // === PAYLOAD EVIDENCE WEIGHTS ===
        // Payload-based detections (behavioral patterns from WAF blocking)
        evidence_weights.insert("payload_detection_cloudflare".to_string(), EvidenceWeight {
            base_weight: 0.80,
            specificity: 0.85,    // WAF-specific blocking patterns
            reliability: 0.75,    // Good reliability when payloads are blocked
            category: EvidenceCategory::Behavioral,
        });
        
        evidence_weights.insert("payload_detection_aws_waf".to_string(), EvidenceWeight {
            base_weight: 0.80,
            specificity: 0.85,    // AWS WAF blocking patterns
            reliability: 0.75,    // Good reliability
            category: EvidenceCategory::Behavioral,
        });
        
        evidence_weights.insert("payload_detection_akamai".to_string(), EvidenceWeight {
            base_weight: 0.80,
            specificity: 0.85,    // Akamai blocking patterns
            reliability: 0.75,    // Good reliability
            category: EvidenceCategory::Behavioral,
        });
        
        evidence_weights.insert("payload_detection_generic_waf".to_string(), EvidenceWeight {
            base_weight: 0.70,
            specificity: 0.70,    // Generic WAF patterns
            reliability: 0.65,    // Lower reliability for generic detection
            category: EvidenceCategory::Behavioral,
        });
        
        evidence_weights.insert("blocked_xss_payload".to_string(), EvidenceWeight {
            base_weight: 0.75,
            specificity: 0.80,    // XSS blocking is common in WAFs
            reliability: 0.70,    // Good reliability
            category: EvidenceCategory::Behavioral,
        });
        
        evidence_weights.insert("blocked_sqlinjection_payload".to_string(), EvidenceWeight {
            base_weight: 0.75,
            specificity: 0.80,    // SQL injection blocking is common
            reliability: 0.70,    // Good reliability
            category: EvidenceCategory::Behavioral,
        });
        
        evidence_weights.insert("blocked_commandinjection_payload".to_string(), EvidenceWeight {
            base_weight: 0.78,
            specificity: 0.82,    // Command injection blocking
            reliability: 0.72,    // Good reliability
            category: EvidenceCategory::Behavioral,
        });
        
        evidence_weights.insert("blocked_pathtraversal_payload".to_string(), EvidenceWeight {
            base_weight: 0.77,
            specificity: 0.81,    // Path traversal blocking
            reliability: 0.71,    // Good reliability
            category: EvidenceCategory::Behavioral,
        });
        
        // Define negative evidence patterns
        let mut negative_evidence_patterns = HashMap::new();
        
        // If we see AWS headers, it's NOT CloudFlare
        negative_evidence_patterns.insert("CloudFlare".to_string(), vec![
            "x-amz-cf-id".to_string(),
            "x-amz-cf-pop".to_string(),
            "cloudfront".to_string(),
        ]);
        
        // If we see CloudFlare headers, it's NOT AWS
        negative_evidence_patterns.insert("AWS".to_string(), vec![
            "cf-ray".to_string(),
            "cf-cache-status".to_string(),
        ]);
        
        // If we see Akamai headers, it's NOT CloudFlare
        negative_evidence_patterns.insert("CloudFlare".to_string(), vec![
            "akamai-grn".to_string(),
            "x-akamai-transformed".to_string(),
        ]);
        
        Self {
            evidence_weights,
            confidence_thresholds: ConfidenceThresholds {
                minimum: 0.60,
                high: 0.90,
                very_high: 0.95,
                absolute: 0.98,
            },
            negative_evidence_patterns,
        }
    }
    
    /// Calculate advanced confidence score with detailed breakdown
    pub fn calculate_confidence(
        &self,
        provider: &str,
        evidence: &[Evidence],
        response_headers: &std::collections::HashMap<String, String>,
    ) -> ConfidenceResult {
        let mut total_score = 0.0;
        let mut evidence_breakdown = HashMap::new();
        let mut positive_evidence_count = 0;
        let mut negative_evidence_count = 0;
        let mut explanation_parts = Vec::new();
        
        // Initialize category scores
        for category in [
            EvidenceCategory::Headers,
            EvidenceCategory::Server,
            EvidenceCategory::Body,
            EvidenceCategory::StatusCode,
            EvidenceCategory::Behavioral,
            EvidenceCategory::ErrorPage,
            EvidenceCategory::Network,
        ] {
            evidence_breakdown.insert(category, 0.0);
        }
        
        // Process positive evidence
        for ev in evidence {
            let weight = if let Some(weight) = self.evidence_weights.get(&ev.signature_matched) {
                weight.clone()
            } else {
                // Fallback weight based on evidence method type
                self.get_fallback_weight(&ev.method_type, &ev.signature_matched)
            };
            
            let evidence_score = ev.confidence * weight.base_weight * weight.specificity * weight.reliability;
            total_score += evidence_score;
            
            // Add to category breakdown
            if let Some(category_score) = evidence_breakdown.get_mut(&weight.category) {
                *category_score += evidence_score;
            }
            
            positive_evidence_count += 1;
            explanation_parts.push(format!(
                "✅ {} ({:.1}% × {:.2} weight = {:.3})",
                ev.description,
                ev.confidence * 100.0,
                weight.base_weight * weight.specificity * weight.reliability,
                evidence_score
            ));
        }
        
        // Check for negative evidence (contradictory patterns)
        if let Some(negative_patterns) = self.negative_evidence_patterns.get(provider) {
            for pattern in negative_patterns {
                for header_name in response_headers.keys() {
                    if header_name.to_lowercase().contains(&pattern.to_lowercase()) {
                        negative_evidence_count += 1;
                        total_score *= 0.3; // Heavily penalize contradictory evidence
                        explanation_parts.push(format!(
                            "❌ Contradictory evidence: {} header found",
                            header_name
                        ));
                    }
                }
            }
        }
        
        // Apply evidence type bonuses/penalties
        let header_evidence_ratio = evidence_breakdown.get(&EvidenceCategory::Headers).unwrap_or(&0.0) / total_score.max(0.001);
        let body_evidence_ratio = evidence_breakdown.get(&EvidenceCategory::Body).unwrap_or(&0.0) / total_score.max(0.001);
        
        // Bonus for header-heavy evidence (more reliable)
        if header_evidence_ratio > 0.7 {
            total_score *= 1.1;
            explanation_parts.push("🎯 Header evidence bonus (+10%)".to_string());
        }
        
        // Penalty for body-heavy evidence (less reliable) 
        if body_evidence_ratio > 0.5 && header_evidence_ratio < 0.3 {
            total_score *= 0.8;
            explanation_parts.push("⚠️ Body evidence penalty (-20%)".to_string());
        }
        
        // Diversity bonus (multiple evidence types)
        let non_zero_categories = evidence_breakdown.values().filter(|&&v| v > 0.0).count();
        if non_zero_categories >= 3 {
            total_score *= 1.05;
            explanation_parts.push("🌟 Evidence diversity bonus (+5%)".to_string());
        }
        
        // Apply confidence ceiling
        total_score = total_score.min(1.0);
        
        // Determine confidence level
        let level = if total_score >= self.confidence_thresholds.absolute {
            ConfidenceLevel::Absolute
        } else if total_score >= self.confidence_thresholds.very_high {
            ConfidenceLevel::NearCertain
        } else if total_score >= self.confidence_thresholds.high {
            ConfidenceLevel::VeryHigh
        } else if total_score >= 0.80 {
            ConfidenceLevel::High
        } else if total_score >= self.confidence_thresholds.minimum {
            ConfidenceLevel::Moderate
        } else if total_score >= 0.20 {
            ConfidenceLevel::Low
        } else {
            ConfidenceLevel::None
        };
        
        // Generate missing evidence suggestions
        let missing_evidence = self.suggest_missing_evidence(provider, evidence);
        
        let explanation = format!(
            "Confidence Analysis for {}:\n{}\n\nFinal Score: {:.1}% ({:?})\nPositive Evidence: {} | Negative Evidence: {}",
            provider,
            explanation_parts.join("\n"),
            total_score * 100.0,
            level,
            positive_evidence_count,
            negative_evidence_count
        );
        
        ConfidenceResult {
            score: total_score,
            level,
            evidence_breakdown,
            positive_evidence_count,
            negative_evidence_count,
            missing_evidence,
            explanation,
        }
    }
    
    fn suggest_missing_evidence(&self, provider: &str, current_evidence: &[Evidence]) -> Vec<String> {
        let mut suggestions = Vec::new();
        let current_patterns: std::collections::HashSet<_> = current_evidence
            .iter()
            .map(|e| &e.signature_matched)
            .collect();
        
        // Suggest high-value missing evidence based on provider
        match provider {
            "CloudFlare" => {
                if !current_patterns.contains(&"cf-ray-header".to_string()) {
                    suggestions.push("CF-Ray header (highest confidence)".to_string());
                }
                if !current_patterns.contains(&"cf-cache-status-header".to_string()) {
                    suggestions.push("CF-Cache-Status header".to_string());
                }
            }
            "AWS" => {
                if !current_patterns.contains(&"x-amz-cf-id-header".to_string()) {
                    suggestions.push("X-Amz-Cf-Id header (CloudFront ID)".to_string());
                }
                if !current_patterns.contains(&"x-amz-cf-pop-header".to_string()) {
                    suggestions.push("X-Amz-Cf-Pop header (Point of Presence)".to_string());
                }
            }
            "Akamai" => {
                if !current_patterns.contains(&"akamai-grn-header".to_string()) {
                    suggestions.push("Akamai-GRN header".to_string());
                }
            }
            _ => {}
        }
        
        suggestions
    }
    
    /// Get fallback weight for unknown signatures based on method type
    fn get_fallback_weight(&self, method_type: &MethodType, _signature: &str) -> EvidenceWeight {
        match method_type {
            MethodType::Header(_) => {
                // Header evidence is most reliable
                EvidenceWeight {
                    base_weight: 0.85,
                    specificity: 0.80,
                    reliability: 0.90,
                    category: EvidenceCategory::Headers,
                }
            }
            MethodType::StatusCode(_) => {
                // Status code evidence is moderately reliable
                EvidenceWeight {
                    base_weight: 0.75,
                    specificity: 0.65,
                    reliability: 0.75,
                    category: EvidenceCategory::StatusCode,
                }
            }
            MethodType::Body(_) => {
                // Body evidence is least reliable
                EvidenceWeight {
                    base_weight: 0.55,
                    specificity: 0.45,
                    reliability: 0.60,
                    category: EvidenceCategory::Body,
                }
            }
            MethodType::Timing => {
                // Timing evidence is behavioral
                EvidenceWeight {
                    base_weight: 0.60,
                    specificity: 0.50,
                    reliability: 0.65,
                    category: EvidenceCategory::Behavioral,
                }
            }
            MethodType::DNS(_) => {
                // DNS evidence is network-based
                EvidenceWeight {
                    base_weight: 0.70,
                    specificity: 0.60,
                    reliability: 0.75,
                    category: EvidenceCategory::Network,
                }
            }
            MethodType::Certificate => {
                // Certificate evidence is network-based
                EvidenceWeight {
                    base_weight: 0.75,
                    specificity: 0.70,
                    reliability: 0.80,
                    category: EvidenceCategory::Network,
                }
            }
            MethodType::Payload => {
                // Payload evidence is behavioral (WAF blocking patterns)
                EvidenceWeight {
                    base_weight: 0.80,
                    specificity: 0.85,
                    reliability: 0.75,
                    category: EvidenceCategory::Behavioral,
                }
            }
        }
    }
}

impl Default for AdvancedScoring {
    fn default() -> Self {
        Self::new()
    }
} 