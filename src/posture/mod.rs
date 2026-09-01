//! Posture summary — unified operator-facing report aggregating detection, VA2, and VA1 signals.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::virtual_adversary::{VaEnforcement, VaRunReport};
use crate::virtual_adversary2::Va2RunReport;
use crate::DetectionResult;

pub mod scoring;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostureGrade {
    A,
    B,
    C,
    D,
    F,
}

impl std::fmt::Display for PostureGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PostureGrade::A => write!(f, "A"),
            PostureGrade::B => write!(f, "B"),
            PostureGrade::C => write!(f, "C"),
            PostureGrade::D => write!(f, "D"),
            PostureGrade::F => write!(f, "F"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionPosture {
    pub waf_detected: bool,
    pub waf_name: Option<String>,
    pub waf_confidence: f64,
    pub cdn_detected: bool,
    pub cdn_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralPosture {
    pub pmi_score: f64,
    pub pmi_label: String,
    pub differential_score: f64,
    pub challenge_score: f64,
    #[serde(default)]
    pub blind_spot_count: usize,
    #[serde(default)]
    pub channel_coverage_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementPosture {
    pub enforcement: String,
    pub confidence_score: f64,
    pub risk_label: String,
    pub blocked_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureReport {
    pub target_url: String,
    pub timestamp: DateTime<Utc>,
    pub grade: PostureGrade,
    pub risk_score: f64,
    pub detection: Option<DetectionPosture>,
    pub behavioral: Option<BehavioralPosture>,
    pub enforcement: Option<EnforcementPosture>,
    pub summary: String,
    /// Blended estimate that the target is actively enforcing (blocking/
    /// challenging), from whichever of VA1/VA2 ran. Additive: does not
    /// affect `risk_score`/`grade`.
    #[serde(default)]
    pub active_enforcement_likelihood: f64,
    /// P(WAF present but not enforcing) = WAF presence * (1 -
    /// active_enforcement_likelihood), or `None` when neither an enforcement
    /// test nor a behavioral campaign ran — without one, the product is
    /// vacuously zero and a `0.0` would assert a negative from no evidence.
    ///
    /// A `Some(0.0)` is measured, but is not a clean negative either: an
    /// inline engine that inspects in microseconds and alters nothing is not
    /// remotely observable. `summary` says so when that case arises. See
    /// `docs/MONITOR_MODE_VALIDATION.md`.
    ///
    /// Additive: does not affect `risk_score`/`grade`.
    #[serde(default)]
    pub monitor_mode_likelihood: Option<f64>,
}

pub struct PostureBuilder {
    target_url: String,
    detection: Option<DetectionPosture>,
    detection_confidence: f64,
    behavioral: Option<BehavioralPosture>,
    pmi_normalized: f64,
    channel_coverage_score: f64,
    enforcement: Option<EnforcementPosture>,
    enforcement_score: f64,
    va1_report: Option<VaRunReport>,
    va2_report: Option<Va2RunReport>,
}

pub fn compose_posture_summary(
    detection: Option<&DetectionResult>,
    va2: Option<&Va2RunReport>,
    va1: Option<&VaRunReport>,
) -> crate::PostureSummary {
    let mut coverage_by_vector = HashMap::new();
    let mut caveats = Vec::new();

    let detection_confidence = detection.and_then(|d| d.waf_confidence()).unwrap_or(0.0);

    let (pair_count, coverage_score) = va2
        .map(|report| {
            if let Some(coverage) = &report.channel_coverage {
                for (channel, score) in &coverage.channels {
                    coverage_by_vector.insert(channel.to_string(), *score);
                }
            }
            let pairs = report
                .paired_control
                .as_ref()
                .map(|p| p.executed_pairs)
                .unwrap_or(report.differential.len());
            (
                pairs,
                report
                    .channel_coverage
                    .as_ref()
                    .map(|c| c.coverage_score)
                    .unwrap_or(0.0),
            )
        })
        .unwrap_or((0, 0.0));

    let active_enforcement_likelihood = scoring::active_enforcement_likelihood(va1, va2);
    let waf_presence_likelihood = scoring::waf_presence_likelihood(detection_confidence, va2);
    let monitor_mode_likelihood = scoring::monitor_mode_likelihood_measured(
        va1.is_some(),
        va2.is_some(),
        waf_presence_likelihood,
        active_enforcement_likelihood,
    );

    let overall_posture_score = ((active_enforcement_likelihood * 65.0)
        + (coverage_score * 25.0)
        + (detection_confidence * 10.0))
        .clamp(0.0, 100.0);

    if pair_count == 0 {
        caveats.push("No paired-control differential evidence collected".to_string());
    } else if pair_count < 4 {
        caveats
            .push("Low paired-control sample size; enforcement estimate may be noisy".to_string());
    }

    if coverage_score < 0.35 {
        caveats.push("Channel coverage is limited; unprotected channels likely remain".to_string());
    }

    if monitor_mode_likelihood.is_none() {
        caveats.push(
            "Monitor-mode likelihood not determined: no enforcement test or behavioral campaign ran"
                .to_string(),
        );
    } else if scoring::monitor_mode_is_measured_zero(monitor_mode_likelihood) {
        caveats.push(scoring::MONITOR_MODE_ZERO_CAVEAT.to_string());
    }

    if std::env::var("WAF_DETECTOR_INSECURE_TLS").is_ok() {
        caveats.push("TLS certificates were not validated during this run".to_string());
    }

    let confidence = (0.35
        + (detection_confidence * 0.25)
        + ((pair_count.min(12) as f64 / 12.0) * 0.25)
        + (coverage_score * 0.15))
        .clamp(0.0, 1.0);

    crate::PostureSummary {
        overall_posture_score,
        monitor_mode_likelihood,
        active_enforcement_likelihood,
        coverage_by_vector,
        confidence,
        caveats,
    }
}

impl PostureBuilder {
    pub fn new(target_url: &str) -> Self {
        Self {
            target_url: target_url.to_string(),
            detection: None,
            detection_confidence: 0.0,
            behavioral: None,
            pmi_normalized: 0.0,
            channel_coverage_score: 0.0,
            enforcement: None,
            enforcement_score: 0.0,
            va1_report: None,
            va2_report: None,
        }
    }

    pub fn with_detection(mut self, result: &DetectionResult) -> Self {
        let waf_confidence = result.waf_confidence().unwrap_or(0.0);
        self.detection = Some(DetectionPosture {
            waf_detected: result.has_waf(),
            waf_name: result.waf_name().map(String::from),
            waf_confidence,
            cdn_detected: result.has_cdn(),
            cdn_name: result.cdn_name().map(String::from),
        });
        self.detection_confidence = waf_confidence;
        self
    }

    pub fn with_va2(mut self, report: &Va2RunReport) -> Self {
        let pmi_normalized = report.pmi.score / 100.0;
        let (blind_spot_count, cov_score) = report
            .channel_coverage
            .as_ref()
            .map(|cc| (cc.blind_spots.len(), cc.coverage_score))
            .unwrap_or((0, 0.0));
        self.behavioral = Some(BehavioralPosture {
            pmi_score: report.pmi.score,
            pmi_label: report.pmi.label.clone(),
            differential_score: report.wbf.differential_score,
            challenge_score: report.wbf.challenge_score,
            blind_spot_count,
            channel_coverage_score: cov_score,
        });
        self.pmi_normalized = pmi_normalized;
        self.channel_coverage_score = cov_score;
        self.va2_report = Some(report.clone());
        self
    }

    pub fn with_va1(mut self, report: &VaRunReport) -> Self {
        let confidence = report.summary.confidence_score();
        self.enforcement = Some(EnforcementPosture {
            enforcement: format!("{:?}", report.enforcement),
            confidence_score: confidence,
            risk_label: report.summary.risk_label().to_string(),
            blocked_ratio: if report.summary.total > 0 {
                report.summary.blocked as f64 / report.summary.total as f64
            } else {
                0.0
            },
        });
        // Map enforcement level to a score
        self.enforcement_score = match report.enforcement {
            VaEnforcement::HardBlock => confidence,
            VaEnforcement::ChallengeGate => confidence * 0.8,
            VaEnforcement::SilentFilter => confidence * 0.5,
            VaEnforcement::NoEnforcement => 0.0,
            // Same score as NoEnforcement — this variant changes the label,
            // not the enforcement-strength math. See spec section 2 / Global
            // Constraints: no new risk-scoring logic for this variant.
            VaEnforcement::PresentNotEnforcing => 0.0,
            VaEnforcement::Inconclusive => confidence * 0.3,
        };
        self.va1_report = Some(report.clone());
        self
    }

    pub fn compute(self) -> PostureReport {
        // Grade calculation: start from worst (100), subtract for protection signals
        let mut base = 100.0_f64;
        let mut parts = Vec::new();

        if self.detection.is_some() {
            let reduction = 20.0 * self.detection_confidence;
            base -= reduction;
            if self.detection_confidence > 0.0 {
                parts.push(format!(
                    "WAF detected ({:.0}% confidence)",
                    self.detection_confidence * 100.0
                ));
            }
        }

        if self.behavioral.is_some() {
            // Blind spots reduce the effective PMI benefit
            let channel_factor = if self.channel_coverage_score > 0.0 {
                self.channel_coverage_score
            } else {
                1.0 // No coverage data = no adjustment
            };
            let reduction = 30.0 * self.pmi_normalized * channel_factor;
            base -= reduction;
            parts.push(format!("protection {:.0}/100", self.pmi_normalized * 100.0));
            if self.channel_coverage_score > 0.0 {
                parts.push(format!(
                    "channel coverage {:.0}%",
                    self.channel_coverage_score * 100.0
                ));
            }
        }

        if self.enforcement.is_some() {
            let reduction = 20.0 * self.enforcement_score;
            base -= reduction;
            parts.push(format!(
                "enforcement {:.0}%",
                self.enforcement_score * 100.0
            ));
        }

        let risk_score = base.clamp(0.0, 100.0);

        let grade = if risk_score <= 20.0 {
            PostureGrade::A
        } else if risk_score <= 40.0 {
            PostureGrade::B
        } else if risk_score <= 60.0 {
            PostureGrade::C
        } else if risk_score <= 80.0 {
            PostureGrade::D
        } else {
            PostureGrade::F
        };

        let summary = if parts.is_empty() {
            "No protection signals detected.".to_string()
        } else {
            format!("Grade {grade}: {}", parts.join(", "))
        };

        let active_enforcement_likelihood = scoring::active_enforcement_likelihood_normalized(
            self.va1_report.as_ref(),
            self.va2_report.as_ref(),
        );
        // Presence, not `self.detection_confidence`. The latter is 0.0 for any
        // WAF that leaves no passive signature, and because
        // `monitor_mode_likelihood` is a product, a 0.0 presence term makes
        // "present but not enforcing" unreportable for precisely those targets.
        let waf_presence_likelihood =
            scoring::waf_presence_likelihood(self.detection_confidence, self.va2_report.as_ref());
        let monitor_mode_likelihood = scoring::monitor_mode_likelihood_measured(
            self.va1_report.is_some(),
            self.va2_report.is_some(),
            waf_presence_likelihood,
            active_enforcement_likelihood,
        );

        // `PostureReport` has no `caveats` field, so the limit rides on the
        // summary -- otherwise a `Some(0.0)` reaches `--posture-json` and the
        // HTML report as a bare, confident-looking zero.
        let summary = if scoring::monitor_mode_is_measured_zero(monitor_mode_likelihood) {
            // The composed summary does not end in punctuation, so separate
            // explicitly rather than running the two sentences together.
            format!(
                "{}. {}",
                summary.trim_end_matches(['.', ' ']),
                scoring::MONITOR_MODE_ZERO_CAVEAT
            )
        } else {
            summary
        };

        PostureReport {
            target_url: self.target_url,
            timestamp: Utc::now(),
            grade,
            risk_score,
            detection: self.detection,
            behavioral: self.behavioral,
            enforcement: self.enforcement,
            summary,
            active_enforcement_likelihood,
            monitor_mode_likelihood,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DetectionMetadata, DetectionResult, ProviderDetection};
    use std::collections::HashMap;

    fn mock_detection_result(waf_confidence: f64) -> DetectionResult {
        DetectionResult {
            url: "https://example.com".to_string(),
            detected_waf: if waf_confidence > 0.0 {
                Some(ProviderDetection {
                    name: "CloudFlare".to_string(),
                    confidence: waf_confidence,
                })
            } else {
                None
            },
            detected_cdn: None,
            provider_scores: HashMap::new(),
            evidence_map: HashMap::new(),
            evidence: Vec::new(),
            detection_time_ms: 50,
            metadata: DetectionMetadata {
                timestamp: chrono::Utc::now(),
                version: "0.1.0".to_string(),
                user_agent: "test".to_string(),
            },
            caveats: Vec::new(),
            security_posture: None,
            error: None,
        }
    }

    fn mock_va2_report(pmi_score: f64, diff_score: f64) -> Va2RunReport {
        use crate::virtual_adversary2::*;
        Va2RunReport {
            target_url: "https://example.com".to_string(),
            plan: Va2CampaignPlan {
                version: "va2-0.1".to_string(),
                seed: 1,
                target_url: "https://example.com".to_string(),
                phases: vec![Va2Phase::Baseline],
                budget: 10,
                steps: vec![],
            },
            results: vec![],
            baseline: Va2BaselineSummary::default(),
            normalization: None,
            statefulness: None,
            challenge: None,
            throttle: None,
            wbf: Va2WbfSummary {
                // See the note in scoring.rs's fixture: these mocks stand for an
                // enforcing WAF, so the discrimination they describe is
                // enforcement discrimination.
                differential_score: diff_score,
                enforcement_differential_score: diff_score,
                challenge_score: 0.5,
                ..Default::default()
            },
            pmi: Va2PmiScore {
                score: pmi_score,
                label: if pmi_score >= 80.0 {
                    "strong".to_string()
                } else {
                    "weak".to_string()
                },
            },
            differential: vec![],
            channel_coverage: None,
            paired_control: None,
            audit: None,
        }
    }

    #[test]
    fn test_posture_detection_only() {
        let det = mock_detection_result(0.95);
        let report = PostureBuilder::new("https://example.com")
            .with_detection(&det)
            .compute();

        // WAF at 0.95 confidence: base = 100 - (20 * 0.95) = 81
        assert!(report.risk_score > 80.0 && report.risk_score < 82.0);
        assert_eq!(report.grade, PostureGrade::F);
        assert!(report.detection.is_some());
        assert!(report.behavioral.is_none());
        assert!(report.enforcement.is_none());
    }

    #[test]
    fn test_posture_with_va2() {
        let det = mock_detection_result(0.95);
        let va2 = mock_va2_report(80.0, 0.8);
        let report = PostureBuilder::new("https://example.com")
            .with_detection(&det)
            .with_va2(&va2)
            .compute();

        // base = 100 - (20 * 0.95) - (30 * 0.80) = 100 - 19 - 24 = 57
        assert!(report.risk_score > 56.0 && report.risk_score < 58.0);
        assert_eq!(report.grade, PostureGrade::C);
        assert!(report.behavioral.is_some());
    }

    #[test]
    fn test_posture_json_roundtrip() {
        let det = mock_detection_result(0.90);
        let report = PostureBuilder::new("https://example.com")
            .with_detection(&det)
            .compute();

        let json = serde_json::to_string(&report).unwrap();
        let parsed: PostureReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.target_url, report.target_url);
        assert_eq!(parsed.grade, report.grade);
        assert!((parsed.risk_score - report.risk_score).abs() < f64::EPSILON);
    }

    #[test]
    fn test_posture_grade_thresholds() {
        // No protection at all = F (risk 100)
        let report = PostureBuilder::new("https://example.com").compute();
        assert_eq!(report.grade, PostureGrade::F);
        assert!((report.risk_score - 100.0).abs() < f64::EPSILON);

        // Full protection = A (risk near 0)
        let det = mock_detection_result(1.0);
        let va2 = mock_va2_report(100.0, 1.0);
        let report = PostureBuilder::new("https://example.com")
            .with_detection(&det)
            .with_va2(&va2)
            .compute();
        // base = 100 - 20 - 30 = 50... still C without VA1
        assert_eq!(report.grade, PostureGrade::C);

        // Full everything
        use crate::virtual_adversary::{VaResultSummary, VirtualAdversaryConfig};
        let va1 = VaRunReport {
            target_url: "https://example.com".to_string(),
            plan_size: 10,
            replay_plan: vec![],
            summary: VaResultSummary {
                total: 10,
                blocked: 10,
                challenge: 0,
                allowed: 0,
                error: 0,
            },
            enforcement: VaEnforcement::HardBlock,
            evidence_score: 1.0,
            evidence_summary: vec![],
            config: VirtualAdversaryConfig::default(),
            results: vec![],
            started_at: std::time::Instant::now(),
            finished_at: None,
            replay_bundle: None,
            audit: None,
        };
        let report = PostureBuilder::new("https://example.com")
            .with_detection(&det)
            .with_va2(&va2)
            .with_va1(&va1)
            .compute();
        // base = 100 - 20 - 30 - (20 * 1.0) = 30
        assert_eq!(report.grade, PostureGrade::B);
        assert!(report.risk_score > 29.0 && report.risk_score < 31.0);
    }

    #[test]
    fn test_posture_with_channel_coverage() {
        use crate::virtual_adversary2::*;
        use std::collections::HashMap as StdHashMap;

        let det = mock_detection_result(0.95);
        let mut va2 = mock_va2_report(80.0, 0.8);
        // Set partial channel coverage (blind spots reduce effective protection)
        va2.channel_coverage = Some(Va2ChannelCoverage {
            channels: {
                let mut ch = StdHashMap::new();
                ch.insert(Va2ProbeChannel::Query, 1.0);
                ch.insert(Va2ProbeChannel::Path, 1.0);
                ch.insert(Va2ProbeChannel::Header, 0.0); // blind spot
                ch.insert(Va2ProbeChannel::Body, 0.5);
                ch.insert(Va2ProbeChannel::Method, 0.0); // blind spot
                ch
            },
            blind_spots: vec![Va2ProbeChannel::Header, Va2ProbeChannel::Method],
            coverage_score: 0.5,
        });

        let report = PostureBuilder::new("https://example.com")
            .with_detection(&det)
            .with_va2(&va2)
            .compute();

        // With channel_coverage_score = 0.5, the VA2 reduction is halved:
        // base = 100 - (20 * 0.95) - (30 * 0.80 * 0.50) = 100 - 19 - 12 = 69
        assert!(
            report.risk_score > 68.0 && report.risk_score < 70.0,
            "expected risk ~69, got {}",
            report.risk_score
        );
        assert_eq!(report.grade, PostureGrade::D);
        assert!(report.behavioral.is_some());
        let beh = report.behavioral.unwrap();
        assert_eq!(beh.blind_spot_count, 2);
        assert!((beh.channel_coverage_score - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_posture_monitor_mode_likelihood_high_when_waf_present_and_not_blocking() {
        use crate::virtual_adversary::{VaResultSummary, VirtualAdversaryConfig};

        let det = mock_detection_result(0.9);
        let va1 = VaRunReport {
            target_url: "https://example.com".to_string(),
            plan_size: 10,
            replay_plan: vec![],
            summary: VaResultSummary {
                total: 10,
                blocked: 0,
                challenge: 0,
                allowed: 10,
                error: 0,
            },
            enforcement: VaEnforcement::PresentNotEnforcing,
            evidence_score: 0.1,
            evidence_summary: vec![],
            config: VirtualAdversaryConfig::default(),
            results: vec![],
            started_at: std::time::Instant::now(),
            finished_at: None,
            replay_bundle: None,
            audit: None,
        };
        let report = PostureBuilder::new("https://example.com")
            .with_detection(&det)
            .with_va1(&va1)
            .compute();

        // Additive fields reflect "WAF present, not enforcing":
        assert!(
            report.monitor_mode_likelihood.is_some_and(|v| v > 0.7),
            "got {:?}",
            report.monitor_mode_likelihood
        );
        assert!(
            report.active_enforcement_likelihood < 0.3,
            "got {}",
            report.active_enforcement_likelihood
        );

        // Discriminating check: grade/risk_score math is UNTOUCHED.
        // enforcement_score for PresentNotEnforcing is 0.0 (same as
        // NoEnforcement, per Task 3) -> base = 100 - (20*0.9) - (20*0.0) = 82.
        assert!(
            report.risk_score > 81.0 && report.risk_score < 83.0,
            "got {}",
            report.risk_score
        );
        assert_eq!(report.grade, PostureGrade::F);
    }

    /// A bare builder ran no enforcement test and no behavioral campaign,
    /// so monitor mode is *not determined* -- not zero. Reporting 0.0 here
    /// was the defect: it asserted a negative from an absence of evidence.
    #[test]
    fn test_posture_monitor_mode_is_none_when_nothing_was_run() {
        let report = PostureBuilder::new("https://example.com").compute();
        assert_eq!(report.monitor_mode_likelihood, None);
        assert_eq!(report.active_enforcement_likelihood, 0.0);
    }

    /// Passive detection alone is still no evidence about enforcement, so a
    /// confident WAF signature must not turn into a monitor-mode reading.
    #[test]
    fn test_posture_monitor_mode_is_none_with_detection_but_no_probes() {
        let det = mock_detection_result(0.95);
        let report = PostureBuilder::new("https://example.com")
            .with_detection(&det)
            .compute();
        assert_eq!(report.monitor_mode_likelihood, None);
    }

    /// A measured zero must carry the reason it is not a clean negative,
    /// because `PostureReport` has no caveats field to put it in.
    #[test]
    fn test_posture_measured_zero_monitor_mode_explains_itself_in_summary() {
        let det = mock_detection_result(0.9);
        let va2 = mock_va2_report(85.0, 0.95);
        let report = PostureBuilder::new("https://example.com")
            .with_detection(&det)
            .with_va2(&va2)
            .compute();
        if scoring::monitor_mode_is_measured_zero(report.monitor_mode_likelihood) {
            assert!(
                report.summary.contains("does not rule out monitor mode"),
                "measured zero without its caveat: {}",
                report.summary
            );
        }
    }

    #[test]
    fn test_posture_monitor_mode_likelihood_low_when_va1_alone_shows_hard_block() {
        use crate::virtual_adversary::{VaResultSummary, VirtualAdversaryConfig};

        let det = mock_detection_result(0.9);
        let va1 = VaRunReport {
            target_url: "https://example.com".to_string(),
            plan_size: 10,
            replay_plan: vec![],
            summary: VaResultSummary {
                total: 10,
                blocked: 10,
                challenge: 0,
                allowed: 0,
                error: 0,
            },
            enforcement: VaEnforcement::HardBlock,
            evidence_score: 0.9,
            evidence_summary: vec![],
            config: VirtualAdversaryConfig::default(),
            results: vec![],
            started_at: std::time::Instant::now(),
            finished_at: None,
            replay_bundle: None,
            audit: None,
        };
        let report = PostureBuilder::new("https://example.com")
            .with_detection(&det)
            .with_va1(&va1)
            .compute();

        // Regression test for the final-review-caught bug: a WAF blocking 100%
        // of VA1 probes, with no VA2 evidence, must NOT read as "likely present
        // but not enforcing." Before the normalization fix, this was 0.72
        // (self-contradictory next to a HardBlock verdict).
        assert!(
            report.active_enforcement_likelihood > 0.9,
            "got {}",
            report.active_enforcement_likelihood
        );
        assert!(
            report.monitor_mode_likelihood.is_some_and(|v| v < 0.1),
            "got {:?}",
            report.monitor_mode_likelihood
        );
    }

    #[test]
    fn test_posture_monitor_mode_likelihood_low_when_va1_alone_shows_challenge_gate() {
        use crate::virtual_adversary::{VaResultSummary, VirtualAdversaryConfig};

        let det = mock_detection_result(0.9);
        let va1 = VaRunReport {
            target_url: "https://example.com".to_string(),
            plan_size: 10,
            replay_plan: vec![],
            summary: VaResultSummary {
                total: 10,
                blocked: 0,
                challenge: 10,
                allowed: 0,
                error: 0,
            },
            enforcement: VaEnforcement::ChallengeGate,
            evidence_score: 0.9,
            evidence_summary: vec![],
            config: VirtualAdversaryConfig::default(),
            results: vec![],
            started_at: std::time::Instant::now(),
            finished_at: None,
            replay_bundle: None,
            audit: None,
        };
        let report = PostureBuilder::new("https://example.com")
            .with_detection(&det)
            .with_va1(&va1)
            .compute();

        // Regression test for a bug found during live --posture-va1
        // verification: a WAF challenging 100% of VA1 probes (ChallengeGate),
        // with no VA2 evidence, must NOT read as "likely present but not
        // enforcing" -- before this fix, active_enforcement_likelihood only
        // counted outright-blocked requests, so this scenario produced
        // monitor_mode_likelihood ~1.0 next to a live ChallengeGate verdict.
        assert!(
            report.active_enforcement_likelihood > 0.9,
            "got {}",
            report.active_enforcement_likelihood
        );
        assert!(
            report.monitor_mode_likelihood.is_some_and(|v| v < 0.1),
            "got {:?}",
            report.monitor_mode_likelihood
        );
    }

    #[test]
    fn test_compose_posture_summary_with_low_signal_caveats() {
        let det = mock_detection_result(0.8);
        let va2 = mock_va2_report(30.0, 0.1);
        let summary = compose_posture_summary(Some(&det), Some(&va2), None);
        assert!(summary.monitor_mode_likelihood.is_some_and(|v| v > 0.5));
        assert!(summary.active_enforcement_likelihood < 0.3);
        assert!(!summary.caveats.is_empty());
    }

    #[test]
    fn test_compose_posture_summary_coverage_projection() {
        use crate::virtual_adversary2::{Va2ChannelCoverage, Va2ProbeChannel};
        use std::collections::HashMap as StdHashMap;
        let det = mock_detection_result(0.9);
        let mut va2 = mock_va2_report(85.0, 0.9);
        va2.channel_coverage = Some(Va2ChannelCoverage {
            channels: {
                let mut channels = StdHashMap::new();
                channels.insert(Va2ProbeChannel::Query, 1.0);
                channels.insert(Va2ProbeChannel::Header, 0.5);
                channels
            },
            blind_spots: vec![],
            coverage_score: 0.75,
        });
        let summary = compose_posture_summary(Some(&det), Some(&va2), None);
        assert!(summary.coverage_by_vector.contains_key("query"));
        assert!(summary.coverage_by_vector.contains_key("header"));
        assert!(summary.confidence > 0.5);
        assert!(summary.overall_posture_score > 40.0);
    }
}
