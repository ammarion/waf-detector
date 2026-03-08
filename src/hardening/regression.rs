use crate::active::{guard_target, ResolvedTarget};
use crate::audit::{AuditSession, RunAudit};
use crate::effectiveness::consent::ConsentManager;
use crate::hardening::finding::{
    ControlFamily, EvidenceRecord, EvidenceRequest, HardeningFinding, HardeningSeverity,
    ObservedAction, RegressionAssertion, RegressionExpectedAction, RegressionPack,
    RegressionPassCriteria, RegressionStabilityLevel,
};
use crate::http::{HttpClient, HttpResponse};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

pub fn build_regression_pack(
    findings: &mut [HardeningFinding],
    evidence_inventory: &[EvidenceRecord],
) -> RegressionPack {
    let evidence_by_id = evidence_inventory
        .iter()
        .map(|record| (record.id.as_str(), record))
        .collect::<HashMap<_, _>>();
    let mut assertions = Vec::new();

    for finding in findings {
        if finding.severity == HardeningSeverity::Info {
            continue;
        }

        let Some(evidence) = finding
            .evidence_refs
            .iter()
            .find_map(|id| evidence_by_id.get(id.as_str()).copied())
        else {
            continue;
        };
        let Some(request) = evidence.request.clone() else {
            continue;
        };

        let assertion = RegressionAssertion {
            finding_id: finding.id.clone(),
            endpoint_id: finding.endpoint_id.clone(),
            expected_action: expected_action(finding.control_family),
            request,
            baseline_request: evidence.baseline_request.clone(),
            pass_criteria: pass_criteria(finding.control_family),
            stability_level: stability_level(finding),
            evidence_refs: finding.evidence_refs.clone(),
        };
        finding.regression_assertion = Some(assertion.clone());
        assertions.push(assertion);
    }

    RegressionPack {
        schema_version: "hardening-regression-pack/v1".to_string(),
        generated_at: Utc::now(),
        assertions,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionAssertionResult {
    pub finding_id: String,
    pub passed: bool,
    pub expected_action: RegressionExpectedAction,
    pub observed_action: ObservedAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default)]
    pub matched_indicators: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionRunReport {
    pub schema_version: String,
    pub target: String,
    pub started_at: chrono::DateTime<Utc>,
    pub completed_at: chrono::DateTime<Utc>,
    pub total_assertions: usize,
    pub passed_assertions: usize,
    pub failed_assertions: usize,
    pub results: Vec<RegressionAssertionResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<RunAudit>,
}

#[async_trait]
trait RegressionHttpAdapter: Send + Sync {
    async fn send(
        &self,
        request: &EvidenceRequest,
        target: &ResolvedTarget,
    ) -> Result<HttpResponse>;
}

struct RealRegressionHttpAdapter {
    client: HttpClient,
}

impl RealRegressionHttpAdapter {
    fn new() -> Result<Self> {
        Ok(Self {
            client: HttpClient::new()?,
        })
    }
}

#[async_trait]
impl RegressionHttpAdapter for RealRegressionHttpAdapter {
    async fn send(
        &self,
        request: &EvidenceRequest,
        target: &ResolvedTarget,
    ) -> Result<HttpResponse> {
        self.client
            .request_pinned(
                &request.method,
                &request.url,
                &request.headers,
                request.body.as_deref(),
                target.pinned_ip,
                None,
            )
            .await
    }
}

pub struct RegressionRunner {
    scope: ConsentManager,
    http: Box<dyn RegressionHttpAdapter + Send + Sync>,
}

impl RegressionRunner {
    pub fn new() -> Result<Self> {
        Ok(Self {
            scope: ConsentManager::new(),
            http: Box::new(RealRegressionHttpAdapter::new()?),
        })
    }

    #[cfg(test)]
    fn with_adapter(adapter: Box<dyn RegressionHttpAdapter + Send + Sync>) -> Self {
        Self {
            scope: ConsentManager::new(),
            http: adapter,
        }
    }

    pub async fn run_pack(
        &self,
        pack: &RegressionPack,
        target_override: Option<&str>,
    ) -> Result<RegressionRunReport> {
        if pack.assertions.is_empty() {
            return Err(anyhow!("regression pack contains no assertions"));
        }

        let base_target = target_override.unwrap_or(&pack.assertions[0].request.url);
        let target = guard_target(&self.scope, base_target)?;
        let started_at = Utc::now();
        let mut audit = AuditSession::new("regression", &target, true)?;
        let mut results = Vec::with_capacity(pack.assertions.len());

        for assertion in &pack.assertions {
            match self.run_assertion(assertion, &target).await {
                Ok(result) => results.push(result),
                Err(err) => {
                    audit.record_failed(&err.to_string())?;
                    return Err(err);
                }
            }
        }

        audit.record_completed()?;
        let completed_at = Utc::now();
        let passed_assertions = results.iter().filter(|result| result.passed).count();
        let failed_assertions = results.len().saturating_sub(passed_assertions);

        Ok(RegressionRunReport {
            schema_version: "hardening-regression-run/v1".to_string(),
            target: target.normalized_url,
            started_at,
            completed_at,
            total_assertions: results.len(),
            passed_assertions,
            failed_assertions,
            results,
            audit: Some(audit.snapshot()),
        })
    }

    async fn run_assertion(
        &self,
        assertion: &RegressionAssertion,
        target: &ResolvedTarget,
    ) -> Result<RegressionAssertionResult> {
        let request = rebase_request(&assertion.request, &target.normalized_url)?;
        let baseline_response = if let Some(baseline_request) = &assertion.baseline_request {
            let rebased = rebase_request(baseline_request, &target.normalized_url)?;
            Some(self.http.send(&rebased, target).await?)
        } else {
            None
        };
        let response = self.http.send(&request, target).await?;
        Ok(evaluate_assertion(
            assertion,
            &response,
            baseline_response.as_ref(),
        ))
    }
}

fn expected_action(control_family: ControlFamily) -> RegressionExpectedAction {
    match control_family {
        ControlFamily::ChallengeEscalationGap => RegressionExpectedAction::Challenge,
        ControlFamily::RateLimitGap => RegressionExpectedAction::RateLimit,
        ControlFamily::SurfaceUnsuitable => RegressionExpectedAction::BaselineMatch,
        _ => RegressionExpectedAction::Block,
    }
}

fn pass_criteria(control_family: ControlFamily) -> RegressionPassCriteria {
    match control_family {
        ControlFamily::ChallengeEscalationGap => RegressionPassCriteria {
            expected_status_codes: vec![403, 429, 503],
            expected_indicators: vec![
                "captcha".to_string(),
                "challenge".to_string(),
                "jschl".to_string(),
                "cf-mitigated".to_string(),
            ],
            max_body_delta_ratio: None,
            notes: vec![
                "The reproduced request should trigger a challenge page, cookie gate, or hard block.".to_string(),
            ],
        },
        ControlFamily::RateLimitGap => RegressionPassCriteria {
            expected_status_codes: vec![429],
            expected_indicators: vec!["retry-after".to_string()],
            max_body_delta_ratio: None,
            notes: vec![
                "Replay the reproduced burst or hint sequence until rate limiting is observed.".to_string(),
            ],
        },
        ControlFamily::SurfaceUnsuitable => RegressionPassCriteria {
            expected_status_codes: Vec::new(),
            expected_indicators: Vec::new(),
            max_body_delta_ratio: Some(0.15),
            notes: vec![
                "Use this assertion only after moving testing to a real input surface.".to_string(),
            ],
        },
        _ => RegressionPassCriteria {
            expected_status_codes: vec![403, 406, 429, 503],
            expected_indicators: vec![
                "blocked".to_string(),
                "forbidden".to_string(),
                "access denied".to_string(),
                "security policy".to_string(),
            ],
            max_body_delta_ratio: None,
            notes: vec![
                "The reproduced request should no longer receive a normal allow response.".to_string(),
            ],
        },
    }
}

fn stability_level(finding: &HardeningFinding) -> RegressionStabilityLevel {
    if finding.confidence >= 0.85 && finding.reproducible {
        RegressionStabilityLevel::High
    } else if finding.confidence >= 0.65 {
        RegressionStabilityLevel::Medium
    } else {
        RegressionStabilityLevel::Low
    }
}

fn rebase_request(request: &EvidenceRequest, target_url: &str) -> Result<EvidenceRequest> {
    let mut rebased = Url::parse(target_url)
        .or_else(|_| Url::parse(&format!("https://{target_url}")))
        .map_err(|err| anyhow!("invalid regression target: {err}"))?;
    let source = Url::parse(&request.url)
        .or_else(|_| Url::parse(&format!("https://{}", request.url)))
        .map_err(|err| anyhow!("invalid regression request url '{}': {err}", request.url))?;
    rebased.set_path(source.path());
    rebased.set_query(source.query());
    rebased.set_fragment(source.fragment());

    Ok(EvidenceRequest {
        method: request.method.clone(),
        url: rebased.to_string(),
        headers: request.headers.clone(),
        body: request.body.clone(),
    })
}

fn evaluate_assertion(
    assertion: &RegressionAssertion,
    response: &HttpResponse,
    baseline_response: Option<&HttpResponse>,
) -> RegressionAssertionResult {
    let indicators = matched_indicators(response, &assertion.pass_criteria);
    let observed_action = classify_response(response, &indicators, baseline_response);
    let mut notes = Vec::new();
    let mut passed = match assertion.expected_action {
        RegressionExpectedAction::Block => observed_action == ObservedAction::Blocked,
        RegressionExpectedAction::Challenge => observed_action == ObservedAction::Challenge,
        RegressionExpectedAction::RateLimit => observed_action == ObservedAction::RateLimited,
        RegressionExpectedAction::BaselineMatch => baseline_matches(
            response,
            baseline_response,
            &assertion.pass_criteria,
            &mut notes,
        ),
    };

    if !assertion.pass_criteria.expected_status_codes.is_empty()
        && !assertion
            .pass_criteria
            .expected_status_codes
            .contains(&response.status)
        && assertion.expected_action != RegressionExpectedAction::BaselineMatch
    {
        notes.push(format!(
            "status {} did not match expected {:?}",
            response.status, assertion.pass_criteria.expected_status_codes
        ));
        passed = false;
    }

    if !assertion.pass_criteria.expected_indicators.is_empty()
        && indicators.is_empty()
        && assertion.expected_action != RegressionExpectedAction::BaselineMatch
    {
        notes.push("response did not contain any expected enforcement indicators".to_string());
        passed = false;
    }

    RegressionAssertionResult {
        finding_id: assertion.finding_id.clone(),
        passed,
        expected_action: assertion.expected_action,
        observed_action,
        status: Some(response.status),
        matched_indicators: indicators,
        notes,
    }
}

fn baseline_matches(
    response: &HttpResponse,
    baseline_response: Option<&HttpResponse>,
    criteria: &RegressionPassCriteria,
    notes: &mut Vec<String>,
) -> bool {
    let Some(baseline) = baseline_response else {
        notes.push("baseline comparison was requested without a baseline request".to_string());
        return false;
    };

    if response.status != baseline.status {
        notes.push(format!(
            "status {} differed from baseline {}",
            response.status, baseline.status
        ));
        return false;
    }

    if let Some(max_delta_ratio) = criteria.max_body_delta_ratio {
        let baseline_len = baseline.body.len() as f64;
        let delta_ratio = if baseline_len == 0.0 {
            if response.body.is_empty() {
                0.0
            } else {
                1.0
            }
        } else {
            ((response.body.len() as f64 - baseline_len).abs()) / baseline_len
        };
        if delta_ratio > max_delta_ratio {
            notes.push(format!(
                "body delta ratio {:.3} exceeded max {:.3}",
                delta_ratio, max_delta_ratio
            ));
            return false;
        }
    }

    true
}

fn matched_indicators(response: &HttpResponse, criteria: &RegressionPassCriteria) -> Vec<String> {
    let body_lower = response.body.to_ascii_lowercase();
    let header_blob = response
        .headers
        .iter()
        .map(|(name, value)| {
            format!(
                "{}:{}",
                name.to_ascii_lowercase(),
                value.to_ascii_lowercase()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    criteria
        .expected_indicators
        .iter()
        .filter(|indicator| {
            let needle = indicator.to_ascii_lowercase();
            body_lower.contains(&needle) || header_blob.contains(&needle)
        })
        .cloned()
        .collect()
}

fn response_deviates_from_baseline(
    response: &HttpResponse,
    baseline_response: Option<&HttpResponse>,
) -> bool {
    baseline_response
        .is_none_or(|baseline| response.status != baseline.status || response.body != baseline.body)
}

fn classify_response(
    response: &HttpResponse,
    matched_indicators: &[String],
    baseline_response: Option<&HttpResponse>,
) -> ObservedAction {
    if response.status == 429 {
        return ObservedAction::RateLimited;
    }

    let challenge_markers = [
        "captcha",
        "challenge",
        "jschl",
        "turnstile",
        "recaptcha",
        "hcaptcha",
    ];
    let body_lower = response.body.to_ascii_lowercase();
    let header_blob = response
        .headers
        .iter()
        .map(|(name, value)| {
            format!(
                "{}:{}",
                name.to_ascii_lowercase(),
                value.to_ascii_lowercase()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    if matched_indicators.iter().any(|indicator| {
        challenge_markers
            .iter()
            .any(|marker| indicator.to_ascii_lowercase().contains(marker))
    }) || (response_deviates_from_baseline(response, baseline_response)
        && challenge_markers
            .iter()
            .any(|marker| body_lower.contains(marker) || header_blob.contains(marker)))
    {
        return ObservedAction::Challenge;
    }

    if matches!(response.status, 403 | 406 | 503) {
        return ObservedAction::Blocked;
    }

    if response_deviates_from_baseline(response, baseline_response)
        && (body_lower.contains("access denied")
            || body_lower.contains("blocked")
            || body_lower.contains("forbidden")
            || body_lower.contains("security policy"))
    {
        return ObservedAction::Blocked;
    }

    ObservedAction::Allowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardening::finding::{EvidenceSource, ObservedAction};
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use tempfile::TempDir;

    #[test]
    fn test_regression_pack_uses_evidence_request_and_expected_action() {
        let mut findings = vec![HardeningFinding {
            id: "f1".to_string(),
            title: "Normalization gap".to_string(),
            severity: HardeningSeverity::High,
            confidence: 0.9,
            control_family: ControlFamily::NormalizationGap,
            vector: "query".to_string(),
            channels: vec!["query".to_string()],
            reproducible: true,
            preconditions: Vec::new(),
            bypass_summary: "summary".to_string(),
            likely_root_cause: "cause".to_string(),
            fix_guidance: Vec::new(),
            vendor_guidance: Vec::new(),
            endpoint_id: Some("ep-1".to_string()),
            path_template: Some("/api/tokenize".to_string()),
            auth_class: None,
            discovery_sources: Vec::new(),
            regression_assertion: None,
            evidence_refs: vec!["ev-1".to_string()],
        }];
        let evidence = vec![EvidenceRecord {
            id: "ev-1".to_string(),
            source: EvidenceSource::Va,
            summary: "Allowed malicious query".to_string(),
            observed_action: ObservedAction::Allowed,
            request: Some(EvidenceRequest {
                method: "GET".to_string(),
                url: "https://example.com/?q=%252e%252e%252f".to_string(),
                headers: Vec::new(),
                body: None,
            }),
            baseline_request: None,
            response_comparison: None,
        }];

        let pack = build_regression_pack(&mut findings, &evidence);
        assert_eq!(pack.assertions.len(), 1);
        assert_eq!(
            pack.assertions[0].expected_action,
            RegressionExpectedAction::Block
        );
        assert_eq!(pack.assertions[0].endpoint_id.as_deref(), Some("ep-1"));
        assert!(findings[0].regression_assertion.is_some());
    }

    #[test]
    fn test_evaluate_block_assertion_passes_on_blocked_response() {
        let assertion = RegressionAssertion {
            finding_id: "f1".to_string(),
            endpoint_id: None,
            expected_action: RegressionExpectedAction::Block,
            request: EvidenceRequest {
                method: "GET".to_string(),
                url: "https://example.com".to_string(),
                headers: Vec::new(),
                body: None,
            },
            baseline_request: None,
            pass_criteria: RegressionPassCriteria {
                expected_status_codes: vec![403, 406],
                expected_indicators: vec!["blocked".to_string()],
                max_body_delta_ratio: None,
                notes: Vec::new(),
            },
            stability_level: RegressionStabilityLevel::High,
            evidence_refs: Vec::new(),
        };
        let response = HttpResponse {
            status: 403,
            headers: HashMap::new(),
            body: "Request blocked by security policy".to_string(),
            url: "https://example.com".to_string(),
        };

        let result = evaluate_assertion(&assertion, &response, None);
        assert!(result.passed);
        assert_eq!(result.observed_action, ObservedAction::Blocked);
    }

    #[test]
    fn test_evaluate_baseline_match_fails_on_large_body_delta() {
        let assertion = RegressionAssertion {
            finding_id: "f1".to_string(),
            endpoint_id: None,
            expected_action: RegressionExpectedAction::BaselineMatch,
            request: EvidenceRequest {
                method: "GET".to_string(),
                url: "https://example.com".to_string(),
                headers: Vec::new(),
                body: None,
            },
            baseline_request: Some(EvidenceRequest {
                method: "GET".to_string(),
                url: "https://example.com".to_string(),
                headers: Vec::new(),
                body: None,
            }),
            pass_criteria: RegressionPassCriteria {
                expected_status_codes: Vec::new(),
                expected_indicators: Vec::new(),
                max_body_delta_ratio: Some(0.1),
                notes: Vec::new(),
            },
            stability_level: RegressionStabilityLevel::High,
            evidence_refs: Vec::new(),
        };
        let baseline = HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: "baseline".to_string(),
            url: "https://example.com".to_string(),
        };
        let response = HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: "baseline response changed substantially".to_string(),
            url: "https://example.com".to_string(),
        };

        let result = evaluate_assertion(&assertion, &response, Some(&baseline));
        assert!(!result.passed);
        assert_eq!(result.observed_action, ObservedAction::Allowed);
    }

    #[test]
    fn test_block_classification_ignores_unchanged_block_keyword_body() {
        let baseline = HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: "access denied".to_string(),
            url: "https://example.com".to_string(),
        };
        let response = HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: "access denied".to_string(),
            url: "https://example.com".to_string(),
        };

        assert_eq!(
            classify_response(&response, &[], Some(&baseline)),
            ObservedAction::Allowed
        );
    }

    #[test]
    fn test_block_classification_uses_changed_block_keyword_body() {
        let baseline = HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: "ok".to_string(),
            url: "https://example.com".to_string(),
        };
        let response = HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: "access denied".to_string(),
            url: "https://example.com".to_string(),
        };

        assert_eq!(
            classify_response(&response, &[], Some(&baseline)),
            ObservedAction::Blocked
        );
    }

    struct MockAdapter {
        responses: std::sync::Mutex<VecDeque<HttpResponse>>,
    }

    #[async_trait]
    impl RegressionHttpAdapter for MockAdapter {
        async fn send(
            &self,
            _request: &EvidenceRequest,
            _target: &ResolvedTarget,
        ) -> Result<HttpResponse> {
            self.responses
                .lock()
                .expect("responses mutex")
                .pop_front()
                .ok_or_else(|| anyhow!("no more responses"))
        }
    }

    #[tokio::test]
    async fn test_runner_replays_pack_and_counts_failures() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("WAF_DETECTOR_HOME").ok();
        let tempdir = TempDir::new().expect("tempdir");
        std::env::set_var("WAF_DETECTOR_HOME", tempdir.path());
        let scope = ConsentManager::new();
        scope
            .set_authorized_targets(&["example.com".to_string()])
            .expect("scope init");

        let runner = RegressionRunner::with_adapter(Box::new(MockAdapter {
            responses: std::sync::Mutex::new(VecDeque::from(vec![HttpResponse {
                status: 403,
                headers: HashMap::new(),
                body: "blocked by waf".to_string(),
                url: "https://example.com".to_string(),
            }])),
        }));
        let pack = RegressionPack {
            schema_version: "hardening-regression-pack/v1".to_string(),
            generated_at: Utc::now(),
            assertions: vec![RegressionAssertion {
                finding_id: "f1".to_string(),
                endpoint_id: None,
                expected_action: RegressionExpectedAction::Block,
                request: EvidenceRequest {
                    method: "GET".to_string(),
                    url: "https://example.com/?q=test".to_string(),
                    headers: Vec::new(),
                    body: None,
                },
                baseline_request: None,
                pass_criteria: RegressionPassCriteria {
                    expected_status_codes: vec![403],
                    expected_indicators: vec!["blocked".to_string()],
                    max_body_delta_ratio: None,
                    notes: Vec::new(),
                },
                stability_level: RegressionStabilityLevel::High,
                evidence_refs: Vec::new(),
            }],
        };

        let report = runner
            .run_pack(&pack, Some("https://example.com"))
            .await
            .unwrap();

        if let Some(value) = original_home {
            std::env::set_var("WAF_DETECTOR_HOME", value);
        } else {
            std::env::remove_var("WAF_DETECTOR_HOME");
        }

        assert_eq!(report.passed_assertions, 1);
        assert_eq!(report.failed_assertions, 0);
    }
}
