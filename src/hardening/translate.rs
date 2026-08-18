use crate::active::ResolvedTarget;
use crate::effectiveness::report::EffectivenessReport;
use crate::effectiveness::static_detection::StaticPageAnalysis;
use crate::effectiveness::techniques;
use crate::engine::waf_mode_detector::PayloadType;
use crate::hardening::finding::{
    ControlFamily, CoverageSummary, EvidenceRecord, EvidenceRequest, EvidenceSource,
    HardeningFinding, HardeningSeverity, ObservedAction, ResponseComparison, SurfaceAssessment,
};
use crate::payload::waf_smoke_test::{PayloadClassification, SmokeTestResult};
use crate::surface::{AuthClass, DiscoverySource, SurfaceEndpoint};
use crate::virtual_adversary::{
    VaEvidenceKind, VaOutcome, VaPayloadCategory, VaReplayPlanItem, VaRunReport,
};
use crate::virtual_adversary2::{Va2CampaignStep, Va2ProbeChannel, Va2RunReport};
use url::Url;

#[derive(Debug, Default)]
pub struct TranslationBundle {
    pub findings: Vec<HardeningFinding>,
    pub evidence_inventory: Vec<EvidenceRecord>,
    pub coverage: CoverageSummary,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RouteFindingContext {
    pub endpoint_id: String,
    pub path_template: String,
    pub auth_class: AuthClass,
    pub discovery_sources: Vec<DiscoverySource>,
}

impl From<&SurfaceEndpoint> for RouteFindingContext {
    fn from(endpoint: &SurfaceEndpoint) -> Self {
        Self {
            endpoint_id: endpoint.endpoint_id.clone(),
            path_template: endpoint.path_template.clone(),
            auth_class: endpoint.auth_class,
            discovery_sources: endpoint.discovery_sources.clone(),
        }
    }
}

fn scoped_id(prefix: &str, context: Option<&RouteFindingContext>, idx: usize) -> String {
    context
        .map(|context| format!("{}-{}-{}", context.endpoint_id, prefix, idx))
        .unwrap_or_else(|| format!("{prefix}-{idx}"))
}

fn apply_route_context(finding: &mut HardeningFinding, context: Option<&RouteFindingContext>) {
    if let Some(context) = context {
        finding.endpoint_id = Some(context.endpoint_id.clone());
        finding.path_template = Some(context.path_template.clone());
        finding.auth_class = Some(context.auth_class);
        finding.discovery_sources = context.discovery_sources.clone();
    }
}

fn idx_from_channel(channel: Va2ProbeChannel) -> usize {
    match channel {
        Va2ProbeChannel::Path => 1,
        Va2ProbeChannel::Query => 2,
        Va2ProbeChannel::Header => 3,
        Va2ProbeChannel::Body => 4,
        Va2ProbeChannel::Method => 5,
    }
}

pub fn surface_assessment_from_static(
    analysis: Option<&StaticPageAnalysis>,
    smoke: Option<&SmokeTestResult>,
) -> SurfaceAssessment {
    if let Some(analysis) = analysis {
        let mut indicators = analysis
            .indicators
            .iter()
            .map(describe_static_indicator)
            .collect::<Vec<_>>();
        let suggestions = analysis
            .suggestions
            .iter()
            .map(|entry| format!("{}: {}", entry.endpoint, entry.description))
            .collect::<Vec<_>>();
        let mut suitable = !analysis.is_likely_static;
        let mut reason = if analysis.is_likely_static {
            "Target appears to be a static or low-interaction surface.".to_string()
        } else {
            "Target appears suitable for input-processing and edge hardening tests.".to_string()
        };

        if let Some(smoke) = smoke.and_then(|report| report.endpoint_context.as_ref()) {
            if smoke.likely_noninteractive {
                suitable = false;
                reason = "Target behaved like a low-interaction surface during smoke testing."
                    .to_string();
                indicators.push(format!(
                    "Smoke context similarity {:.2} with likely non-interactive behavior",
                    smoke.similarity
                ));
            }
        }

        SurfaceAssessment {
            suitable,
            confidence: if suitable {
                analysis.confidence.min(0.75)
            } else {
                analysis.confidence.min(0.5)
            },
            reason,
            indicators,
            suggestions,
        }
    } else {
        SurfaceAssessment {
            suitable: true,
            confidence: 0.25,
            reason: "Static surface assessment unavailable; proceeding with active findings only."
                .to_string(),
            indicators: Vec::new(),
            suggestions: Vec::new(),
        }
    }
}

pub fn translate_surface_assessment(
    target: &ResolvedTarget,
    assessment: &SurfaceAssessment,
    context: Option<&RouteFindingContext>,
) -> TranslationBundle {
    if assessment.suitable {
        return TranslationBundle::default();
    }

    let evidence_id = scoped_id("evidence-surface-unsuitable", context, 1);
    let mut finding = HardeningFinding {
        id: scoped_id("surface-unsuitable", context, 1),
        title: "Surface is not suitable for hardening validation".to_string(),
        severity: HardeningSeverity::Info,
        confidence: assessment.confidence.min(0.5),
        control_family: ControlFamily::SurfaceUnsuitable,
        vector: "target-surface".to_string(),
        channels: Vec::new(),
        reproducible: false,
        preconditions: vec!["Move testing to an endpoint that parses user input.".to_string()],
        bypass_summary: assessment.reason.clone(),
        likely_root_cause:
            "The tested endpoint looks static or non-interactive, so active control gaps are not measurable here.".to_string(),
        fix_guidance: Vec::new(),
        vendor_guidance: Vec::new(),
        endpoint_id: None,
        path_template: None,
        auth_class: None,
        discovery_sources: Vec::new(),
        regression_assertion: None,
        evidence_refs: vec![evidence_id.clone()],
    };
    apply_route_context(&mut finding, context);
    let evidence = EvidenceRecord {
        id: evidence_id,
        source: EvidenceSource::SurfaceAssessment,
        summary: assessment.reason.clone(),
        observed_action: ObservedAction::BaselineMatch,
        request: Some(EvidenceRequest {
            method: "GET".to_string(),
            url: target.normalized_url.clone(),
            headers: Vec::new(),
            body: None,
        }),
        baseline_request: None,
        response_comparison: Some(ResponseComparison {
            summary: assessment.indicators.clone(),
        }),
    };

    let mut coverage = CoverageSummary::default();
    coverage.sources_run.push("surface_assessment".to_string());
    coverage.findings_by_family.insert(
        ControlFamily::SurfaceUnsuitable.as_str().to_string(),
        1usize,
    );
    coverage.evidence_count = 1;

    TranslationBundle {
        findings: vec![finding],
        evidence_inventory: vec![evidence],
        coverage,
        notes: Vec::new(),
    }
}

pub fn translate_smoke(
    target: &ResolvedTarget,
    smoke: &SmokeTestResult,
    context: Option<&RouteFindingContext>,
) -> TranslationBundle {
    let mut bundle = TranslationBundle::default();
    bundle.coverage.sources_run.push("smoke".to_string());

    for (idx, result) in smoke.test_results.iter().enumerate() {
        let Some((severity, confidence)) =
            smoke_gap_severity(result.payload_type.clone(), &result.classification)
        else {
            continue;
        };
        let control_family = control_family_from_payload_type(result.payload_type.clone());
        let channel = if result.payload_type == PayloadType::ScannerDetection {
            "header".to_string()
        } else {
            "query".to_string()
        };
        let finding_id = scoped_id("smoke", context, idx + 1);
        let evidence_id = scoped_id("evidence-smoke", context, idx + 1);
        let request = if result.payload_type == PayloadType::ScannerDetection {
            EvidenceRequest {
                method: "GET".to_string(),
                url: target.normalized_url.clone(),
                headers: vec![("User-Agent".to_string(), result.payload.clone())],
                body: None,
            }
        } else {
            EvidenceRequest {
                method: "GET".to_string(),
                url: append_query(&target.normalized_url, "test", &result.payload),
                headers: Vec::new(),
                body: None,
            }
        };
        let evidence = EvidenceRecord {
            id: evidence_id.clone(),
            source: EvidenceSource::Smoke,
            summary: format!(
                "Smoke probe `{}` produced {} with status {}",
                result.payload,
                classification_label(&result.classification),
                result.response_status
            ),
            observed_action: observed_action_from_smoke(&result.classification),
            request: Some(request),
            baseline_request: Some(EvidenceRequest {
                method: "GET".to_string(),
                url: target.normalized_url.clone(),
                headers: Vec::new(),
                body: None,
            }),
            response_comparison: Some(ResponseComparison {
                summary: result.evidence.clone(),
            }),
        };
        let mut finding = HardeningFinding {
            id: finding_id,
            title: format!("Smoke probe bypassed {}", result.payload_type),
            severity,
            confidence,
            control_family,
            vector: result.payload.clone(),
            channels: vec![channel],
            reproducible: true,
            preconditions: vec!["Owned target registered in active scope.".to_string()],
            bypass_summary: format!(
                "A coarse smoke probe for `{}` received an {} response instead of an enforcement action.",
                result.payload,
                classification_label(&result.classification).to_ascii_lowercase()
            ),
            likely_root_cause: smoke_root_cause(control_family).to_string(),
            fix_guidance: Vec::new(),
            vendor_guidance: Vec::new(),
            endpoint_id: None,
            path_template: None,
            auth_class: None,
            discovery_sources: Vec::new(),
            regression_assertion: None,
            evidence_refs: vec![evidence_id],
        };
        apply_route_context(&mut finding, context);
        *bundle
            .coverage
            .findings_by_family
            .entry(control_family.as_str().to_string())
            .or_insert(0) += 1;
        bundle.evidence_inventory.push(evidence);
        bundle.findings.push(finding);
    }

    if smoke
        .endpoint_context
        .as_ref()
        .map(|context| context.likely_noninteractive)
        .unwrap_or(false)
        && bundle.findings.is_empty()
    {
        bundle.notes.push(
            "Smoke testing suggests the target behaves like a low-interaction surface.".to_string(),
        );
    }
    bundle.coverage.evidence_count = bundle.evidence_inventory.len();
    bundle
}

pub fn translate_va(
    target: &ResolvedTarget,
    report: &VaRunReport,
    context: Option<&RouteFindingContext>,
) -> TranslationBundle {
    let mut bundle = TranslationBundle::default();
    bundle.coverage.sources_run.push("va".to_string());

    for (idx, result) in report.results.iter().enumerate() {
        if matches!(result.outcome, VaOutcome::Blocked | VaOutcome::Error) {
            continue;
        }
        let plan_item = report.replay_plan.get(idx);
        let control_family = control_family_from_va(result.category, plan_item);
        let severity = va_severity(result.category, result.outcome, &result.evidence);
        let confidence = va_confidence(&result.evidence);
        let channel = plan_item
            .map(|item| item.channel.to_ascii_lowercase())
            .unwrap_or_else(|| "unknown".to_string());
        let evidence_id = scoped_id("evidence-va", context, idx + 1);
        let request = plan_item.map(evidence_request_from_va);
        let evidence = EvidenceRecord {
            id: evidence_id.clone(),
            source: EvidenceSource::Va,
            summary: format!(
                "VA probe `{}` resulted in {:?} ({})",
                result.payload, result.outcome, result.reason
            ),
            observed_action: match result.outcome {
                VaOutcome::Allowed => ObservedAction::Allowed,
                VaOutcome::Challenge => ObservedAction::Challenge,
                VaOutcome::Blocked => ObservedAction::Blocked,
                VaOutcome::Error => ObservedAction::Error,
            },
            request,
            baseline_request: Some(EvidenceRequest {
                method: "GET".to_string(),
                url: target.normalized_url.clone(),
                headers: Vec::new(),
                body: None,
            }),
            response_comparison: Some(ResponseComparison {
                summary: result
                    .evidence
                    .iter()
                    .map(|entry| entry.detail.clone())
                    .collect(),
            }),
        };
        let mut finding = HardeningFinding {
            id: scoped_id("va", context, idx + 1),
            title: format!("VA probe exposed {}", control_family.as_str()),
            severity,
            confidence,
            control_family,
            vector: result.payload.clone(),
            channels: vec![channel],
            reproducible: true,
            preconditions: vec!["Owned target registered in active scope.".to_string()],
            bypass_summary: va_bypass_summary(result.outcome, &result.payload),
            likely_root_cause: va_root_cause(control_family).to_string(),
            fix_guidance: Vec::new(),
            vendor_guidance: Vec::new(),
            endpoint_id: None,
            path_template: None,
            auth_class: None,
            discovery_sources: Vec::new(),
            regression_assertion: None,
            evidence_refs: vec![evidence_id],
        };
        apply_route_context(&mut finding, context);
        *bundle
            .coverage
            .findings_by_family
            .entry(control_family.as_str().to_string())
            .or_insert(0) += 1;
        bundle.evidence_inventory.push(evidence);
        bundle.findings.push(finding);
    }

    bundle.coverage.evidence_count = bundle.evidence_inventory.len();
    bundle
}

pub fn translate_va2(
    target: &ResolvedTarget,
    report: &Va2RunReport,
    context: Option<&RouteFindingContext>,
) -> TranslationBundle {
    let mut bundle = TranslationBundle::default();
    bundle.coverage.sources_run.push("va2".to_string());

    if let Some(coverage) = &report.channel_coverage {
        bundle.coverage.coverage_score = Some(coverage.coverage_score);
        for (channel, score) in &coverage.channels {
            bundle
                .coverage
                .channel_scores
                .insert(channel.to_string(), *score);
            if *score >= 0.5 {
                continue;
            }

            let control_family = control_family_from_va2_channel(*channel);
            let differential = report
                .differential
                .iter()
                .find(|diff| diff.channel == Some(*channel) && !diff.discriminated);
            let evidence_id = scoped_id("evidence-va2", context, idx_from_channel(*channel));
            let evidence = EvidenceRecord {
                id: evidence_id.clone(),
                source: EvidenceSource::Va2,
                summary: format!(
                    "VA2 channel `{}` discrimination score was {:.2}",
                    channel, score
                ),
                observed_action: ObservedAction::BaselineMatch,
                request: differential
                    .and_then(|diff| step_by_id(&report.plan.steps, diff.step_id))
                    .map(|step| evidence_request_from_va2_step(&target.normalized_url, step)),
                baseline_request: differential
                    .and_then(|diff| step_by_id(&report.plan.steps, diff.baseline_step_id))
                    .map(|step| evidence_request_from_va2_step(&target.normalized_url, step)),
                response_comparison: differential.map(|diff| ResponseComparison {
                    summary: vec![
                        format!("status_delta={}", diff.status_delta),
                        format!("body_length_pct_change={:.3}", diff.body_length_pct_change),
                        format!("header_mutation_count={}", diff.header_mutation_count),
                        format!("timing_delta_ms={}", diff.timing_delta_ms),
                    ],
                }),
            };
            let severity = if coverage.blind_spots.contains(channel) {
                HardeningSeverity::High
            } else {
                HardeningSeverity::Medium
            };
            let mut finding = HardeningFinding {
                id: scoped_id("va2", context, idx_from_channel(*channel)),
                title: if coverage.blind_spots.contains(channel) {
                    format!("No discrimination across {} probes", channel)
                } else {
                    format!("Weak discrimination across {} probes", channel)
                },
                severity,
                confidence: 0.85,
                control_family,
                vector: channel.to_string(),
                channels: vec![channel.to_string()],
                reproducible: true,
                preconditions: vec![
                    "Paired-control VA2 plan executed on the owned target.".to_string()
                ],
                bypass_summary: if coverage.blind_spots.contains(channel) {
                    format!(
                        "Variant {} probes matched their baseline responses, indicating a channel blind spot.",
                        channel
                    )
                } else {
                    format!(
                        "{} probes only discriminated {:.0}% of the time, leaving inconsistent enforcement coverage.",
                        channel,
                        score * 100.0
                    )
                },
                likely_root_cause: va2_root_cause(control_family).to_string(),
                fix_guidance: Vec::new(),
                vendor_guidance: Vec::new(),
                endpoint_id: None,
                path_template: None,
                auth_class: None,
                discovery_sources: Vec::new(),
                regression_assertion: None,
                evidence_refs: vec![evidence_id],
            };
            apply_route_context(&mut finding, context);
            *bundle
                .coverage
                .findings_by_family
                .entry(control_family.as_str().to_string())
                .or_insert(0) += 1;
            bundle.evidence_inventory.push(evidence);
            bundle.findings.push(finding);
        }
    }

    bundle.coverage.evidence_count = bundle.evidence_inventory.len();
    bundle
}

pub fn translate_effectiveness(
    target: &ResolvedTarget,
    report: &EffectivenessReport,
    intensity_level: u8,
    context: Option<&RouteFindingContext>,
) -> TranslationBundle {
    let mut bundle = TranslationBundle::default();
    bundle
        .coverage
        .sources_run
        .push("effectiveness".to_string());

    for (idx, vulnerability) in report.vulnerabilities.iter().enumerate() {
        let Some(control_family) = map_effectiveness_category(&vulnerability.category) else {
            continue;
        };
        let Some((request, baseline_request)) = reconstruct_effectiveness_requests(
            &target.normalized_url,
            &vulnerability.description,
            intensity_level,
        ) else {
            continue;
        };

        let evidence_id = scoped_id("evidence-effectiveness", context, idx + 1);
        let severity = parse_effectiveness_severity(&vulnerability.severity);
        let confidence = if baseline_request.is_some() { 0.8 } else { 0.6 };
        let evidence = EvidenceRecord {
            id: evidence_id.clone(),
            source: EvidenceSource::Effectiveness,
            summary: vulnerability.evidence.clone(),
            observed_action: ObservedAction::Allowed,
            request: Some(request),
            baseline_request,
            response_comparison: Some(ResponseComparison {
                summary: vec![vulnerability.evidence.clone()],
            }),
        };
        let mut finding = HardeningFinding {
            id: scoped_id("effectiveness", context, idx + 1),
            title: format!("Effectiveness engine found {}", vulnerability.category),
            severity,
            confidence,
            control_family,
            vector: vulnerability.category.clone(),
            channels: vec![effectiveness_channel(control_family).to_string()],
            reproducible: true,
            preconditions: vec![
                "Effectiveness testing executed against the owned target.".to_string()
            ],
            bypass_summary: vulnerability.description.clone(),
            likely_root_cause: vulnerability.remediation.clone(),
            fix_guidance: Vec::new(),
            vendor_guidance: Vec::new(),
            endpoint_id: None,
            path_template: None,
            auth_class: None,
            discovery_sources: Vec::new(),
            regression_assertion: None,
            evidence_refs: vec![evidence_id],
        };
        apply_route_context(&mut finding, context);
        *bundle
            .coverage
            .findings_by_family
            .entry(control_family.as_str().to_string())
            .or_insert(0) += 1;
        bundle.evidence_inventory.push(evidence);
        bundle.findings.push(finding);
    }

    bundle.coverage.evidence_count = bundle.evidence_inventory.len();
    bundle
}

fn describe_static_indicator(
    indicator: &crate::effectiveness::static_detection::StaticIndicator,
) -> String {
    match indicator {
        crate::effectiveness::static_detection::StaticIndicator::CacheHeaders { header, value } => {
            format!("Cache header {header}={value}")
        }
        crate::effectiveness::static_detection::StaticIndicator::CdnDetected {
            provider,
            header,
        } => format!("CDN/header indicator {provider} via {header}"),
        crate::effectiveness::static_detection::StaticIndicator::StaticContentType {
            content_type,
        } => format!("Static content type {content_type}"),
        crate::effectiveness::static_detection::StaticIndicator::NoServerHeaders => {
            "No dynamic server-side headers detected".to_string()
        }
        crate::effectiveness::static_detection::StaticIndicator::IdenticalResponses {
            similarity_percentage,
        } => format!(
            "Responses remained {:.1}% identical after parameter mutation",
            similarity_percentage
        ),
        crate::effectiveness::static_detection::StaticIndicator::StaticFileExtension {
            extension,
        } => format!("Static file extension {extension}"),
        crate::effectiveness::static_detection::StaticIndicator::StaticHostingPlatform {
            platform,
        } => format!("Static hosting platform {platform}"),
    }
}

fn smoke_gap_severity(
    payload_type: PayloadType,
    classification: &PayloadClassification,
) -> Option<(HardeningSeverity, f64)> {
    match classification {
        PayloadClassification::Allowed => Some((
            match payload_type {
                PayloadType::SqlInjectionAdvanced
                | PayloadType::PathTraversal
                | PayloadType::CommandInjection
                | PayloadType::HttpRequestSmuggling
                | PayloadType::SSRF
                | PayloadType::Log4Shell => HardeningSeverity::High,
                PayloadType::XssAdvanced
                | PayloadType::SqlInjectionBasic
                | PayloadType::GraphQLInjection
                | PayloadType::SSTI
                | PayloadType::PrototypePollution
                | PayloadType::FileUpload => HardeningSeverity::Medium,
                _ => HardeningSeverity::Low,
            },
            0.6,
        )),
        PayloadClassification::Challenge => Some((HardeningSeverity::Medium, 0.58)),
        _ => None,
    }
}

fn control_family_from_payload_type(payload_type: PayloadType) -> ControlFamily {
    match payload_type {
        PayloadType::PathTraversal => ControlFamily::PathHandlingGap,
        PayloadType::ScannerDetection => ControlFamily::HeaderTrustGap,
        PayloadType::Enumeration => ControlFamily::ChallengeEscalationGap,
        PayloadType::HttpRequestSmuggling => ControlFamily::ParserMismatch,
        PayloadType::GraphQLInjection
        | PayloadType::SSTI
        | PayloadType::PrototypePollution
        | PayloadType::SSRF
        | PayloadType::Log4Shell
        | PayloadType::WebSocketInjection
        | PayloadType::CommandInjection
        | PayloadType::FileUpload
        | PayloadType::SqlInjectionBasic
        | PayloadType::SqlInjectionAdvanced
        | PayloadType::XssBasic
        | PayloadType::XssAdvanced => ControlFamily::BodyInspectionGap,
    }
}

fn smoke_root_cause(control_family: ControlFamily) -> &'static str {
    match control_family {
        ControlFamily::PathHandlingGap => {
            "Path normalization and traversal handling did not force the reproduced variant through a blocking policy."
        }
        ControlFamily::HeaderTrustGap => {
            "Header-based threat classification is too weak or trusts attacker-controlled signals."
        }
        ControlFamily::ParserMismatch => {
            "The edge parser likely accepted an ambiguous request shape without enforcing a denial policy."
        }
        ControlFamily::ChallengeEscalationGap => {
            "Threat scoring did not escalate this coarse probe into a challenge or block."
        }
        _ => {
            "Input inspection coverage is weaker than expected for this coarse payload family."
        }
    }
}

fn observed_action_from_smoke(classification: &PayloadClassification) -> ObservedAction {
    match classification {
        PayloadClassification::Allowed => ObservedAction::Allowed,
        PayloadClassification::Blocked => ObservedAction::Blocked,
        PayloadClassification::Error => ObservedAction::Error,
        PayloadClassification::RateLimited => ObservedAction::RateLimited,
        PayloadClassification::Challenge => ObservedAction::Challenge,
    }
}

fn classification_label(classification: &PayloadClassification) -> &'static str {
    match classification {
        PayloadClassification::Allowed => "ALLOWED",
        PayloadClassification::Blocked => "BLOCKED",
        PayloadClassification::Error => "ERROR",
        PayloadClassification::RateLimited => "RATE LIMITED",
        PayloadClassification::Challenge => "CHALLENGE",
    }
}

fn control_family_from_va(
    category: VaPayloadCategory,
    plan_item: Option<&VaReplayPlanItem>,
) -> ControlFamily {
    match category {
        VaPayloadCategory::SqlInjection | VaPayloadCategory::Xss => {
            ControlFamily::BodyInspectionGap
        }
        VaPayloadCategory::PathTraversal => ControlFamily::PathHandlingGap,
        VaPayloadCategory::ParserAmbiguity => ControlFamily::ParserMismatch,
        VaPayloadCategory::ProtocolMutation => match plan_item.map(|item| item.channel.as_str()) {
            Some("Method") => ControlFamily::MethodSemanticsGap,
            _ => ControlFamily::HeaderTrustGap,
        },
        VaPayloadCategory::EncodingBoundary => ControlFamily::NormalizationGap,
        VaPayloadCategory::BehavioralThrottle => ControlFamily::RateLimitGap,
        VaPayloadCategory::ResponseFingerprint => ControlFamily::ChallengeEscalationGap,
        VaPayloadCategory::SemanticDrift => match plan_item.map(|item| item.channel.as_str()) {
            Some("Path") => ControlFamily::PathHandlingGap,
            Some("Method") => ControlFamily::MethodSemanticsGap,
            Some("Cookie") => ControlFamily::StatefulnessGap,
            _ => ControlFamily::NormalizationGap,
        },
        VaPayloadCategory::AdversaryProbe => ControlFamily::BodyInspectionGap,
    }
}

fn va_severity(
    category: VaPayloadCategory,
    outcome: VaOutcome,
    evidence: &[crate::virtual_adversary::VaEvidence],
) -> HardeningSeverity {
    let high_confidence = evidence.iter().any(|entry| {
        matches!(
            entry.kind,
            VaEvidenceKind::BaselineDeviation
                | VaEvidenceKind::StatusChange
                | VaEvidenceKind::HeaderDiff
                | VaEvidenceKind::LengthDelta
        )
    });
    match outcome {
        VaOutcome::Allowed => match category {
            VaPayloadCategory::SqlInjection | VaPayloadCategory::PathTraversal
                if high_confidence =>
            {
                HardeningSeverity::Critical
            }
            VaPayloadCategory::SqlInjection
            | VaPayloadCategory::PathTraversal
            | VaPayloadCategory::ParserAmbiguity
            | VaPayloadCategory::ProtocolMutation
            | VaPayloadCategory::EncodingBoundary => HardeningSeverity::High,
            _ => HardeningSeverity::Medium,
        },
        VaOutcome::Challenge => match category {
            VaPayloadCategory::SqlInjection | VaPayloadCategory::PathTraversal => {
                HardeningSeverity::High
            }
            _ => HardeningSeverity::Medium,
        },
        _ => HardeningSeverity::Low,
    }
}

fn va_confidence(evidence: &[crate::virtual_adversary::VaEvidence]) -> f64 {
    if evidence.iter().any(|entry| {
        matches!(
            entry.kind,
            VaEvidenceKind::BaselineDeviation
                | VaEvidenceKind::StatusChange
                | VaEvidenceKind::HeaderDiff
                | VaEvidenceKind::LengthDelta
        )
    }) {
        0.9
    } else {
        0.65
    }
}

fn evidence_request_from_va(item: &VaReplayPlanItem) -> EvidenceRequest {
    EvidenceRequest {
        method: item.method.clone(),
        url: item.url.clone(),
        headers: item.headers.clone(),
        body: item.body.clone(),
    }
}

fn va_bypass_summary(outcome: VaOutcome, payload: &str) -> String {
    match outcome {
        VaOutcome::Allowed => format!(
            "The reproduced adversarial payload `{payload}` was allowed instead of being blocked."
        ),
        VaOutcome::Challenge => format!(
            "The reproduced adversarial payload `{payload}` only triggered a challenge, not a hard block."
        ),
        VaOutcome::Blocked => format!("The payload `{payload}` was blocked."),
        VaOutcome::Error => format!("The payload `{payload}` produced an error."),
    }
}

fn va_root_cause(control_family: ControlFamily) -> &'static str {
    match control_family {
        ControlFamily::NormalizationGap => {
            "Edge normalization appears out of sync with the detection transforms applied before rule evaluation."
        }
        ControlFamily::ParserMismatch => {
            "The WAF and origin likely parse the same request structure differently, leaving ambiguous requests under-inspected."
        }
        ControlFamily::HeaderTrustGap => {
            "Header canonicalization or trusted-header policy appears inconsistent for the reproduced variant."
        }
        ControlFamily::MethodSemanticsGap => {
            "Method overrides or semantic drift are not receiving the same enforcement as standard request flows."
        }
        ControlFamily::PathHandlingGap => {
            "Path routing and traversal normalization are not consistently enforced before the request reaches origin logic."
        }
        ControlFamily::BodyInspectionGap => {
            "The reproduced payload reached the application without consistent query/body inspection coverage."
        }
        ControlFamily::ChallengeEscalationGap => {
            "Threat scoring is visible, but escalation stops short of a deterministic deny decision."
        }
        ControlFamily::RateLimitGap => {
            "Stateful throttling does not treat the reproduced request family as part of the same abusive sequence."
        }
        ControlFamily::StatefulnessGap => {
            "Suspicion does not persist across equivalent requests or follow-up probes."
        }
        ControlFamily::SurfaceUnsuitable => {
            "The target surface does not process enough input for meaningful hardening validation."
        }
    }
}

fn control_family_from_va2_channel(channel: Va2ProbeChannel) -> ControlFamily {
    match channel {
        Va2ProbeChannel::Path => ControlFamily::PathHandlingGap,
        Va2ProbeChannel::Query => ControlFamily::NormalizationGap,
        Va2ProbeChannel::Header => ControlFamily::HeaderTrustGap,
        Va2ProbeChannel::Body => ControlFamily::BodyInspectionGap,
        Va2ProbeChannel::Method => ControlFamily::MethodSemanticsGap,
    }
}

fn va2_root_cause(control_family: ControlFamily) -> &'static str {
    match control_family {
        ControlFamily::NormalizationGap => {
            "Equivalent query variants were not discriminated, suggesting weak normalization-aware inspection."
        }
        ControlFamily::HeaderTrustGap => {
            "Header mutations produced baseline-equivalent handling, indicating weak header-specific enforcement."
        }
        ControlFamily::MethodSemanticsGap => {
            "Method-level mutations did not change enforcement enough to demonstrate consistent coverage."
        }
        ControlFamily::PathHandlingGap => {
            "Path variants reached the same handling path without meaningful edge discrimination."
        }
        ControlFamily::BodyInspectionGap => {
            "Body-channel variants were treated too similarly to their controls, implying under-inspection."
        }
        _ => {
            "Paired-control coverage did not demonstrate strong discrimination for this request channel."
        }
    }
}

fn step_by_id(steps: &[Va2CampaignStep], id: u32) -> Option<&Va2CampaignStep> {
    steps.iter().find(|step| step.id == id)
}

fn evidence_request_from_va2_step(target_url: &str, step: &Va2CampaignStep) -> EvidenceRequest {
    let mut url = Url::parse(target_url).expect("target url should be valid");
    url.set_path(&step.path);
    url.set_query(step.query.as_deref());
    EvidenceRequest {
        method: step.method.clone(),
        url: url.to_string(),
        headers: step
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        body: step.body.clone(),
    }
}

fn map_effectiveness_category(category: &str) -> Option<ControlFamily> {
    match category.to_ascii_lowercase().as_str() {
        "sql injection" | "xss" | "command injection" | "template injection" | "ssrf" => {
            Some(ControlFamily::BodyInspectionGap)
        }
        "path traversal" => Some(ControlFamily::PathHandlingGap),
        "xxe" => Some(ControlFamily::ParserMismatch),
        "evasion" => Some(ControlFamily::NormalizationGap),
        _ => None,
    }
}

fn parse_effectiveness_severity(severity: &str) -> HardeningSeverity {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => HardeningSeverity::Critical,
        "high" => HardeningSeverity::High,
        "medium" => HardeningSeverity::Medium,
        "low" => HardeningSeverity::Low,
        _ => HardeningSeverity::Info,
    }
}

fn effectiveness_channel(control_family: ControlFamily) -> &'static str {
    match control_family {
        ControlFamily::PathHandlingGap => "path",
        ControlFamily::HeaderTrustGap => "header",
        ControlFamily::MethodSemanticsGap => "method",
        ControlFamily::RateLimitGap => "header",
        ControlFamily::StatefulnessGap => "header",
        _ => "body",
    }
}

fn reconstruct_effectiveness_requests(
    target_url: &str,
    description: &str,
    intensity_level: u8,
) -> Option<(EvidenceRequest, Option<EvidenceRequest>)> {
    let technique_name = description
        .split(": ")
        .last()
        .map(str::trim)
        .filter(|name| !name.is_empty())?;
    let all_techniques = all_effectiveness_techniques(intensity_level);
    let technique = all_techniques
        .iter()
        .find(|entry| entry.name == technique_name)?;

    if !matches!(
        technique.method.as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    ) {
        return None;
    }

    Some((
        EvidenceRequest {
            method: technique.method.clone(),
            url: target_url.to_string(),
            headers: technique
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            body: Some(technique.payload.clone()),
        },
        Some(EvidenceRequest {
            method: "GET".to_string(),
            url: target_url.to_string(),
            headers: Vec::new(),
            body: None,
        }),
    ))
}

fn all_effectiveness_techniques(intensity_level: u8) -> Vec<techniques::TestingTechnique> {
    let mut entries = techniques::get_techniques_for_level(intensity_level);
    entries.extend(techniques::get_evasion_techniques());
    entries
}

fn append_query(base_url: &str, key: &str, value: &str) -> String {
    let mut url = Url::parse(base_url).expect("base url should be valid");
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair(key, value);
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::virtual_adversary::{
        VaEvidence, VaEvidenceKind, VaPayloadCategory, VaResultRecord, VaResultSummary,
        VirtualAdversaryConfig,
    };
    use crate::virtual_adversary2::{
        PairedControlSummary, Va2BaselineSummary, Va2CampaignPlan, Va2ChallengeProfile,
        Va2ChannelCoverage, Va2DifferentialResult, Va2PmiScore, Va2RunReport, Va2RunResult,
        Va2StateSummary, Va2StepKind, Va2ThrottleCurve, Va2WbfSummary,
    };

    fn target() -> ResolvedTarget {
        ResolvedTarget {
            original_url: "https://example.com".to_string(),
            normalized_url: "https://example.com/".to_string(),
            host: "example.com".to_string(),
            port: 443,
            registered_target: crate::effectiveness::consent::ScopeTarget {
                host: "example.com".to_string(),
                class: crate::effectiveness::consent::TargetClass::Public,
            },
            active_target_profile: crate::active::ActiveTargetProfile::Public,
            resolved_ips: vec!["93.184.216.34".parse().unwrap()],
            pinned_ip: "93.184.216.34".parse().unwrap(),
        }
    }

    #[test]
    fn test_translate_va_maps_encoding_boundary_to_normalization_gap() {
        let report = VaRunReport {
            target_url: "https://example.com".to_string(),
            plan_size: 1,
            replay_plan: vec![VaReplayPlanItem {
                index: 1,
                class: "EncodingBoundary".to_string(),
                channel: "Query".to_string(),
                description: "probe".to_string(),
                method: "GET".to_string(),
                url: "https://example.com/?q=%252e%252e%252f".to_string(),
                headers: Vec::new(),
                body: None,
            }],
            summary: VaResultSummary::new(),
            enforcement: crate::virtual_adversary::VaEnforcement::NoEnforcement,
            evidence_score: 0.0,
            evidence_summary: Vec::new(),
            config: VirtualAdversaryConfig::default(),
            results: vec![VaResultRecord {
                payload: "probe".to_string(),
                category: VaPayloadCategory::EncodingBoundary,
                outcome: VaOutcome::Allowed,
                reason: "allowed".to_string(),
                evidence: vec![VaEvidence {
                    kind: VaEvidenceKind::StatusChange,
                    detail: "status_delta=0".to_string(),
                }],
            }],
            started_at: std::time::Instant::now(),
            finished_at: None,
            replay_bundle: None,
            audit: None,
        };

        let translated = translate_va(&target(), &report, None);
        assert_eq!(translated.findings.len(), 1);
        assert_eq!(
            translated.findings[0].control_family,
            ControlFamily::NormalizationGap
        );
    }

    #[test]
    fn test_translate_va2_blind_spot_becomes_coverage_finding() {
        let report = Va2RunReport {
            target_url: "https://example.com".to_string(),
            plan: Va2CampaignPlan {
                version: "1".to_string(),
                seed: 1,
                target_url: "https://example.com".to_string(),
                phases: Vec::new(),
                budget: 2,
                steps: vec![
                    Va2CampaignStep {
                        id: 1,
                        phase: crate::virtual_adversary2::Va2Phase::ProtocolVariance,
                        kind: Va2StepKind::Baseline,
                        method: "GET".to_string(),
                        path: "/".to_string(),
                        query: None,
                        headers: HashMap::new(),
                        body: None,
                        delay_ms: 0,
                        notes: "baseline".to_string(),
                        expected_equivalence: None,
                        channel: Some(Va2ProbeChannel::Query),
                    },
                    Va2CampaignStep {
                        id: 2,
                        phase: crate::virtual_adversary2::Va2Phase::ProtocolVariance,
                        kind: Va2StepKind::Equivalence,
                        method: "GET".to_string(),
                        path: "/".to_string(),
                        query: Some("q=%252e%252e%252f".to_string()),
                        headers: HashMap::new(),
                        body: None,
                        delay_ms: 0,
                        notes: "variant".to_string(),
                        expected_equivalence: Some(1),
                        channel: Some(Va2ProbeChannel::Query),
                    },
                ],
            },
            results: vec![Va2RunResult {
                step_id: 1,
                phase: crate::virtual_adversary2::Va2Phase::ProtocolVariance,
                kind: Va2StepKind::Baseline,
                status: Some(200),
                duration_ms: 10,
                error: None,
            }],
            baseline: Va2BaselineSummary::default(),
            normalization: None,
            statefulness: Some(Va2StateSummary::default()),
            challenge: Some(Va2ChallengeProfile::default()),
            throttle: Some(Va2ThrottleCurve::default()),
            wbf: Va2WbfSummary::default(),
            pmi: Va2PmiScore::default(),
            differential: vec![Va2DifferentialResult {
                step_id: 2,
                baseline_step_id: 1,
                status_delta: 0,
                body_length_pct_change: 0.01,
                header_mutation_count: 0,
                timing_delta_ms: 0,
                discriminated: false,
                outcome: Some(crate::virtual_adversary2::PairedControlOutcome::NotDetected),
                channel: Some(Va2ProbeChannel::Query),
                ..Default::default()
            }],
            channel_coverage: Some(Va2ChannelCoverage {
                channels: HashMap::from([(Va2ProbeChannel::Query, 0.0)]),
                blind_spots: vec![Va2ProbeChannel::Query],
                coverage_score: 0.0,
            }),
            paired_control: Some(PairedControlSummary::default()),
            audit: None,
        };

        let translated = translate_va2(&target(), &report, None);
        assert_eq!(translated.findings.len(), 1);
        assert_eq!(
            translated.findings[0].control_family,
            ControlFamily::NormalizationGap
        );
    }

    #[test]
    fn test_translate_surface_assessment_emits_surface_unsuitable_finding() {
        let assessment = SurfaceAssessment {
            suitable: false,
            confidence: 0.42,
            reason: "Target appears static".to_string(),
            indicators: vec!["Static content type text/html".to_string()],
            suggestions: vec!["/api/search: dynamic endpoint".to_string()],
        };

        let translated = translate_surface_assessment(&target(), &assessment, None);
        assert_eq!(translated.findings.len(), 1);
        assert_eq!(
            translated.findings[0].control_family,
            ControlFamily::SurfaceUnsuitable
        );
        assert_eq!(translated.findings[0].severity, HardeningSeverity::Info);
    }

    #[test]
    fn test_route_context_is_attached_to_findings() {
        let assessment = SurfaceAssessment {
            suitable: false,
            confidence: 0.4,
            reason: "Target appears static".to_string(),
            indicators: Vec::new(),
            suggestions: Vec::new(),
        };
        let context = RouteFindingContext {
            endpoint_id: "ep-1".to_string(),
            path_template: "/api/tokenize".to_string(),
            auth_class: AuthClass::Required,
            discovery_sources: vec![DiscoverySource::OpenApi],
        };

        let translated = translate_surface_assessment(&target(), &assessment, Some(&context));
        assert_eq!(translated.findings[0].endpoint_id.as_deref(), Some("ep-1"));
        assert_eq!(
            translated.findings[0].path_template.as_deref(),
            Some("/api/tokenize")
        );
        assert_eq!(translated.findings[0].auth_class, Some(AuthClass::Required));
    }
}
