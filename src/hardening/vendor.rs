use crate::hardening::finding::{ControlFamily, HardeningFinding, VendorMode};
use crate::DetectionResult;

pub fn resolve_vendor_mode(requested: VendorMode, detection: &DetectionResult) -> VendorMode {
    if requested != VendorMode::Auto {
        return requested;
    }

    let detected_name = detection
        .detected_waf
        .as_ref()
        .map(|provider| provider.name.to_ascii_lowercase())
        .unwrap_or_default();

    if detected_name.contains("cloudflare") {
        VendorMode::Cloudflare
    } else if detected_name.contains("aws")
        || detected_name.contains("amazon")
        || detected_name.contains("cloudfront")
    {
        VendorMode::Aws
    } else {
        VendorMode::Auto
    }
}

pub fn apply_vendor_guidance(findings: &mut [HardeningFinding], vendor_mode: VendorMode) {
    for finding in findings {
        let mut guidance = generic_guidance(finding.control_family);
        guidance.extend(vendor_specific_guidance(
            vendor_mode,
            finding.control_family,
        ));
        finding.fix_guidance = guidance.clone();
        finding.vendor_guidance = vendor_specific_guidance(vendor_mode, finding.control_family);
    }
}

fn generic_guidance(control_family: ControlFamily) -> Vec<String> {
    match control_family {
        ControlFamily::NormalizationGap => vec![
            "Inspect both raw and normalized inputs before rule evaluation.".to_string(),
            "Align URL decoding, Unicode normalization, and double-decoding policy between edge transforms and WAF rules.".to_string(),
            "Add regression coverage for the exact encoded variant that bypassed inspection.".to_string(),
        ],
        ControlFamily::ParserMismatch => vec![
            "Normalize duplicate parameters and conflicting headers before inspection.".to_string(),
            "Apply the same parser behavior at the WAF and origin layers for multipart, XML, and header edge cases.".to_string(),
            "Block or challenge ambiguous requests instead of forwarding them unchanged.".to_string(),
        ],
        ControlFamily::HeaderTrustGap => vec![
            "Restrict trust in forwarding and override headers to known proxy hops only.".to_string(),
            "Inspect mutated or repeated headers after canonicalization, not just the first observed value.".to_string(),
            "Add explicit policies for suspicious user-agent, host, and hop-by-hop header variants.".to_string(),
        ],
        ControlFamily::MethodSemanticsGap => vec![
            "Inspect method override semantics and non-standard verbs with the same rule coverage as GET and POST.".to_string(),
            "Ensure method-based allowlists do not skip body and header inspection.".to_string(),
            "Challenge or block semantic method drift that changes request handling downstream.".to_string(),
        ],
        ControlFamily::PathHandlingGap => vec![
            "Canonicalize path traversal, dot-segment, and encoded slash variants before rule execution.".to_string(),
            "Inspect both the inbound path and the post-normalization path seen by the origin.".to_string(),
            "Add explicit traversal and routing drift rules for the reproduced path variant.".to_string(),
        ],
        ControlFamily::BodyInspectionGap => vec![
            "Expand request body inspection scope to cover the content type and payload shape that bypassed enforcement.".to_string(),
            "Apply the same signatures and transformations to query, body, and JSON/XML fields where the application accepts user input.".to_string(),
            "Prefer positive validation on high-risk parameters instead of signature-only blocking.".to_string(),
        ],
        ControlFamily::ChallengeEscalationGap => vec![
            "Escalate proven malicious requests from soft challenge to hard block where business risk allows.".to_string(),
            "Tune bot/challenge thresholds so repeated attacker signals cannot coast through with only lightweight friction.".to_string(),
            "Regression-test the exact probe to require a challenge or block instead of a normal response.".to_string(),
        ],
        ControlFamily::RateLimitGap => vec![
            "Attach rate limiting to the offending route, IP reputation, and header fingerprint used in the reproduced probe.".to_string(),
            "Make throttle rules stateful across equivalent request variants, not just identical requests.".to_string(),
            "Gate burst behavior with challenge or temporary block once the reproduced threshold is reached.".to_string(),
        ],
        ControlFamily::StatefulnessGap => vec![
            "Carry challenge and bot state across the full request journey rather than evaluating each probe in isolation.".to_string(),
            "Bind suspicious sessions to cookie or token state so equivalent follow-up requests cannot reset reputation.".to_string(),
            "Regression-test state transitions, not just single requests, after policy changes.".to_string(),
        ],
        ControlFamily::SurfaceUnsuitable => vec![
            "Move testing to an endpoint that actually parses user-controlled input at the edge or origin.".to_string(),
            "Prefer authenticated API routes, form handlers, search endpoints, or upload paths over static landing pages.".to_string(),
        ],
    }
}

fn vendor_specific_guidance(vendor_mode: VendorMode, control_family: ControlFamily) -> Vec<String> {
    match vendor_mode {
        VendorMode::Cloudflare => match control_family {
            ControlFamily::NormalizationGap => vec![
                "Cloudflare: align Transform Rules and custom WAF rules so decoding and normalization happen before managed/custom inspection.".to_string(),
                "Cloudflare: add custom expressions for the encoded variant instead of relying only on managed signatures.".to_string(),
            ],
            ControlFamily::ParserMismatch => vec![
                "Cloudflare: add custom rules for duplicated or conflicting headers/parameters that the origin parser treats differently.".to_string(),
            ],
            ControlFamily::HeaderTrustGap => vec![
                "Cloudflare: lock down trusted proxy headers and create custom rules for `x-forwarded-*`, host, and hop-by-hop header abuse.".to_string(),
            ],
            ControlFamily::MethodSemanticsGap => vec![
                "Cloudflare: scope custom rules to method overrides and non-standard verbs; do not exempt them from managed rules.".to_string(),
            ],
            ControlFamily::PathHandlingGap => vec![
                "Cloudflare: add path normalization and traversal expressions in custom rules before origin routing decisions.".to_string(),
            ],
            ControlFamily::BodyInspectionGap => vec![
                "Cloudflare: confirm request body inspection is enabled for the route and content type; supplement with custom WAF expressions for the reproduced parameter.".to_string(),
            ],
            ControlFamily::ChallengeEscalationGap => vec![
                "Cloudflare: raise Bot Management or custom rule actions from managed challenge to block for this reproduced payload family.".to_string(),
            ],
            ControlFamily::RateLimitGap => vec![
                "Cloudflare: tighten Rate Limiting Rules with the same URI, header, and method attributes used in the bypass.".to_string(),
            ],
            ControlFamily::StatefulnessGap => vec![
                "Cloudflare: ensure bot/challenge state is reused across equivalent requests instead of evaluating each path variant independently.".to_string(),
            ],
            ControlFamily::SurfaceUnsuitable => Vec::new(),
        },
        VendorMode::Aws => match control_family {
            ControlFamily::NormalizationGap => vec![
                "AWS WAF: add the required text transformations in the rule statement so encoded variants are normalized before evaluation.".to_string(),
                "AWS WAF: verify the scope-down statement does not exclude the reproduced encoded request shape.".to_string(),
            ],
            ControlFamily::ParserMismatch => vec![
                "AWS WAF: use labels and custom rules to block duplicated headers or ambiguous parameter structures before they reach the origin.".to_string(),
            ],
            ControlFamily::HeaderTrustGap => vec![
                "AWS WAF: inspect the forwarded headers actually trusted by the application and scope custom rules to those fields.".to_string(),
            ],
            ControlFamily::MethodSemanticsGap => vec![
                "AWS WAF: add method conditions and labels so override headers and unusual verbs do not bypass body inspection.".to_string(),
            ],
            ControlFamily::PathHandlingGap => vec![
                "AWS WAF: normalize path traversal variants with text transformations and route-specific statements before allow logic.".to_string(),
            ],
            ControlFamily::BodyInspectionGap => vec![
                "AWS WAF: confirm body inspection size limits and field scope cover the reproduced payload, then add targeted custom statements or rule-group tuning.".to_string(),
            ],
            ControlFamily::ChallengeEscalationGap => vec![
                "AWS WAF: replace count/challenge behavior with block or label-driven escalation for this reproduced malicious class.".to_string(),
            ],
            ControlFamily::RateLimitGap => vec![
                "AWS WAF: attach rate-based rules and labels to the exact URI/method/header combination used in the reproduced burst.".to_string(),
            ],
            ControlFamily::StatefulnessGap => vec![
                "AWS WAF: carry labels across related rules so equivalent requests inherit prior suspicion instead of resetting evaluation.".to_string(),
            ],
            ControlFamily::SurfaceUnsuitable => Vec::new(),
        },
        VendorMode::Auto => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DetectionMetadata, DetectionResult, ProviderDetection};
    use chrono::Utc;
    use std::collections::HashMap;

    fn detection(name: &str) -> DetectionResult {
        DetectionResult {
            url: "https://example.com".to_string(),
            detected_waf: Some(ProviderDetection {
                name: name.to_string(),
                confidence: 0.95,
            }),
            detected_cdn: None,
            provider_scores: HashMap::new(),
            evidence_map: HashMap::new(),
            evidence: Vec::new(),
            detection_time_ms: 10,
            metadata: DetectionMetadata {
                timestamp: Utc::now(),
                version: "test".to_string(),
                user_agent: "ua".to_string(),
            },
            caveats: Vec::new(),
            security_posture: None,
            error: None,
        }
    }

    #[test]
    fn test_vendor_mode_resolves_cloudflare_from_detection() {
        assert_eq!(
            resolve_vendor_mode(VendorMode::Auto, &detection("Cloudflare")),
            VendorMode::Cloudflare
        );
    }

    #[test]
    fn test_vendor_guidance_falls_back_to_generic_for_unknown_vendor() {
        let mut findings = vec![HardeningFinding {
            id: "f1".to_string(),
            title: "title".to_string(),
            severity: crate::hardening::finding::HardeningSeverity::High,
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
            endpoint_id: None,
            path_template: None,
            auth_class: None,
            discovery_sources: Vec::new(),
            regression_assertion: None,
            evidence_refs: Vec::new(),
        }];

        apply_vendor_guidance(&mut findings, VendorMode::Auto);
        assert!(findings[0].fix_guidance.len() >= 2);
        assert!(findings[0].vendor_guidance.is_empty());
    }
}
