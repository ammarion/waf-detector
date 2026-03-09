use crate::effectiveness::report::EffectivenessReport;
use crate::hardening::HardeningReport;
use crate::origin_probe::OriginProbeReport;
use crate::posture::PostureReport;
use crate::virtual_adversary::VaRunReport;
use crate::virtual_adversary2::Va2RunReport;
use crate::DetectionResult;
use anyhow::{Context, Result};
use serde_json::Value;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReportKind {
    Hardening,
    Posture,
    Effectiveness,
    Enforcement,
    Behavioral,
    Detection,
    OriginProbe,
    Unknown,
}

#[derive(Debug, Clone)]
struct MetricCard {
    label: String,
    value: String,
    tone: &'static str,
}

#[derive(Debug, Clone)]
struct Callout {
    tone: &'static str,
    title: String,
    body: String,
}

#[derive(Debug, Clone)]
struct FindingCard {
    severity: String,
    title: String,
    detail: String,
    recommendation: Option<String>,
}

#[derive(Debug, Clone)]
struct FindingGroup {
    title: String,
    intro: Option<String>,
    findings: Vec<FindingCard>,
}

#[derive(Debug, Clone)]
struct Section {
    title: String,
    intro: Option<String>,
    rows: Vec<(String, String)>,
    bullets: Vec<String>,
}

#[derive(Debug, Clone)]
struct AssessmentVerdict {
    verdict: &'static str,
    tone: &'static str,
    description: String,
    proven: String,
}

#[derive(Debug, Clone)]
struct EffectivenessAssessment {
    verdict: AssessmentVerdict,
    baseline_all_degraded: bool,
    degraded_count: usize,
    is_static_target: bool,
    static_confidence: Option<f64>,
    primary_dynamic_endpoint: Option<String>,
}

#[derive(Debug, Clone)]
struct TableSection {
    title: String,
    intro: Option<String>,
    columns: Vec<String>,
    rows: Vec<Vec<String>>,
    /// Index of the outcome column for badge rendering (None = no badge column).
    outcome_column: Option<usize>,
    /// Whether to render filter buttons above this table.
    filterable: bool,
}

#[derive(Debug, Clone)]
struct ReportView {
    kind: ReportKind,
    kind_label: String,
    title: String,
    subtitle: String,
    summary_cards: Vec<MetricCard>,
    callouts: Vec<Callout>,
    findings: Vec<FindingCard>,
    finding_groups: Vec<FindingGroup>,
    sections: Vec<Section>,
    tables: Vec<TableSection>,
    /// Only set for effectiveness reports.
    assessment_verdict: Option<AssessmentVerdict>,
}

pub fn render_report_file(input: &Path, output: Option<&Path>) -> Result<PathBuf> {
    let raw = fs::read_to_string(input)
        .with_context(|| format!("failed to read report input {}", input.display()))?;
    let html = render_report_html(&raw, input)?;
    let output_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| default_output_path(input));
    fs::write(&output_path, html)
        .with_context(|| format!("failed to write HTML report to {}", output_path.display()))?;
    Ok(output_path)
}

fn default_output_path(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("waf-report");
    input.with_file_name(format!("{stem}.html"))
}

fn render_report_html(raw_json: &str, input_path: &Path) -> Result<String> {
    let value: Value = serde_json::from_str(raw_json)
        .with_context(|| format!("{} is not valid JSON", input_path.display()))?;
    let pretty_json = serde_json::to_string_pretty(&value)?;
    let view = build_report_view(&value)?;
    Ok(render_html_document(&view, &pretty_json, input_path))
}

fn build_report_view(value: &Value) -> Result<ReportView> {
    if looks_like_hardening(value) {
        let report: HardeningReport =
            serde_json::from_value(value.clone()).context("failed to parse hardening report")?;
        return Ok(build_hardening_view(&report));
    }
    if looks_like_posture(value) {
        let report: PostureReport =
            serde_json::from_value(value.clone()).context("failed to parse posture report")?;
        return Ok(build_posture_view(&report));
    }
    if looks_like_effectiveness(value) {
        let report: EffectivenessReport = serde_json::from_value(value.clone())
            .context("failed to parse effectiveness report")?;
        return Ok(build_effectiveness_view(&report));
    }
    if looks_like_va2(value) {
        let report: Va2RunReport =
            serde_json::from_value(value.clone()).context("failed to parse VA2 report")?;
        return Ok(build_va2_view(&report));
    }
    if looks_like_va(value) {
        let report: VaRunReport =
            serde_json::from_value(value.clone()).context("failed to parse VA report")?;
        return Ok(build_va_view(&report));
    }
    if looks_like_detection(value) {
        let report: DetectionResult =
            serde_json::from_value(value.clone()).context("failed to parse detection result")?;
        return Ok(build_detection_view(&report));
    }
    if looks_like_origin_probe(value) {
        let report: OriginProbeReport =
            serde_json::from_value(value.clone()).context("failed to parse origin probe report")?;
        return Ok(build_origin_probe_view(&report));
    }

    Ok(build_unknown_view(value))
}

fn looks_like_hardening(value: &Value) -> bool {
    has_keys(
        value,
        &[
            "target",
            "provider_detection",
            "surface_assessment",
            "coverage",
            "summary",
        ],
    )
}

fn looks_like_posture(value: &Value) -> bool {
    has_keys(value, &["target_url", "grade", "risk_score", "summary"])
        && value.get("detection").is_some()
}

fn looks_like_effectiveness(value: &Value) -> bool {
    has_keys(value, &["target_url", "risk_score", "phases", "statistics"])
}

fn looks_like_va(value: &Value) -> bool {
    has_keys(
        value,
        &[
            "target_url",
            "plan_size",
            "summary",
            "enforcement",
            "evidence_score",
        ],
    )
}

fn looks_like_va2(value: &Value) -> bool {
    has_keys(value, &["target_url", "plan", "baseline", "wbf", "pmi"])
}

fn looks_like_detection(value: &Value) -> bool {
    has_keys(
        value,
        &["url", "provider_scores", "evidence_map", "metadata"],
    )
}

fn looks_like_origin_probe(value: &Value) -> bool {
    has_keys(
        value,
        &[
            "target_url",
            "target_host",
            "origin_ip",
            "findings",
            "bypass_confirmed",
        ],
    )
}

fn has_keys(value: &Value, keys: &[&str]) -> bool {
    keys.iter().all(|key| value.get(*key).is_some())
}

fn build_hardening_view(report: &HardeningReport) -> ReportView {
    let highest = report
        .summary
        .highest_severity
        .map(|severity| severity.as_str().to_uppercase())
        .unwrap_or_else(|| "NONE".to_string());
    let provider = report
        .summary
        .provider
        .clone()
        .or_else(|| report.provider_detection.detected_waf.clone())
        .unwrap_or_else(|| "Unknown".to_string());
    let mut sections = Vec::new();
    sections.push(Section {
        title: "Coverage".to_string(),
        intro: Some("What the full hardening pass covered during this scan.".to_string()),
        rows: vec![
            (
                "Sources run".to_string(),
                join_or_dash(report.coverage.sources_run.clone()),
            ),
            (
                "Evidence records".to_string(),
                report.coverage.evidence_count.to_string(),
            ),
            (
                "Coverage score".to_string(),
                format_optional_score(report.coverage.coverage_score),
            ),
        ],
        bullets: map_counts(&report.coverage.findings_by_family),
    });
    sections.push(Section {
        title: "Surface Assessment".to_string(),
        intro: Some(report.surface_assessment.reason.clone()),
        rows: vec![
            (
                "Suitable".to_string(),
                yes_no(report.surface_assessment.suitable).to_string(),
            ),
            (
                "Confidence".to_string(),
                format!("{:.0}%", report.surface_assessment.confidence * 100.0),
            ),
        ],
        bullets: report
            .surface_assessment
            .indicators
            .iter()
            .chain(report.surface_assessment.suggestions.iter())
            .cloned()
            .collect(),
    });
    if !report.summary.notes.is_empty() {
        sections.push(Section {
            title: "Operator Notes".to_string(),
            intro: None,
            rows: Vec::new(),
            bullets: report.summary.notes.clone(),
        });
    }
    let tables = vec![
        TableSection {
            title: "Finding Inventory".to_string(),
            intro: Some(
                "Every hardening finding with the fields operators need for configuration and code changes."
                    .to_string(),
            ),
            columns: vec![
                "Severity".to_string(),
                "Title".to_string(),
                "Family".to_string(),
                "Vector".to_string(),
                "Endpoint".to_string(),
                "Path".to_string(),
                "Confidence".to_string(),
                "Root Cause".to_string(),
                "First Fix".to_string(),
                "Vendor Guidance".to_string(),
            ],
            rows: report
                .findings
                .iter()
                .map(|finding| {
                    vec![
                        finding.severity.as_str().to_uppercase(),
                        finding.title.clone(),
                        finding.control_family.as_str().to_string(),
                        finding.vector.clone(),
                        finding.endpoint_id.clone().unwrap_or_else(|| "—".to_string()),
                        finding.path_template.clone().unwrap_or_else(|| "—".to_string()),
                        format!("{:.0}%", finding.confidence * 100.0),
                        sanitize_cell(finding.likely_root_cause.clone()),
                        sanitize_cell(
                            finding
                                .fix_guidance
                                .first()
                                .cloned()
                                .unwrap_or_else(|| "—".to_string()),
                        ),
                        sanitize_cell(
                            finding
                                .vendor_guidance
                                .first()
                                .cloned()
                                .unwrap_or_else(|| "—".to_string()),
                        ),
                    ]
                })
                .collect(),
            outcome_column: None,
            filterable: false,
        },
        TableSection {
            title: "Evidence Inventory".to_string(),
            intro: Some(
                "Observed requests and response comparisons that back the hardening findings."
                    .to_string(),
            ),
            columns: vec![
                "ID".to_string(),
                "Source".to_string(),
                "Action".to_string(),
                "Summary".to_string(),
                "Requests".to_string(),
                "Comparison".to_string(),
            ],
            rows: report
                .evidence_inventory
                .iter()
                .map(|record| {
                    vec![
                        record.id.clone(),
                        format!("{:?}", record.source),
                        format!("{:?}", record.observed_action),
                        sanitize_cell(record.summary.clone()),
                        format_request_summary(
                            record.request.as_ref(),
                            record.baseline_request.as_ref(),
                        ),
                        sanitize_cell(
                            record
                                .response_comparison
                                .as_ref()
                                .map(|cmp| cmp.summary.join(" | "))
                                .unwrap_or_else(|| "—".to_string()),
                        ),
                    ]
                })
                .collect(),
            outcome_column: None,
            filterable: false,
        },
    ];

    ReportView {
        kind: ReportKind::Hardening,
        kind_label: "Hardening Report".to_string(),
        title: report.target.clone(),
        subtitle: format!("Full public-surface hardening assessment for {provider}"),
        summary_cards: vec![
            MetricCard {
                label: "Provider".to_string(),
                value: provider,
                tone: "info",
            },
            MetricCard {
                label: "Total Findings".to_string(),
                value: report.summary.total_findings.to_string(),
                tone: "warn",
            },
            MetricCard {
                label: "Actionable".to_string(),
                value: report.summary.actionable_findings.to_string(),
                tone: "bad",
            },
            MetricCard {
                label: "Highest Severity".to_string(),
                value: highest,
                tone: severity_tone(report.summary.highest_severity.map(|s| s.as_str())),
            },
        ],
        callouts: vec![Callout {
            tone: if report.summary.ci_gate_triggered {
                "bad"
            } else {
                "good"
            },
            title: format!("CI gate: {}", report.summary.ci_gate.as_str()),
            body: if report.summary.ci_gate_triggered {
                "The hardening gate was triggered by one or more findings.".to_string()
            } else {
                "No hardening gate was triggered by this report.".to_string()
            },
        }],
        findings: report
            .findings
            .iter()
            .take(12)
            .map(|finding| FindingCard {
                severity: finding.severity.as_str().to_uppercase(),
                title: finding.title.clone(),
                detail: format!(
                    "{} | vector={} | confidence {:.0}%",
                    finding.control_family.as_str(),
                    finding.vector,
                    finding.confidence * 100.0
                ),
                recommendation: finding.fix_guidance.first().cloned(),
            })
            .collect(),
        finding_groups: Vec::new(),
        sections,
        tables,
        assessment_verdict: None,
    }
}

fn build_posture_view(report: &PostureReport) -> ReportView {
    let mut sections = Vec::new();
    if let Some(detection) = &report.detection {
        sections.push(Section {
            title: "Detection".to_string(),
            intro: None,
            rows: vec![
                (
                    "WAF".to_string(),
                    detection
                        .waf_name
                        .clone()
                        .unwrap_or_else(|| "Not detected".to_string()),
                ),
                (
                    "WAF confidence".to_string(),
                    format!("{:.0}%", detection.waf_confidence * 100.0),
                ),
                (
                    "CDN".to_string(),
                    detection
                        .cdn_name
                        .clone()
                        .unwrap_or_else(|| "Not detected".to_string()),
                ),
            ],
            bullets: Vec::new(),
        });
    }
    if let Some(behavioral) = &report.behavioral {
        sections.push(Section {
            title: "Behavioral Signals".to_string(),
            intro: Some(format!("PMI label: {}", behavioral.pmi_label)),
            rows: vec![
                ("PMI".to_string(), format!("{:.1}", behavioral.pmi_score)),
                (
                    "Differential score".to_string(),
                    format!("{:.0}%", behavioral.differential_score * 100.0),
                ),
                (
                    "Challenge score".to_string(),
                    format!("{:.0}%", behavioral.challenge_score * 100.0),
                ),
                (
                    "Channel coverage".to_string(),
                    format!("{:.0}%", behavioral.channel_coverage_score * 100.0),
                ),
            ],
            bullets: if behavioral.blind_spot_count > 0 {
                vec![format!(
                    "Blind spots detected: {}",
                    behavioral.blind_spot_count
                )]
            } else {
                Vec::new()
            },
        });
    }
    if let Some(enforcement) = &report.enforcement {
        sections.push(Section {
            title: "Enforcement".to_string(),
            intro: Some(enforcement.enforcement.clone()),
            rows: vec![
                (
                    "Confidence".to_string(),
                    format!("{:.0}%", enforcement.confidence_score * 100.0),
                ),
                ("Risk label".to_string(), enforcement.risk_label.clone()),
                (
                    "Blocked ratio".to_string(),
                    format!("{:.0}%", enforcement.blocked_ratio * 100.0),
                ),
            ],
            bullets: Vec::new(),
        });
    }

    ReportView {
        kind: ReportKind::Posture,
        kind_label: "Posture Report".to_string(),
        title: report.target_url.clone(),
        subtitle: "Unified grade across detection, enforcement, and behavioral analysis"
            .to_string(),
        summary_cards: vec![
            MetricCard {
                label: "Grade".to_string(),
                value: report.grade.to_string(),
                tone: grade_tone(report.grade.to_string().as_str()),
            },
            MetricCard {
                label: "Risk Score".to_string(),
                value: format!("{:.1}/100", report.risk_score),
                tone: risk_tone(report.risk_score),
            },
            MetricCard {
                label: "Behavior".to_string(),
                value: report
                    .behavioral
                    .as_ref()
                    .map(|value| value.pmi_label.clone())
                    .unwrap_or_else(|| "N/A".to_string()),
                tone: "info",
            },
            MetricCard {
                label: "Enforcement".to_string(),
                value: report
                    .enforcement
                    .as_ref()
                    .map(|value| value.enforcement.clone())
                    .unwrap_or_else(|| "N/A".to_string()),
                tone: "warn",
            },
        ],
        callouts: vec![Callout {
            tone: risk_tone(report.risk_score),
            title: "Posture Summary".to_string(),
            body: report.summary.clone(),
        }, Callout {
            tone: "info",
            title: "Scope of this artifact".to_string(),
            body: "Posture reports are summaries. They do not carry probe-by-probe payload inventories. Render a hardening, effectiveness, enforcement, or behavioral JSON artifact for full operational detail.".to_string(),
        }],
        findings: Vec::new(),
        finding_groups: Vec::new(),
        sections,
        tables: Vec::new(),
        assessment_verdict: None,
    }
}

fn build_effectiveness_view(report: &EffectivenessReport) -> ReportView {
    let actionable_tests = report.actionable_test_count();
    let degraded_tests = report.degraded_test_count();
    let assessment = build_effectiveness_assessment(report);
    let mut sections = Vec::new();
    sections.push(Section {
        title: "Assessment Quality".to_string(),
        intro: Some(
            "How much of this scan produced trustworthy application-facing signals versus edge or transport failures."
                .to_string(),
        ),
        rows: vec![
            (
                "Actionable tests".to_string(),
                actionable_tests.to_string(),
            ),
            (
                "Degraded responses".to_string(),
                degraded_tests.to_string(),
            ),
            (
                "Static-root hint".to_string(),
                yes_no(report.has_static_target_hint()).to_string(),
            ),
            (
                "Baseline healthy".to_string(),
                yes_no(!report.baseline_all_degraded()).to_string(),
            ),
        ],
        bullets: Vec::new(),
    });
    if let Some(analysis) = &report.static_page_analysis {
        sections.push(Section {
            title: "Target Suitability".to_string(),
            intro: Some(
                "Static-page analysis captured before active testing so operators can tell whether the chosen endpoint is a good proxy for real protection behavior."
                    .to_string(),
            ),
            rows: vec![
                (
                    "Likely static".to_string(),
                    yes_no(analysis.is_likely_static).to_string(),
                ),
                (
                    "Confidence".to_string(),
                    format!("{:.0}%", analysis.confidence * 100.0),
                ),
            ],
            bullets: analysis
                .indicators
                .iter()
                .map(render_static_indicator)
                .chain(
                    analysis
                        .suggestions
                        .iter()
                        .map(|suggestion| format!(
                            "Suggested endpoint: {} ({}) — {}",
                            suggestion.endpoint, suggestion.description, suggestion.rationale
                        )),
                )
                .collect(),
        });
    }
    sections.push(Section {
        title: "Statistics".to_string(),
        intro: None,
        rows: vec![
            (
                "Total tests".to_string(),
                report.statistics.total_tests.to_string(),
            ),
            ("Actionable tests".to_string(), actionable_tests.to_string()),
            (
                "Blocked".to_string(),
                report.statistics.blocked_requests.to_string(),
            ),
            (
                "Allowed".to_string(),
                report.statistics.allowed_requests.to_string(),
            ),
            (
                "False positive rate".to_string(),
                format!("{:.1}%", report.statistics.false_positive_rate * 100.0),
            ),
        ],
        bullets: report
            .phases
            .iter()
            .map(|phase| phase.name.clone())
            .collect(),
    });
    if let Some(parser) = &report.parser_discrepancy {
        sections.push(Section {
            title: "Parser Discrepancy".to_string(),
            intro: Some(
                "Curated candidate bypass testing based on parsing discrepancies.".to_string(),
            ),
            rows: vec![
                (
                    "Executed pairs".to_string(),
                    parser.executed_pairs.to_string(),
                ),
                (
                    "Candidate bypasses".to_string(),
                    parser.candidate_bypasses.to_string(),
                ),
                (
                    "Unique bypasses".to_string(),
                    parser.unique_bypasses.to_string(),
                ),
            ],
            bullets: parser
                .by_content_type
                .iter()
                .map(|(key, value)| format!("{key}: {value}"))
                .collect(),
        });
    }
    if !report.recommendations.is_empty() {
        sections.push(Section {
            title: "Recommendations".to_string(),
            intro: None,
            rows: Vec::new(),
            bullets: report
                .recommendations
                .iter()
                .map(|rec| format!("{}: {}", rec.category, rec.description))
                .collect(),
        });
    }
    let mut test_rows = report
        .test_results
        .iter()
        .map(|(name, result)| {
            vec![
                name.clone(),
                effectiveness_outcome_label(result).to_string(),
                result.status_code.to_string(),
                result.response_time.as_millis().to_string(),
                result.response_body_length.to_string(),
                sanitize_cell(result.evidence.clone()),
                sanitize_cell(result.response_body_sample.clone()),
                sanitize_cell(format_hash_headers(&result.response_headers)),
            ]
        })
        .collect::<Vec<_>>();
    test_rows.sort_by(|a, b| a[0].cmp(&b[0]));
    let mut baseline_rows = report
        .baseline_results
        .iter()
        .map(|(name, result)| {
            vec![
                name.clone(),
                effectiveness_outcome_label(result).to_string(),
                result.status_code.to_string(),
                result.response_time.as_millis().to_string(),
                result.response_body_length.to_string(),
                sanitize_cell(result.evidence.clone()),
                sanitize_cell(result.response_body_sample.clone()),
            ]
        })
        .collect::<Vec<_>>();
    baseline_rows.sort_by(|a, b| a[0].cmp(&b[0]));
    let mut tables = vec![
        TableSection {
            title: "Probe Results".to_string(),
            intro: Some(
                "Every effectiveness probe that was executed against the target.".to_string(),
            ),
            columns: vec![
                "Probe".to_string(),
                "Outcome".to_string(),
                "Status".to_string(),
                "Latency ms".to_string(),
                "Body bytes".to_string(),
                "Evidence".to_string(),
                "Body sample".to_string(),
                "Headers".to_string(),
            ],
            rows: test_rows,
            outcome_column: Some(1),
            filterable: true,
        },
        TableSection {
            title: "Baseline Responses".to_string(),
            intro: Some(
                "Baseline requests used to compare attack behavior against the target.".to_string(),
            ),
            columns: vec![
                "Baseline".to_string(),
                "Outcome".to_string(),
                "Status".to_string(),
                "Latency ms".to_string(),
                "Body bytes".to_string(),
                "Evidence".to_string(),
                "Body sample".to_string(),
            ],
            rows: baseline_rows,
            outcome_column: None,
            filterable: false,
        },
        TableSection {
            title: "Vulnerability Detail".to_string(),
            intro: Some(
                "Each flagged weakness and the concrete remediation string attached to it."
                    .to_string(),
            ),
            columns: vec![
                "Severity".to_string(),
                "Category".to_string(),
                "Description".to_string(),
                "Evidence".to_string(),
                "Remediation".to_string(),
            ],
            rows: report
                .vulnerabilities
                .iter()
                .map(|finding| {
                    vec![
                        finding.severity.clone(),
                        finding.category.clone(),
                        sanitize_cell(finding.description.clone()),
                        sanitize_cell(finding.evidence.clone()),
                        sanitize_cell(finding.remediation.clone()),
                    ]
                })
                .collect(),
            outcome_column: None,
            filterable: false,
        },
        TableSection {
            title: "Recommendation Detail".to_string(),
            intro: Some(
                "Priority-ordered changes that can be made to code, policy, or WAF configuration."
                    .to_string(),
            ),
            columns: vec![
                "Priority".to_string(),
                "Category".to_string(),
                "Description".to_string(),
                "Implementation".to_string(),
            ],
            rows: report
                .recommendations
                .iter()
                .map(|rec| {
                    vec![
                        rec.priority.clone(),
                        rec.category.clone(),
                        sanitize_cell(rec.description.clone()),
                        sanitize_cell(rec.implementation.clone()),
                    ]
                })
                .collect(),
            outcome_column: None,
            filterable: false,
        },
    ];
    if let Some(parser) = &report.parser_discrepancy {
        tables.push(TableSection {
            title: "Parser Discrepancy Candidates".to_string(),
            intro: Some(
                "Control/variant pairs for candidate parsing-discrepancy bypasses.".to_string(),
            ),
            columns: vec![
                "Content-Type".to_string(),
                "Class".to_string(),
                "Severity".to_string(),
                "Confidence".to_string(),
                "Suppressed".to_string(),
                "Evidence".to_string(),
                "Control".to_string(),
                "Variant".to_string(),
            ],
            rows: parser
                .findings
                .iter()
                .map(|finding| {
                    vec![
                        finding.content_type.clone(),
                        finding.canonical_class.clone(),
                        finding.severity.clone(),
                        format!("{:.0}%", finding.confidence * 100.0),
                        finding.suppressed_variants.to_string(),
                        sanitize_cell(finding.evidence.clone()),
                        sanitize_cell(format!(
                            "{} {} | body={}",
                            finding.control_replay.method,
                            finding.control_replay.url,
                            finding.control_replay.body
                        )),
                        sanitize_cell(format!(
                            "{} {} | body={}",
                            finding.variant_replay.method,
                            finding.variant_replay.url,
                            finding.variant_replay.body
                        )),
                    ]
                })
                .collect(),
            outcome_column: None,
            filterable: false,
        });
    }

    ReportView {
        kind: ReportKind::Effectiveness,
        kind_label: "Effectiveness Report".to_string(),
        title: report.target_url.clone(),
        subtitle: "Payload blocking, parser-discrepancy checks, and remediation guidance"
            .to_string(),
        summary_cards: vec![
            MetricCard {
                label: "Risk Score".to_string(),
                value: format!("{:.1}/100", report.risk_score),
                tone: risk_tone(report.risk_score),
            },
            MetricCard {
                label: "Blocked".to_string(),
                value: report.statistics.blocked_requests.to_string(),
                tone: "good",
            },
            MetricCard {
                label: "Potential Misses".to_string(),
                value: report.statistics.allowed_requests.to_string(),
                tone: "bad",
            },
            MetricCard {
                label: "Degraded".to_string(),
                value: degraded_tests.to_string(),
                tone: "warn",
            },
        ],
        callouts: effectiveness_callouts(report),
        findings: Vec::new(),
        finding_groups: build_effectiveness_finding_groups(report),
        sections,
        tables,
        assessment_verdict: Some(assessment.verdict),
    }
}

fn build_va_view(report: &VaRunReport) -> ReportView {
    let mut sections = Vec::new();
    sections.push(Section {
        title: "Summary".to_string(),
        intro: None,
        rows: vec![
            ("Plan size".to_string(), report.plan_size.to_string()),
            ("Blocked".to_string(), report.summary.blocked.to_string()),
            (
                "Challenge".to_string(),
                report.summary.challenge.to_string(),
            ),
            ("Allowed".to_string(), report.summary.allowed.to_string()),
            ("Errors".to_string(), report.summary.error.to_string()),
        ],
        bullets: report
            .evidence_summary
            .iter()
            .map(|item| format!("{:?}: {}", item.kind, item.count))
            .collect(),
    });
    let tables = vec![
        TableSection {
            title: "Enforcement Probe Results".to_string(),
            intro: Some(
                "All enforcement probes with their final classification and evidence.".to_string(),
            ),
            columns: vec![
                "Category".to_string(),
                "Payload".to_string(),
                "Outcome".to_string(),
                "Reason".to_string(),
                "Evidence".to_string(),
            ],
            rows: report
                .results
                .iter()
                .map(|result| {
                    vec![
                        format!("{:?}", result.category),
                        sanitize_cell(result.payload.clone()),
                        format!("{:?}", result.outcome),
                        sanitize_cell(result.reason.clone()),
                        sanitize_cell(
                            result
                                .evidence
                                .iter()
                                .map(|item| format!("{:?}: {}", item.kind, item.detail))
                                .collect::<Vec<_>>()
                                .join(" | "),
                        ),
                    ]
                })
                .collect(),
            outcome_column: None,
            filterable: false,
        },
        TableSection {
            title: "Replay Plan".to_string(),
            intro: Some(
                "Deterministic replay inventory that can be reused for follow-up testing."
                    .to_string(),
            ),
            columns: vec![
                "Index".to_string(),
                "Class".to_string(),
                "Channel".to_string(),
                "Method".to_string(),
                "URL".to_string(),
                "Headers".to_string(),
                "Body".to_string(),
            ],
            rows: report
                .replay_plan
                .iter()
                .map(|item| {
                    vec![
                        item.index.to_string(),
                        item.class.clone(),
                        item.channel.clone(),
                        item.method.clone(),
                        sanitize_cell(item.url.clone()),
                        format_headers(&item.headers),
                        sanitize_cell(item.body.clone().unwrap_or_else(|| "—".to_string())),
                    ]
                })
                .collect(),
            outcome_column: None,
            filterable: false,
        },
    ];

    ReportView {
        kind: ReportKind::Enforcement,
        kind_label: "Enforcement Report".to_string(),
        title: report.target_url.clone(),
        subtitle: "Categorized attack probes showing block, challenge, and allow behavior"
            .to_string(),
        summary_cards: vec![
            MetricCard {
                label: "Enforcement".to_string(),
                value: format!("{:?}", report.enforcement),
                tone: "warn",
            },
            MetricCard {
                label: "Blocked".to_string(),
                value: report.summary.blocked.to_string(),
                tone: "good",
            },
            MetricCard {
                label: "Allowed".to_string(),
                value: report.summary.allowed.to_string(),
                tone: "bad",
            },
            MetricCard {
                label: "Evidence Score".to_string(),
                value: format!("{:.1}", report.evidence_score),
                tone: "info",
            },
        ],
        callouts: Vec::new(),
        findings: report
            .results
            .iter()
            .filter(|result| format!("{:?}", result.outcome) == "Allowed")
            .take(12)
            .map(|result| FindingCard {
                severity: "ALLOWED".to_string(),
                title: format!("{:?}", result.category),
                detail: result.reason.clone(),
                recommendation: None,
            })
            .collect(),
        finding_groups: Vec::new(),
        sections,
        tables,
        assessment_verdict: None,
    }
}

fn build_va2_view(report: &Va2RunReport) -> ReportView {
    let mut sections = Vec::new();
    sections.push(Section {
        title: "Behavioral Signals".to_string(),
        intro: Some(report.pmi.label.clone()),
        rows: vec![
            ("PMI".to_string(), format!("{:.1}", report.pmi.score)),
            (
                "Differential score".to_string(),
                format!("{:.0}%", report.wbf.differential_score * 100.0),
            ),
            (
                "Normalization score".to_string(),
                format!("{:.0}%", report.wbf.normalization_score * 100.0),
            ),
            (
                "Challenge score".to_string(),
                format!("{:.0}%", report.wbf.challenge_score * 100.0),
            ),
            (
                "Throttle score".to_string(),
                format!("{:.0}%", report.wbf.throttle_score * 100.0),
            ),
        ],
        bullets: report
            .channel_coverage
            .as_ref()
            .map(|coverage| {
                coverage
                    .blind_spots
                    .iter()
                    .map(|spot| format!("{spot} channel had 0% attack discrimination"))
                    .collect()
            })
            .unwrap_or_default(),
    });
    if let Some(coverage) = &report.channel_coverage {
        sections.push(Section {
            title: "Channel Coverage".to_string(),
            intro: Some(format!(
                "{:.0}% overall coverage",
                coverage.coverage_score * 100.0
            )),
            rows: coverage
                .channels
                .iter()
                .map(|(channel, score)| (channel.to_string(), format!("{:.0}%", score * 100.0)))
                .collect(),
            bullets: coverage
                .blind_spots
                .iter()
                .map(|spot| format!("{spot} channel had no confirmed attack discrimination"))
                .collect(),
        });
    }
    let result_by_step = report
        .results
        .iter()
        .map(|result| (result.step_id, result))
        .collect::<std::collections::HashMap<_, _>>();
    let tables = vec![
        TableSection {
            title: "Behavioral Step Results".to_string(),
            intro: Some("Every planned VA2 step and the observed response metadata.".to_string()),
            columns: vec![
                "Step".to_string(),
                "Phase".to_string(),
                "Kind".to_string(),
                "Channel".to_string(),
                "Method".to_string(),
                "Path".to_string(),
                "Query".to_string(),
                "Status".to_string(),
                "Duration ms".to_string(),
                "Error".to_string(),
                "Notes".to_string(),
            ],
            rows: report
                .plan
                .steps
                .iter()
                .map(|step| {
                    let result = result_by_step.get(&step.id);
                    vec![
                        step.id.to_string(),
                        format!("{:?}", step.phase),
                        format!("{:?}", step.kind),
                        step.channel
                            .map(|channel| channel.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                        step.method.clone(),
                        step.path.clone(),
                        step.query.clone().unwrap_or_else(|| "—".to_string()),
                        result
                            .and_then(|entry| entry.status)
                            .map(|status| status.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                        result
                            .map(|entry| entry.duration_ms.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                        sanitize_cell(
                            result
                                .and_then(|entry| entry.error.clone())
                                .unwrap_or_else(|| "—".to_string()),
                        ),
                        sanitize_cell(step.notes.clone()),
                    ]
                })
                .collect(),
            outcome_column: None,
            filterable: false,
        },
        TableSection {
            title: "Differential Results".to_string(),
            intro: Some(
                "Baseline-to-variant comparisons that drive paired-control conclusions."
                    .to_string(),
            ),
            columns: vec![
                "Step".to_string(),
                "Baseline".to_string(),
                "Channel".to_string(),
                "Outcome".to_string(),
                "Discriminated".to_string(),
                "Status Δ".to_string(),
                "Body Δ %".to_string(),
                "Header muts".to_string(),
                "Timing Δ ms".to_string(),
            ],
            rows: report
                .differential
                .iter()
                .map(|diff| {
                    vec![
                        diff.step_id.to_string(),
                        diff.baseline_step_id.to_string(),
                        diff.channel
                            .map(|channel| channel.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                        diff.outcome
                            .map(|outcome| format!("{:?}", outcome))
                            .unwrap_or_else(|| "—".to_string()),
                        bool_label(diff.discriminated).to_string(),
                        diff.status_delta.to_string(),
                        format!("{:.1}", diff.body_length_pct_change),
                        diff.header_mutation_count.to_string(),
                        diff.timing_delta_ms.to_string(),
                    ]
                })
                .collect(),
            outcome_column: None,
            filterable: false,
        },
    ];

    ReportView {
        kind: ReportKind::Behavioral,
        kind_label: "Behavioral Report".to_string(),
        title: report.target_url.clone(),
        subtitle: "Paired-control analysis across normalization, statefulness, challenge, and rate pressure".to_string(),
        summary_cards: vec![
            MetricCard {
                label: "PMI".to_string(),
                value: format!("{:.1}", report.pmi.score),
                tone: risk_tone(100.0 - report.pmi.score),
            },
            MetricCard {
                label: "Label".to_string(),
                value: report.pmi.label.clone(),
                tone: "info",
            },
            MetricCard {
                label: "Differential Pairs".to_string(),
                value: report.differential.len().to_string(),
                tone: "warn",
            },
            MetricCard {
                label: "Coverage".to_string(),
                value: report
                    .channel_coverage
                    .as_ref()
                    .map(|coverage| format!("{:.0}%", coverage.coverage_score * 100.0))
                    .unwrap_or_else(|| "N/A".to_string()),
                tone: "good",
            },
        ],
        callouts: Vec::new(),
        findings: report
            .channel_coverage
            .as_ref()
            .map(|coverage| {
                coverage
                    .blind_spots
                    .iter()
                    .map(|spot| FindingCard {
                        severity: "BLIND SPOT".to_string(),
                        title: format!("{spot}"),
                        detail: format!("{spot} channel showed no confirmed attack discrimination"),
                        recommendation: None,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        finding_groups: Vec::new(),
        sections,
        tables,
        assessment_verdict: None,
    }
}

fn build_detection_view(report: &DetectionResult) -> ReportView {
    let provider_evidence = report
        .evidence_map
        .iter()
        .map(|(provider, evidence)| format!("{provider}: {} signals", evidence.len()))
        .collect::<Vec<_>>();
    let mut provider_rows = report
        .provider_scores
        .iter()
        .map(|(provider, score)| vec![provider.clone(), format!("{:.0}%", score * 100.0)])
        .collect::<Vec<_>>();
    provider_rows.sort_by(|a, b| a[0].cmp(&b[0]));
    let mut evidence_rows = Vec::new();
    for (provider, evidence_list) in &report.evidence_map {
        for evidence in evidence_list {
            evidence_rows.push(vec![
                provider.clone(),
                format!("{:?}", evidence.method_type),
                format!("{:.0}%", evidence.confidence * 100.0),
                sanitize_cell(evidence.description.clone()),
                sanitize_cell(evidence.signature_matched.clone()),
                sanitize_cell(evidence.raw_data.clone()),
            ]);
        }
    }
    ReportView {
        kind: ReportKind::Detection,
        kind_label: "Detection Result".to_string(),
        title: report.url.clone(),
        subtitle: "Provider fingerprinting across headers, body, DNS, timing, and TLS".to_string(),
        summary_cards: vec![
            MetricCard {
                label: "WAF".to_string(),
                value: report
                    .waf_name()
                    .map(str::to_string)
                    .unwrap_or_else(|| "Not detected".to_string()),
                tone: "info",
            },
            MetricCard {
                label: "CDN".to_string(),
                value: report
                    .cdn_name()
                    .map(str::to_string)
                    .unwrap_or_else(|| "Not detected".to_string()),
                tone: "info",
            },
            MetricCard {
                label: "WAF Confidence".to_string(),
                value: report
                    .waf_confidence()
                    .map(|value| format!("{:.0}%", value * 100.0))
                    .unwrap_or_else(|| "0%".to_string()),
                tone: "good",
            },
            MetricCard {
                label: "Detection Time".to_string(),
                value: format!("{} ms", report.detection_time_ms),
                tone: "neutral",
            },
        ],
        callouts: report
            .caveats
            .iter()
            .map(|caveat| Callout {
                tone: "warn",
                title: "Caveat".to_string(),
                body: caveat.clone(),
            })
            .collect(),
        findings: Vec::new(),
        finding_groups: Vec::new(),
        sections: vec![Section {
            title: "Evidence Inventory".to_string(),
            intro: None,
            rows: vec![(
                "Providers scored".to_string(),
                report.provider_scores.len().to_string(),
            )],
            bullets: provider_evidence,
        }],
        tables: vec![
            TableSection {
                title: "Provider Scores".to_string(),
                intro: Some(
                    "Raw provider confidence scores before final WAF/CDN selection.".to_string(),
                ),
                columns: vec!["Provider".to_string(), "Score".to_string()],
                rows: provider_rows,
                outcome_column: None,
                filterable: false,
            },
            TableSection {
                title: "Detection Evidence".to_string(),
                intro: Some(
                    "Every matched signal that contributed to provider detection.".to_string(),
                ),
                columns: vec![
                    "Provider".to_string(),
                    "Method".to_string(),
                    "Confidence".to_string(),
                    "Description".to_string(),
                    "Signature".to_string(),
                    "Raw".to_string(),
                ],
                rows: evidence_rows,
                outcome_column: None,
                filterable: false,
            },
        ],
        assessment_verdict: None,
    }
}

fn build_origin_probe_view(report: &OriginProbeReport) -> ReportView {
    let accessible_paths = report.findings.len();
    let bypassed_paths = report
        .findings
        .iter()
        .filter(|finding| finding.waf_bypassed)
        .count();

    let verdict = if report.bypass_confirmed {
        AssessmentVerdict {
            verdict: "BYPASS CONFIRMED",
            tone: "bad",
            description: "At least one operational path was reachable on the origin IP and the main target also responded via origin without clear block indicators. Treat this as a direct edge-bypass exposure.".to_string(),
            proven: format!("{} bypassed path(s), {} accessible total", bypassed_paths, accessible_paths),
        }
    } else if accessible_paths > 0 {
        AssessmentVerdict {
            verdict: "NO BYPASS",
            tone: "warn",
            description: "Some same-origin paths were reachable on the origin IP, but the follow-up attack probe did not confirm a clean WAF bypass.".to_string(),
            proven: format!("{} accessible path(s), 0 confirmed bypasses", accessible_paths),
        }
    } else {
        AssessmentVerdict {
            verdict: "NO ACCESSIBLE PATHS",
            tone: "good",
            description: "No well-known operational paths were reachable directly on the origin IP during this run.".to_string(),
            proven: "0 paths tested".to_string(),
        }
    };

    let sections = vec![Section {
        title: "Origin Summary".to_string(),
        intro: Some(
            "Direct-origin checks against well-known operational paths that may be reachable outside the edge/WAF."
                .to_string(),
        ),
        rows: vec![
            ("Target host".to_string(), report.target_host.clone()),
            ("Origin IP".to_string(), report.origin_ip.to_string()),
            ("Accessible paths".to_string(), accessible_paths.to_string()),
            ("Bypassed paths".to_string(), bypassed_paths.to_string()),
        ],
        bullets: report
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "{} via origin returned HTTP {}",
                    finding.bypass_path, finding.status_on_bypass_path
                )
            })
            .collect(),
    }];

    let findings = report
        .findings
        .iter()
        .filter(|finding| finding.waf_bypassed)
        .take(12)
        .map(|finding| FindingCard {
            severity: "BYPASS".to_string(),
            title: finding.bypass_path.clone(),
            detail: format!(
                "{} returned HTTP {} and the main target via origin IP returned HTTP {} without block indicators.",
                finding.bypass_url, finding.status_on_bypass_path, finding.status_on_main_via_origin
            ),
            recommendation: Some(
                "Move the path behind the same edge controls as the primary hostname and block direct origin access."
                    .to_string(),
            ),
        })
        .collect();

    let tables = vec![TableSection {
        title: "Accessible Origin Paths".to_string(),
        intro: Some(
            "Every same-origin path that responded directly on the origin IP and the evidence collected for bypass determination."
                .to_string(),
        ),
        columns: vec![
            "Path".to_string(),
            "Bypass URL".to_string(),
            "Origin IP".to_string(),
            "Path Status".to_string(),
            "Main via Origin Status".to_string(),
            "Bypassed".to_string(),
            "Evidence".to_string(),
        ],
        rows: report
            .findings
            .iter()
            .map(|finding| {
                vec![
                    finding.bypass_path.clone(),
                    finding.bypass_url.clone(),
                    finding.origin_ip.to_string(),
                    finding.status_on_bypass_path.to_string(),
                    finding.status_on_main_via_origin.to_string(),
                    if finding.waf_bypassed {
                        "Allowed".to_string()
                    } else {
                        "Blocked".to_string()
                    },
                    sanitize_cell(finding.evidence.join(" | ")),
                ]
            })
            .collect(),
        outcome_column: Some(5),
        filterable: true,
    }];

    ReportView {
        kind: ReportKind::OriginProbe,
        kind_label: "Origin Probe Report".to_string(),
        title: report.target_url.clone(),
        subtitle: "Direct-origin reachability and WAF bypass verification for public-facing operational paths"
            .to_string(),
        summary_cards: vec![
            MetricCard {
                label: "Origin IP".to_string(),
                value: report.origin_ip.to_string(),
                tone: "info",
            },
            MetricCard {
                label: "Accessible Paths".to_string(),
                value: accessible_paths.to_string(),
                tone: "warn",
            },
            MetricCard {
                label: "Bypassed Paths".to_string(),
                value: bypassed_paths.to_string(),
                tone: if bypassed_paths > 0 { "bad" } else { "good" },
            },
            MetricCard {
                label: "Bypass Confirmed".to_string(),
                value: yes_no(report.bypass_confirmed).to_string(),
                tone: if report.bypass_confirmed { "bad" } else { "good" },
            },
        ],
        callouts: Vec::new(),
        findings,
        finding_groups: Vec::new(),
        sections,
        tables,
        assessment_verdict: Some(verdict),
    }
}

fn build_unknown_view(value: &Value) -> ReportView {
    let root_type = match value {
        Value::Object(_) => "object",
        Value::Array(_) => "array",
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        Value::Null => "null",
    };
    ReportView {
        kind: ReportKind::Unknown,
        kind_label: "Generic JSON Report".to_string(),
        title: "Saved Scan Output".to_string(),
        subtitle: "Structured JSON that did not match a known first-class report type".to_string(),
        summary_cards: vec![MetricCard {
            label: "Root Type".to_string(),
            value: root_type.to_string(),
            tone: "neutral",
        }],
        callouts: vec![Callout {
            tone: "info",
            title: "Unknown report type".to_string(),
            body: "The renderer kept the polished shell and included the raw JSON so the report remains usable.".to_string(),
        }],
        findings: Vec::new(),
        finding_groups: Vec::new(),
        sections: Vec::new(),
        tables: Vec::new(),
        assessment_verdict: None,
    }
}

fn build_effectiveness_assessment(report: &EffectivenessReport) -> EffectivenessAssessment {
    let degraded_count = report.degraded_test_count();
    let baseline_all_degraded = report.baseline_all_degraded();
    let actionable = report.actionable_test_count();
    let static_analysis = report.static_page_analysis.as_ref();
    let is_static_target = static_analysis
        .map(|analysis| analysis.is_likely_static)
        .unwrap_or(false);
    let static_confidence = static_analysis.map(|analysis| analysis.confidence);
    let primary_dynamic_endpoint = static_analysis.and_then(|analysis| {
        analysis
            .suggestions
            .first()
            .map(|suggestion| suggestion.endpoint.clone())
    });

    let verdict = if baseline_all_degraded {
        AssessmentVerdict {
            verdict: "INCONCLUSIVE",
            tone: "bad",
            description: "All baseline requests returned transport or edge-error responses. No application-layer signals were collected. Results are not meaningful until a healthy endpoint is tested.".to_string(),
            proven: format!(
                "0 actionable signals — {degraded_count} transport/edge failure(s)"
            ),
        }
    } else if is_static_target {
        let conf = static_confidence
            .map(|confidence| format!("{:.0}%", confidence * 100.0))
            .unwrap_or_else(|| "unknown".to_string());
        AssessmentVerdict {
            verdict: "STATIC TARGET",
            tone: "warn",
            description: format!(
                "Static-page analysis scored this endpoint at {conf} confidence for non-interactive behavior. Results may not reflect protection applied to dynamic routes."
            ),
            proven: format!(
                "{} blocked, {} potential misses",
                report.statistics.blocked_requests, report.statistics.allowed_requests
            ),
        }
    } else if actionable == 0 {
        AssessmentVerdict {
            verdict: "INCONCLUSIVE",
            tone: "bad",
            description:
                "No actionable probe results were collected. All probes returned transport or edge-error responses."
                    .to_string(),
            proven: format!("0 actionable signals — {degraded_count} transport/edge failure(s)"),
        }
    } else if degraded_count > 0 {
        AssessmentVerdict {
            verdict: "DEGRADED",
            tone: "warn",
            description: format!(
                "{degraded_count} probe(s) returned edge or transport errors. Only non-error results are actionable. Degraded rows should not be treated as misses."
            ),
            proven: format!(
                "{} blocked, {} potential misses, {} degraded",
                report.statistics.blocked_requests, report.statistics.allowed_requests, degraded_count
            ),
        }
    } else {
        AssessmentVerdict {
            verdict: "HEALTHY",
            tone: "good",
            description: "Baseline was healthy and all probe results are actionable. Allowed rows represent potential protection gaps.".to_string(),
            proven: format!(
                "{} blocked, {} potential misses",
                report.statistics.blocked_requests, report.statistics.allowed_requests
            ),
        }
    };

    EffectivenessAssessment {
        verdict,
        baseline_all_degraded,
        degraded_count,
        is_static_target,
        static_confidence,
        primary_dynamic_endpoint,
    }
}

fn render_html_document(view: &ReportView, raw_json: &str, input_path: &Path) -> String {
    let input_label = input_path.display().to_string();

    let verdict_html = view
        .assessment_verdict
        .as_ref()
        .map(render_verdict_banner)
        .unwrap_or_default();

    let callouts_html = if view.callouts.is_empty() {
        String::new()
    } else {
        format!(
            "<section class=\"panel\">{}</section>",
            render_callouts(&view.callouts)
        )
    };

    let findings_html = if view.findings.is_empty() {
        if view.finding_groups.is_empty() {
            String::new()
        } else {
            format!(
                "<section class=\"panel\"><h2>Findings</h2>{}</section>",
                render_finding_groups(&view.finding_groups)
            )
        }
    } else {
        format!(
            "<section class=\"panel\"><h2>Findings</h2>{}</section>",
            render_findings(&view.findings)
        )
    };

    let sections_html = render_sections(&view.sections);
    let tables_html = render_tables(&view.tables);
    let cards_html = render_metric_cards(&view.summary_cards);

    let kind_str = match view.kind {
        ReportKind::Hardening => "Hardening",
        ReportKind::Posture => "Posture",
        ReportKind::Effectiveness => "Effectiveness",
        ReportKind::Enforcement => "Enforcement",
        ReportKind::Behavioral => "Behavioral",
        ReportKind::Detection => "Detection",
        ReportKind::OriginProbe => "Origin Probe",
        ReportKind::Unknown => "JSON",
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} · {kind}</title>
  <style>
    :root {{
      --bg: #f5efe7;
      --bg-accent: #efe1d2;
      --panel: rgba(255,255,255,0.82);
      --panel-strong: #ffffff;
      --text: #1f2933;
      --muted: #5c6b77;
      --border: rgba(31,41,51,0.10);
      --good: #1a6644;
      --warn: #8a5e00;
      --bad: #9b1724;
      --info: #0f5282;
      --neutral: #5c6b77;
      --shadow: 0 4px 24px rgba(84,61,37,0.10);
      --shadow-lg: 0 20px 60px rgba(84,61,37,0.14);
      --radius: 20px;
    }}
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; }}
    body {{
      font-family: "SF Pro Text", "Segoe UI", system-ui, -apple-system, sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(233,184,115,0.18) 0%, transparent 32%),
        radial-gradient(circle at top right, rgba(82,150,195,0.12) 0%, transparent 28%),
        linear-gradient(180deg, var(--bg) 0%, #f9f7f3 100%);
      min-height: 100vh;
      line-height: 1.55;
    }}
    .page {{
      max-width: 1160px;
      margin: 0 auto;
      padding: 36px 24px 80px;
      display: grid;
      gap: 20px;
    }}
    .hero {{
      position: relative;
      overflow: hidden;
      padding: 32px 32px 28px;
      border-radius: 28px;
      background:
        linear-gradient(135deg, rgba(255,255,255,0.88), rgba(255,255,255,0.70)),
        linear-gradient(120deg, rgba(240,193,133,0.32), rgba(86,145,183,0.16));
      box-shadow: var(--shadow-lg);
      border: 1px solid rgba(255,255,255,0.50);
    }}
    .hero::after {{
      content: "";
      position: absolute;
      inset: auto -100px -120px auto;
      width: 280px; height: 280px;
      border-radius: 50%;
      background: rgba(214,153,84,0.10);
      pointer-events: none;
    }}
    .eyebrow {{
      display: inline-flex;
      align-items: center;
      padding: 6px 13px;
      border-radius: 999px;
      background: rgba(255,255,255,0.75);
      border: 1px solid rgba(31,41,51,0.09);
      color: var(--muted);
      font-size: 12px;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      font-weight: 500;
    }}
    h1 {{
      margin: 16px 0 8px;
      font-size: clamp(26px, 4vw, 44px);
      font-weight: 800;
      line-height: 1.06;
      letter-spacing: -0.02em;
    }}
    .subtitle {{
      max-width: 780px;
      color: var(--muted);
      font-size: 17px;
      line-height: 1.6;
    }}
    .meta {{
      margin-top: 14px;
      color: var(--muted);
      font-size: 13px;
    }}
    .cards {{
      margin-top: 22px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 14px;
    }}
    .card {{
      padding: 16px 18px 14px;
      border-radius: 18px;
      background: var(--panel);
      border: 1px solid var(--border);
    }}
    .card-label {{
      font-size: 11px;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--muted);
      font-weight: 600;
      margin-bottom: 8px;
    }}
    .card-value {{
      font-size: 26px;
      font-weight: 800;
      line-height: 1.1;
      letter-spacing: -0.01em;
    }}
    .verdict-banner {{
      display: flex;
      align-items: flex-start;
      gap: 18px;
      padding: 18px 22px;
      border-radius: var(--radius);
      border: 1px solid transparent;
    }}
    .verdict-banner.tone-good {{
      background: linear-gradient(135deg, rgba(26,102,68,0.07), rgba(26,102,68,0.03));
      border-color: rgba(26,102,68,0.22);
    }}
    .verdict-banner.tone-warn {{
      background: linear-gradient(135deg, rgba(138,94,0,0.07), rgba(138,94,0,0.03));
      border-color: rgba(138,94,0,0.22);
    }}
    .verdict-banner.tone-bad {{
      background: linear-gradient(135deg, rgba(155,23,36,0.08), rgba(155,23,36,0.03));
      border-color: rgba(155,23,36,0.22);
    }}
    .verdict-badge {{
      flex-shrink: 0;
      padding: 8px 14px;
      border-radius: 10px;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.09em;
      text-transform: uppercase;
      color: white;
      white-space: nowrap;
    }}
    .tone-good .verdict-badge {{ background: var(--good); }}
    .tone-warn .verdict-badge {{ background: var(--warn); }}
    .tone-bad  .verdict-badge {{ background: var(--bad); }}
    .verdict-desc {{ font-size: 15px; line-height: 1.6; margin-bottom: 4px; }}
    .verdict-proven {{ font-size: 13px; color: var(--muted); font-variant-numeric: tabular-nums; }}
    .tone-good   {{ color: var(--good); }}
    .tone-warn   {{ color: var(--warn); }}
    .tone-bad    {{ color: var(--bad); }}
    .tone-info   {{ color: var(--info); }}
    .tone-neutral {{ color: var(--neutral); }}
    .panel {{
      background: var(--panel-strong);
      border-radius: var(--radius);
      border: 1px solid var(--border);
      box-shadow: var(--shadow);
      padding: 24px 26px;
    }}
    .panel h2 {{
      font-size: 19px;
      font-weight: 700;
      margin-bottom: 14px;
      letter-spacing: -0.01em;
    }}
    .panel-intro {{
      color: var(--muted);
      line-height: 1.65;
      margin-bottom: 14px;
      font-size: 14px;
    }}
    .callout {{
      padding: 14px 16px;
      border-radius: 14px;
      border: 1px solid var(--border);
      margin-bottom: 12px;
      background: linear-gradient(180deg, rgba(245,247,250,0.75), rgba(255,255,255,0.92));
    }}
    .callout:last-child {{ margin-bottom: 0; }}
    .callout strong {{ display: block; margin-bottom: 5px; font-size: 14px; }}
    .callout div {{ font-size: 14px; color: var(--muted); line-height: 1.6; }}
    .callout.tone-good strong {{ color: var(--good); }}
    .callout.tone-warn strong {{ color: var(--warn); }}
    .callout.tone-bad  strong {{ color: var(--bad); }}
    .callout.tone-info strong {{ color: var(--info); }}
    .findings {{ display: grid; gap: 12px; }}
    .finding-groups {{ display: grid; gap: 18px; }}
    .finding-group + .finding-group {{
      padding-top: 18px;
      border-top: 1px solid var(--border);
    }}
    .finding-group h3 {{
      font-size: 16px;
      font-weight: 700;
      margin-bottom: 6px;
      letter-spacing: -0.01em;
    }}
    .finding-group-intro {{
      margin-bottom: 12px;
      font-size: 14px;
      color: var(--muted);
      line-height: 1.6;
    }}
    .finding {{
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 16px 18px;
      background: linear-gradient(180deg, rgba(255,255,255,0.98), rgba(247,245,242,0.94));
    }}
    .finding-header {{
      display: flex;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 6px;
    }}
    .pill {{
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 11px;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      font-weight: 600;
      background: rgba(31,41,51,0.07);
      color: var(--muted);
      white-space: nowrap;
    }}
    .finding h3 {{ margin: 0; font-size: 16px; font-weight: 700; }}
    .finding p {{ margin: 6px 0 0; color: var(--muted); font-size: 14px; line-height: 1.6; }}
    .filter-btns {{
      display: flex;
      gap: 8px;
      padding: 0 0 14px;
      flex-wrap: wrap;
    }}
    .filter-btn {{
      padding: 5px 14px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: var(--panel);
      color: var(--muted);
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.12s, color 0.12s, border-color 0.12s;
      font-family: inherit;
    }}
    .filter-btn:hover {{ background: var(--bg-accent); }}
    .filter-btn.active {{ background: var(--text); color: #fff; border-color: var(--text); }}
    .table-wrap {{
      overflow-x: auto;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: #fffcf7;
    }}
    .detail-table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 760px;
    }}
    .detail-table th,
    .detail-table td {{
      padding: 11px 13px;
      text-align: left;
      vertical-align: top;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
      line-height: 1.5;
    }}
    .detail-table th {{
      position: sticky;
      top: 0;
      z-index: 1;
      background: #f4ede0;
      color: var(--muted);
      font-size: 11px;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      font-weight: 700;
    }}
    .detail-table tbody tr:last-child td {{ border-bottom: none; }}
    .detail-table tbody tr:hover td {{ background: rgba(245,239,231,0.55); }}
    .badge {{
      display: inline-block;
      padding: 3px 9px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      white-space: nowrap;
    }}
    .outcome-blocked         {{ background: rgba(26,102,68,0.12);  color: var(--good); }}
    .outcome-allowed         {{ background: rgba(155,23,36,0.12);  color: var(--bad); }}
    .outcome-edge-error      {{ background: rgba(138,94,0,0.12);   color: var(--warn); }}
    .outcome-transport-error {{ background: rgba(92,107,119,0.12); color: var(--neutral); }}
    .outcome-unknown         {{ background: rgba(92,107,119,0.08); color: var(--neutral); }}
    .cell-expand {{ max-width: 280px; }}
    .cell-preview {{ word-break: break-all; font-size: 13px; }}
    .cell-detail {{ margin-top: 4px; }}
    .cell-detail summary {{
      font-size: 11px;
      color: var(--info);
      cursor: pointer;
      list-style: none;
    }}
    .cell-detail summary::before {{ content: "▶ "; font-size: 9px; }}
    details[open].cell-detail summary::before {{ content: "▼ "; }}
    .cell-detail code {{
      display: block;
      margin-top: 6px;
      font-family: "SF Mono", "Fira Code", "Consolas", monospace;
      font-size: 11px;
      white-space: pre-wrap;
      word-break: break-all;
      background: rgba(0,0,0,0.04);
      padding: 8px 10px;
      border-radius: 8px;
      line-height: 1.55;
    }}
    .kv {{
      display: grid;
      grid-template-columns: minmax(130px, 170px) 1fr;
      gap: 9px 12px;
      margin-top: 10px;
    }}
    .kv dt {{ color: var(--muted); font-weight: 600; font-size: 13px; }}
    .kv dd {{ margin: 0; font-size: 13px; line-height: 1.55; }}
    ul {{ margin: 10px 0 0 18px; padding: 0; color: var(--muted); font-size: 13px; }}
    li + li {{ margin-top: 6px; }}
    .raw-json details summary {{
      cursor: pointer;
      font-weight: 700;
      font-size: 14px;
      user-select: none;
    }}
    .raw-json pre {{
      margin: 12px 0 0;
      padding: 16px 18px;
      overflow-x: auto;
      border-radius: 14px;
      background: #111827;
      color: #e5eef7;
      font-family: "SF Mono", "Fira Code", "Consolas", monospace;
      font-size: 12px;
      line-height: 1.65;
    }}
    .empty {{ color: var(--muted); font-style: italic; font-size: 14px; }}
    @media (max-width: 840px) {{
      .page {{ padding: 20px 14px 60px; gap: 16px; }}
      .hero {{ padding: 22px 20px 20px; }}
      .card-value {{ font-size: 22px; }}
      .panel {{ padding: 18px; }}
      .verdict-banner {{ flex-direction: column; gap: 12px; }}
    }}
  </style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <div class="eyebrow">{kind} · {input}</div>
      <h1>{title}</h1>
      <p class="subtitle">{subtitle}</p>
      <div class="meta">Kind: {kind_label}</div>
      <div class="cards">{cards}</div>
    </section>

    {verdict}

    {callouts}

    {findings}

    {sections}

    {tables}

    <section class="panel raw-json">
      <h2>Raw JSON</h2>
      <details>
        <summary>Expand source payload</summary>
        <pre>{raw_json}</pre>
      </details>
    </section>
  </main>
  <script>
  (function(){{
    document.querySelectorAll('.filter-btn').forEach(function(btn){{
      btn.addEventListener('click', function(){{
        var filter = this.dataset.filter;
        var wrap = this.closest('.filter-wrap');
        wrap.querySelectorAll('.filter-btn').forEach(function(b){{ b.classList.remove('active'); }});
        this.classList.add('active');
        var table = wrap.querySelector('table[data-filterable]');
        if (!table) return;
        table.querySelectorAll('tbody tr').forEach(function(row){{
          if (filter === 'all') {{
            row.style.display = '';
          }} else if (filter === 'errors') {{
            var o = row.dataset.outcome || '';
            row.style.display = (o === 'edge-error' || o === 'transport-error') ? '' : 'none';
          }} else {{
            row.style.display = (row.dataset.outcome === filter) ? '' : 'none';
          }}
        }});
      }});
    }});
  }})();
  </script>
</body>
</html>
"#,
        title = escape_html(&view.title),
        kind = escape_html(kind_str),
        input = escape_html(&input_label),
        subtitle = escape_html(&view.subtitle),
        kind_label = escape_html(&view.kind_label),
        cards = cards_html,
        verdict = verdict_html,
        callouts = callouts_html,
        findings = findings_html,
        sections = sections_html,
        tables = tables_html,
        raw_json = escape_html(raw_json),
    )
}

fn render_verdict_banner(verdict: &AssessmentVerdict) -> String {
    format!(
        r#"<div class="verdict-banner tone-{tone}"><div class="verdict-badge">{verdict}</div><div><p class="verdict-desc">{desc}</p><p class="verdict-proven">{proven}</p></div></div>"#,
        tone = verdict.tone,
        verdict = escape_html(verdict.verdict),
        desc = escape_html(&verdict.description),
        proven = escape_html(&verdict.proven),
    )
}

fn outcome_to_data_attr(outcome: &str) -> &'static str {
    match outcome {
        "Blocked" => "blocked",
        "Allowed" => "allowed",
        "Edge error" => "edge-error",
        "Transport error" => "transport-error",
        _ => "unknown",
    }
}

fn render_metric_cards(cards: &[MetricCard]) -> String {
    if cards.is_empty() {
        return "<div class=\"empty\">No summary metrics available.</div>".to_string();
    }
    let mut out = String::new();
    for card in cards {
        let _ = write!(
            out,
            "<article class=\"card\"><div class=\"card-label\">{}</div><div class=\"card-value tone-{}\">{}</div></article>",
            escape_html(&card.label),
            card.tone,
            escape_html(&card.value)
        );
    }
    out
}

fn render_callouts(callouts: &[Callout]) -> String {
    if callouts.is_empty() {
        return "<p class=\"empty\">No operator caveats or summary callouts for this report.</p>"
            .to_string();
    }
    let mut out = String::new();
    for callout in callouts {
        let _ = write!(
            out,
            "<article class=\"callout tone-{}\"><strong>{}</strong><div>{}</div></article>",
            callout.tone,
            escape_html(&callout.title),
            escape_html(&callout.body)
        );
    }
    out
}

fn render_findings(findings: &[FindingCard]) -> String {
    if findings.is_empty() {
        return "<p class=\"empty\">No discrete findings were attached to this report.</p>"
            .to_string();
    }
    let mut out = String::from("<div class=\"findings\">");
    for finding in findings {
        let tone = severity_tone(Some(&finding.severity));
        let _ = write!(
            out,
            "<article class=\"finding\"><div class=\"finding-header\"><h3>{}</h3><span class=\"pill tone-{}\">{}</span></div><p>{}</p>{}</article>",
            escape_html(&finding.title),
            tone,
            escape_html(&finding.severity),
            escape_html(&finding.detail),
            finding
                .recommendation
                .as_ref()
                .map(|value| format!("<p><strong>Recommendation:</strong> {}</p>", escape_html(value)))
                .unwrap_or_default(),
        );
    }
    out.push_str("</div>");
    out
}

fn render_finding_groups(groups: &[FindingGroup]) -> String {
    if groups.is_empty() {
        return "<p class=\"empty\">No discrete findings were attached to this report.</p>"
            .to_string();
    }
    let mut out = String::from("<div class=\"finding-groups\">");
    for group in groups {
        let _ = write!(
            out,
            "<section class=\"finding-group\"><h3>{}</h3>{}{}</section>",
            escape_html(&group.title),
            group
                .intro
                .as_ref()
                .map(|intro| format!(
                    "<p class=\"finding-group-intro\">{}</p>",
                    escape_html(intro)
                ))
                .unwrap_or_default(),
            render_findings(&group.findings)
        );
    }
    out.push_str("</div>");
    out
}

fn render_sections(sections: &[Section]) -> String {
    if sections.is_empty() {
        return "<p class=\"empty\">No extra sections were generated for this report type.</p>"
            .to_string();
    }
    let mut out = String::new();
    for section in sections {
        let _ = write!(
            out,
            "<section class=\"panel\" style=\"margin-bottom:16px;\"><h2>{}</h2>{}{}{}</section>",
            escape_html(&section.title),
            section
                .intro
                .as_ref()
                .map(|intro| format!("<p class=\"panel-intro\">{}</p>", escape_html(intro)))
                .unwrap_or_default(),
            render_rows(&section.rows),
            render_bullets(&section.bullets),
        );
    }
    out
}

fn render_tables(tables: &[TableSection]) -> String {
    if tables.is_empty() {
        return "<p class=\"empty\">No detailed data tables were generated for this report.</p>"
            .to_string();
    }
    let mut out = String::new();
    for table in tables {
        let _ =
            write!(
            out,
            "<section class=\"panel\" style=\"margin-bottom:16px;\"><h2>{}</h2>{}{}{}</section>",
            escape_html(&table.title),
            table
                .intro
                .as_ref()
                .map(|intro| format!("<p class=\"panel-intro\">{}</p>", escape_html(intro)))
                .unwrap_or_default(),
            render_table_grid(&table.columns, &table.rows, table.outcome_column, table.filterable),
            if table.rows.is_empty() {
                "<p class=\"empty\">No rows.</p>".to_string()
            } else {
                String::new()
            }
        );
    }
    out
}

fn render_table_grid(
    columns: &[String],
    rows: &[Vec<String>],
    outcome_column: Option<usize>,
    filterable: bool,
) -> String {
    if columns.is_empty() {
        return String::new();
    }
    let mut out = String::new();

    // Wrap in filter-wrap div when filterable so JS can scope the filter buttons to this table
    if filterable {
        out.push_str(
            "<div class=\"filter-wrap\"><div class=\"filter-btns\">             <button class=\"filter-btn active\" data-filter=\"all\">All</button>             <button class=\"filter-btn\" data-filter=\"blocked\">Blocked</button>             <button class=\"filter-btn\" data-filter=\"allowed\">Allowed</button>             <button class=\"filter-btn\" data-filter=\"errors\">Errors</button>             </div>",
        );
    }

    out.push_str("<div class=\"table-wrap\">");
    if filterable {
        out.push_str("<table class=\"detail-table\" data-filterable><thead><tr>");
    } else {
        out.push_str("<table class=\"detail-table\"><thead><tr>");
    }
    for column in columns {
        let _ = write!(out, "<th>{}</th>", escape_html(column));
    }
    out.push_str("</tr></thead><tbody>");

    for row in rows {
        // Determine the outcome string for data-outcome and badge rendering
        let outcome_str = outcome_column
            .and_then(|col| row.get(col))
            .map(|s| s.as_str())
            .unwrap_or("");
        let data_attr = if outcome_column.is_some() {
            let attr_val = outcome_to_data_attr(outcome_str);
            format!(" data-outcome=\"{}\"", attr_val)
        } else {
            String::new()
        };
        let _ = write!(out, "<tr{}>", data_attr);

        for (i, cell) in row.iter().enumerate() {
            // Outcome column: render as a colored badge
            if outcome_column == Some(i) {
                let attr_val = outcome_to_data_attr(cell);
                let _ = write!(
                    out,
                    "<td><span class=\"badge outcome-{}\">{}</span></td>",
                    attr_val,
                    escape_html(cell)
                );
            } else if cell.len() > 120 {
                // Long cell: show truncated preview + expandable details (truncate at char boundary)
                let preview = match cell.char_indices().nth(120) {
                    Some((i, _)) => &cell[..i],
                    None => cell,
                };
                let _ = write!(
                    out,
                    "<td class=\"cell-expand\"><div class=\"cell-preview\">{}&hellip;</div>                     <details class=\"cell-detail\"><summary>show full</summary>                     <code>{}</code></details></td>",
                    escape_html(preview),
                    escape_html(cell)
                );
            } else {
                let _ = write!(out, "<td>{}</td>", escape_html(cell));
            }
        }
        out.push_str("</tr>");
    }

    out.push_str("</tbody></table></div>");
    if filterable {
        out.push_str("</div>"); // close filter-wrap
    }
    out
}

fn render_rows(rows: &[(String, String)]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let mut out = String::from("<dl class=\"kv\">");
    for (label, value) in rows {
        let _ = write!(
            out,
            "<dt>{}</dt><dd>{}</dd>",
            escape_html(label),
            escape_html(value)
        );
    }
    out.push_str("</dl>");
    out
}

fn render_bullets(bullets: &[String]) -> String {
    if bullets.is_empty() {
        return String::new();
    }
    let mut out = String::from("<ul>");
    for bullet in bullets {
        let _ = write!(out, "<li>{}</li>", escape_html(bullet));
    }
    out.push_str("</ul>");
    out
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn severity_tone(severity: Option<&str>) -> &'static str {
    match severity
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "critical" | "high" | "blind spot" | "allowed" => "bad",
        "medium" | "warn" => "warn",
        "low" | "info" => "info",
        "a" | "b" => "good",
        "d" | "f" => "bad",
        _ => "neutral",
    }
}

fn risk_tone(risk_score: f64) -> &'static str {
    if risk_score >= 70.0 {
        "bad"
    } else if risk_score >= 40.0 {
        "warn"
    } else {
        "good"
    }
}

fn grade_tone(grade: &str) -> &'static str {
    match grade {
        "A" | "B" => "good",
        "C" => "warn",
        "D" | "F" => "bad",
        _ => "neutral",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "Yes"
    } else {
        "No"
    }
}

fn join_or_dash(values: Vec<String>) -> String {
    if values.is_empty() {
        "—".to_string()
    } else {
        values.join(", ")
    }
}

fn map_counts(values: &std::collections::HashMap<String, usize>) -> Vec<String> {
    let mut entries = values.iter().collect::<Vec<_>>();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    entries
        .into_iter()
        .map(|(key, value)| format!("{key}: {value}"))
        .collect()
}

fn format_optional_score(value: Option<f64>) -> String {
    value
        .map(|score| format!("{:.0}%", score * 100.0))
        .unwrap_or_else(|| "N/A".to_string())
}

fn sanitize_cell(value: impl Into<String>) -> String {
    value.into().replace('\n', " ")
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn effectiveness_outcome_label(result: &crate::effectiveness::TestResult) -> &'static str {
    if result.is_transport_error() {
        "Transport error"
    } else if result.is_edge_error() {
        "Edge error"
    } else if result.blocked {
        "Blocked"
    } else {
        "Allowed"
    }
}

fn effectiveness_callouts(report: &EffectivenessReport) -> Vec<Callout> {
    let assessment = build_effectiveness_assessment(report);
    let mut callouts = Vec::new();

    if assessment.baseline_all_degraded {
        callouts.push(Callout {
            tone: "bad",
            title: "Assessment quality is degraded".to_string(),
            body: "All baseline requests returned transport or edge-error responses. Treat this report as inconclusive for application-layer protection gaps until a healthy endpoint is tested.".to_string(),
        });
    } else if assessment.degraded_count > 0 {
        callouts.push(Callout {
            tone: "warn",
            title: "Edge or transport errors were observed".to_string(),
            body: format!(
                "{} probe(s) returned transport failures or 5xx edge responses. Only non-error, non-blocked rows should be treated as potential misses.",
                assessment.degraded_count
            ),
        });
    }

    if assessment.is_static_target {
        let confidence = assessment
            .static_confidence
            .map(|value| format!("{:.0}%", value * 100.0))
            .unwrap_or_else(|| "unknown".to_string());
        callouts.push(Callout {
            tone: "warn",
            title: "Root target looks static or non-interactive".to_string(),
            body: format!(
                "Static-page analysis scored this endpoint at {confidence} confidence for static or non-interactive behavior. Prefer a dynamic endpoint such as {}.",
                assessment
                    .primary_dynamic_endpoint
                    .as_deref()
                    .unwrap_or("/api/")
            ),
        });
    } else if report.has_static_target_hint() {
        callouts.push(Callout {
            tone: "warn",
            title: "Root target looks static or non-interactive".to_string(),
            body: "The scan detected little or no parameter processing on the tested URL. Results on / may not reflect the protection applied to dynamic endpoints like /api/, /login, or /search.".to_string(),
        });
    }

    let proven = if report.statistics.allowed_requests > 0 {
        format!(
            "{} explicit block(s), {} potential miss(es), {} degraded/error response(s).",
            report.statistics.blocked_requests,
            report.statistics.allowed_requests,
            report.degraded_test_count()
        )
    } else {
        format!(
            "{} explicit block(s), no confirmed non-error misses, {} degraded/error response(s).",
            report.statistics.blocked_requests,
            report.degraded_test_count()
        )
    };
    callouts.push(Callout {
        tone: "info",
        title: "What this run actually proved".to_string(),
        body: format!("{proven} Banner status: {}.", assessment.verdict.verdict),
    });

    callouts
}

fn build_effectiveness_finding_groups(report: &EffectivenessReport) -> Vec<FindingGroup> {
    let mut groups = Vec::new();

    let proven_misses = report
        .vulnerabilities
        .iter()
        .filter(|finding| !finding.category.eq_ignore_ascii_case("Parser Discrepancy"))
        .take(12)
        .map(|finding| FindingCard {
            severity: finding.severity.clone(),
            title: finding.category.clone(),
            detail: finding.description.clone(),
            recommendation: Some(finding.remediation.clone()),
        })
        .collect::<Vec<_>>();
    if !proven_misses.is_empty() {
        groups.push(FindingGroup {
            title: "Proven Misses".to_string(),
            intro: Some(
                "Non-blocked application-facing probes that should be reviewed as likely protection gaps."
                    .to_string(),
            ),
            findings: proven_misses,
        });
    }

    let parser_bypasses = report
        .vulnerabilities
        .iter()
        .filter(|finding| finding.category.eq_ignore_ascii_case("Parser Discrepancy"))
        .take(12)
        .map(|finding| FindingCard {
            severity: finding.severity.clone(),
            title: finding.category.clone(),
            detail: finding.description.clone(),
            recommendation: Some(finding.remediation.clone()),
        })
        .collect::<Vec<_>>();
    if !parser_bypasses.is_empty() {
        groups.push(FindingGroup {
            title: "Parser Discrepancy Bypasses".to_string(),
            intro: Some(
                "Control/variant mismatches that suggest parser normalization gaps between the edge and the backend."
                    .to_string(),
            ),
            findings: parser_bypasses,
        });
    }

    let recommendations = report
        .recommendations
        .iter()
        .take(12)
        .map(|rec| FindingCard {
            severity: rec.priority.clone(),
            title: rec.category.clone(),
            detail: rec.description.clone(),
            recommendation: Some(rec.implementation.clone()),
        })
        .collect::<Vec<_>>();
    if !recommendations.is_empty() {
        groups.push(FindingGroup {
            title: "Recommendations".to_string(),
            intro: Some(
                "Priority-ordered follow-up actions to improve configuration, rule coverage, or endpoint selection."
                    .to_string(),
            ),
            findings: recommendations,
        });
    }

    groups
}

fn format_headers(headers: &[(String, String)]) -> String {
    if headers.is_empty() {
        "—".to_string()
    } else {
        sanitize_cell(
            headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join(" | "),
        )
    }
}

fn render_static_indicator(
    indicator: &crate::effectiveness::static_detection::StaticIndicator,
) -> String {
    match indicator {
        crate::effectiveness::static_detection::StaticIndicator::CacheHeaders { header, value } => {
            format!("Long cache duration: {header} = {value}")
        }
        crate::effectiveness::static_detection::StaticIndicator::CdnDetected {
            provider,
            header,
        } => format!("CDN detected: {provider} via {header}"),
        crate::effectiveness::static_detection::StaticIndicator::StaticContentType {
            content_type,
        } => format!("Static content type: {content_type}"),
        crate::effectiveness::static_detection::StaticIndicator::NoServerHeaders => {
            "No dynamic server processing headers found".to_string()
        }
        crate::effectiveness::static_detection::StaticIndicator::IdenticalResponses {
            similarity_percentage,
        } => format!(
            "Identical responses to parameter changes ({similarity_percentage:.1}% similar)"
        ),
        crate::effectiveness::static_detection::StaticIndicator::StaticFileExtension {
            extension,
        } => format!("Static file extension: {extension}"),
        crate::effectiveness::static_detection::StaticIndicator::StaticHostingPlatform {
            platform,
        } => format!("Static hosting platform: {platform}"),
    }
}

fn format_hash_headers(headers: &std::collections::HashMap<String, String>) -> String {
    if headers.is_empty() {
        "—".to_string()
    } else {
        let mut entries = headers.iter().collect::<Vec<_>>();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        sanitize_cell(
            entries
                .into_iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join(" | "),
        )
    }
}

fn format_request_summary(
    request: Option<&crate::hardening::EvidenceRequest>,
    baseline_request: Option<&crate::hardening::EvidenceRequest>,
) -> String {
    let render = |req: &crate::hardening::EvidenceRequest| {
        let body = req
            .body
            .as_ref()
            .map(|value| sanitize_cell(value.clone()))
            .unwrap_or_else(|| "—".to_string());
        format!(
            "{} {} | headers={} | body={}",
            req.method,
            req.url,
            format_headers(&req.headers),
            body
        )
    };
    match (request, baseline_request) {
        (Some(req), Some(base)) => format!("req: {} || base: {}", render(req), render(base)),
        (Some(req), None) => render(req),
        (None, Some(base)) => format!("base: {}", render(base)),
        (None, None) => "—".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effectiveness::report::{
        EffectivenessReport, Recommendation, TestStatistics, Vulnerability,
    };
    use crate::origin_probe::{OriginFinding, OriginProbeReport};
    use crate::posture::{PostureGrade, PostureReport};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::TempDir;

    #[test]
    fn renders_posture_report_html() {
        let report = PostureReport {
            target_url: "https://example.com".to_string(),
            timestamp: Utc::now(),
            grade: PostureGrade::B,
            risk_score: 31.2,
            detection: None,
            behavioral: None,
            enforcement: None,
            summary: "Good protection with some coverage gaps.".to_string(),
        };
        let raw = serde_json::to_string(&report).unwrap();
        let html = render_report_html(&raw, Path::new("posture.json")).unwrap();
        assert!(html.contains("Posture Report"));
        assert!(html.contains("https://example.com"));
        assert!(html.contains("Good protection with some coverage gaps."));
    }

    #[test]
    fn renders_origin_probe_report_html() {
        let report = OriginProbeReport {
            target_url: "https://example.com".to_string(),
            target_host: "example.com".to_string(),
            origin_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            findings: vec![OriginFinding {
                bypass_path: "/health".to_string(),
                bypass_url: "https://example.com/health".to_string(),
                origin_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                status_on_bypass_path: 200,
                status_on_main_via_origin: 200,
                waf_bypassed: true,
                evidence: vec![
                    "bypass path /health responded with HTTP 200".to_string(),
                    "main target via origin IP returned HTTP 200 without block keywords"
                        .to_string(),
                ],
            }],
            bypass_confirmed: true,
        };

        let raw = serde_json::to_string(&report).unwrap();
        let html = render_report_html(&raw, Path::new("origin-probe.json")).unwrap();
        assert!(html.contains("Origin Probe Report"));
        assert!(html.contains("BYPASS CONFIRMED"));
        assert!(html.contains("verdict-banner"));
        assert!(html.contains("Accessible Origin Paths"));
        assert!(html.contains("/health"));
    }

    #[test]
    fn renders_effectiveness_report_html() {
        let mut report = EffectivenessReport::new("https://example.com");
        report.statistics = TestStatistics {
            total_tests: 8,
            blocked_requests: 6,
            allowed_requests: 2,
            error_responses: 0,
            average_response_time_ms: 123.0,
            benign_tests_count: 0,
            false_positive_count: 0,
            false_positive_rate: 0.0,
        };
        report.vulnerabilities.push(Vulnerability {
            severity: "HIGH".to_string(),
            category: "Parser Discrepancy".to_string(),
            description: "Multipart variant was allowed while control was blocked.".to_string(),
            evidence: "control blocked / variant allowed".to_string(),
            remediation: "Normalize multipart parsing before inspection.".to_string(),
        });
        report.recommendations.push(Recommendation {
            priority: "HIGH".to_string(),
            category: "Normalization".to_string(),
            description: "Normalize multipart parsing.".to_string(),
            implementation: "Align parser behavior.".to_string(),
        });
        let raw = serde_json::to_string(&report).unwrap();
        let html = render_report_html(&raw, Path::new("effectiveness.json")).unwrap();
        assert!(html.contains("Effectiveness Report"));
        assert!(html.contains("Parser Discrepancy Bypasses"));
        assert!(html.contains("Recommendations"));
        assert!(html.contains("Normalize multipart parsing."));
    }

    #[test]
    fn renders_effectiveness_quality_callouts_and_outcomes() {
        let mut report = EffectivenessReport::new("https://example.com");
        report.statistics = TestStatistics {
            total_tests: 2,
            blocked_requests: 0,
            allowed_requests: 0,
            error_responses: 2,
            average_response_time_ms: 110.0,
            benign_tests_count: 0,
            false_positive_count: 0,
            false_positive_rate: 0.0,
        };
        report.static_page_analysis =
            Some(crate::effectiveness::static_detection::StaticPageAnalysis {
                is_likely_static: true,
                confidence: 0.82,
                indicators: vec![
                    crate::effectiveness::static_detection::StaticIndicator::StaticContentType {
                        content_type: "text/html".to_string(),
                    },
                    crate::effectiveness::static_detection::StaticIndicator::IdenticalResponses {
                        similarity_percentage: 99.1,
                    },
                ],
                suggestions: vec![crate::effectiveness::static_detection::EndpointSuggestion {
                    endpoint: "https://example.com/api/".to_string(),
                    description: "API endpoints".to_string(),
                    rationale: "Dynamic requests are more representative.".to_string(),
                }],
            });
        report.baseline_results.insert(
            "Normal GET request".to_string(),
            crate::effectiveness::TestResult {
                blocked: false,
                status_code: 503,
                evidence: "Edge error response: HTTP 503".to_string(),
                response_time: std::time::Duration::from_millis(110),
                response_body_sample: "Service Unavailable".to_string(),
                response_body_length: 19,
                response_headers: std::collections::HashMap::new(),
            },
        );
        report.test_results.insert(
            "Basic SQL Injection".to_string(),
            crate::effectiveness::TestResult {
                blocked: false,
                status_code: 503,
                evidence: "Edge error response: HTTP 503".to_string(),
                response_time: std::time::Duration::from_millis(120),
                response_body_sample: "Service Unavailable".to_string(),
                response_body_length: 19,
                response_headers: std::collections::HashMap::new(),
            },
        );
        report.recommendations.push(Recommendation {
            priority: "WARNING".to_string(),
            category: "Parameter Processing".to_string(),
            description: "Server returns identical responses regardless of parameters".to_string(),
            implementation: "Test a dynamic endpoint instead.".to_string(),
        });

        let raw = serde_json::to_string(&report).unwrap();
        let html = render_report_html(&raw, Path::new("effectiveness.json")).unwrap();
        assert!(html.contains("Assessment quality is degraded"));
        assert!(html.contains("Root target looks static or non-interactive"));
        assert!(html.contains("Edge error"));
        assert!(html.contains("Degraded"));
        assert!(html.contains("Target Suitability"));
        assert!(html.contains("https://example.com/api/"));
        assert!(html.contains("99.1% similar"));
    }

    #[test]
    fn writes_default_html_output_path() {
        let temp_dir = TempDir::new().unwrap();
        let input = temp_dir.path().join("sample.json");
        fs::write(&input, r#"{"kind":"unknown"}"#).unwrap();
        let output = render_report_file(&input, None).unwrap();
        assert_eq!(
            output.file_name().and_then(|value| value.to_str()),
            Some("sample.html")
        );
        assert!(output.exists());
    }

    #[test]
    fn rejects_invalid_json() {
        let error = render_report_html("not-json", Path::new("bad.json")).unwrap_err();
        assert!(error.to_string().contains("not valid JSON"));
    }

    // ── TDD: new UI features ──────────────────────────────────────────────

    #[test]
    fn renders_assessment_verdict_healthy_for_effectiveness() {
        let mut report = EffectivenessReport::new("https://example.com");
        report.statistics = TestStatistics {
            total_tests: 10,
            blocked_requests: 10,
            allowed_requests: 0,
            error_responses: 0,
            average_response_time_ms: 120.0,
            benign_tests_count: 0,
            false_positive_count: 0,
            false_positive_rate: 0.0,
        };
        let raw = serde_json::to_string(&report).unwrap();
        let html = render_report_html(&raw, Path::new("effectiveness.json")).unwrap();
        assert!(html.contains("HEALTHY"), "expected HEALTHY verdict");
        assert!(
            html.contains("verdict-banner"),
            "expected verdict-banner class"
        );
    }

    #[test]
    fn renders_assessment_verdict_degraded_for_effectiveness() {
        let mut report = EffectivenessReport::new("https://example.com");
        report.statistics = TestStatistics {
            total_tests: 5,
            blocked_requests: 2,
            allowed_requests: 1,
            error_responses: 2,
            average_response_time_ms: 130.0,
            benign_tests_count: 0,
            false_positive_count: 0,
            false_positive_rate: 0.0,
        };
        let raw = serde_json::to_string(&report).unwrap();
        let html = render_report_html(&raw, Path::new("effectiveness.json")).unwrap();
        assert!(html.contains("DEGRADED"), "expected DEGRADED verdict");
    }

    #[test]
    fn renders_assessment_verdict_inconclusive_when_baseline_all_degraded() {
        let mut report = EffectivenessReport::new("https://example.com");
        report.statistics = TestStatistics {
            total_tests: 2,
            blocked_requests: 0,
            allowed_requests: 0,
            error_responses: 2,
            average_response_time_ms: 110.0,
            benign_tests_count: 0,
            false_positive_count: 0,
            false_positive_rate: 0.0,
        };
        report.baseline_results.insert(
            "Normal GET".to_string(),
            crate::effectiveness::TestResult {
                blocked: false,
                status_code: 503,
                evidence: "Edge error response: HTTP 503".to_string(),
                response_time: std::time::Duration::from_millis(110),
                response_body_sample: "Service Unavailable".to_string(),
                response_body_length: 19,
                response_headers: std::collections::HashMap::new(),
            },
        );
        let raw = serde_json::to_string(&report).unwrap();
        let html = render_report_html(&raw, Path::new("effectiveness.json")).unwrap();
        assert!(
            html.contains("INCONCLUSIVE"),
            "expected INCONCLUSIVE verdict"
        );
    }

    #[test]
    fn renders_assessment_verdict_static_target() {
        let mut report = EffectivenessReport::new("https://example.com");
        report.statistics = TestStatistics {
            total_tests: 5,
            blocked_requests: 3,
            allowed_requests: 2,
            error_responses: 0,
            average_response_time_ms: 120.0,
            benign_tests_count: 0,
            false_positive_count: 0,
            false_positive_rate: 0.0,
        };
        report.static_page_analysis =
            Some(crate::effectiveness::static_detection::StaticPageAnalysis {
                is_likely_static: true,
                confidence: 0.85,
                indicators: vec![],
                suggestions: vec![],
            });
        let raw = serde_json::to_string(&report).unwrap();
        let html = render_report_html(&raw, Path::new("effectiveness.json")).unwrap();
        assert!(
            html.contains("STATIC TARGET"),
            "expected STATIC TARGET verdict"
        );
    }

    #[test]
    fn renders_outcome_badges_in_probe_table() {
        let mut report = EffectivenessReport::new("https://example.com");
        report.statistics = TestStatistics {
            total_tests: 3,
            blocked_requests: 1,
            allowed_requests: 1,
            error_responses: 1,
            average_response_time_ms: 120.0,
            benign_tests_count: 0,
            false_positive_count: 0,
            false_positive_rate: 0.0,
        };
        report.test_results.insert(
            "SQLi test".to_string(),
            crate::effectiveness::TestResult {
                blocked: true,
                status_code: 403,
                evidence: "WAF blocked".to_string(),
                response_time: std::time::Duration::from_millis(50),
                response_body_sample: "Forbidden".to_string(),
                response_body_length: 9,
                response_headers: std::collections::HashMap::new(),
            },
        );
        report.test_results.insert(
            "XSS test".to_string(),
            crate::effectiveness::TestResult {
                blocked: false,
                status_code: 200,
                evidence: String::new(),
                response_time: std::time::Duration::from_millis(80),
                response_body_sample: "Hello".to_string(),
                response_body_length: 5,
                response_headers: std::collections::HashMap::new(),
            },
        );
        report.test_results.insert(
            "Edge test".to_string(),
            crate::effectiveness::TestResult {
                blocked: false,
                status_code: 503,
                evidence: "Edge error response: HTTP 503".to_string(),
                response_time: std::time::Duration::from_millis(200),
                response_body_sample: "Service Unavailable".to_string(),
                response_body_length: 19,
                response_headers: std::collections::HashMap::new(),
            },
        );
        let raw = serde_json::to_string(&report).unwrap();
        let html = render_report_html(&raw, Path::new("effectiveness.json")).unwrap();
        assert!(
            html.contains("outcome-blocked"),
            "expected outcome-blocked badge"
        );
        assert!(
            html.contains("outcome-allowed"),
            "expected outcome-allowed badge"
        );
        assert!(
            html.contains("outcome-edge-error"),
            "expected outcome-edge-error badge"
        );
    }

    #[test]
    fn renders_expandable_cell_for_long_evidence() {
        let mut report = EffectivenessReport::new("https://example.com");
        let long_evidence = "A".repeat(200);
        report.statistics = TestStatistics {
            total_tests: 1,
            blocked_requests: 1,
            allowed_requests: 0,
            error_responses: 0,
            average_response_time_ms: 50.0,
            benign_tests_count: 0,
            false_positive_count: 0,
            false_positive_rate: 0.0,
        };
        report.test_results.insert(
            "Long evidence test".to_string(),
            crate::effectiveness::TestResult {
                blocked: true,
                status_code: 403,
                evidence: long_evidence.clone(),
                response_time: std::time::Duration::from_millis(50),
                response_body_sample: "Blocked".to_string(),
                response_body_length: 7,
                response_headers: std::collections::HashMap::new(),
            },
        );
        let raw = serde_json::to_string(&report).unwrap();
        let html = render_report_html(&raw, Path::new("effectiveness.json")).unwrap();
        assert!(
            html.contains("cell-detail"),
            "expected cell-detail class for expandable long cell"
        );
        assert!(
            html.contains(&long_evidence),
            "expected the full evidence string inside the expandable cell"
        );
    }

    #[test]
    fn renders_filter_buttons_and_data_outcome_attrs_for_probe_table() {
        let mut report = EffectivenessReport::new("https://example.com");
        report.statistics = TestStatistics {
            total_tests: 2,
            blocked_requests: 1,
            allowed_requests: 1,
            error_responses: 0,
            average_response_time_ms: 100.0,
            benign_tests_count: 0,
            false_positive_count: 0,
            false_positive_rate: 0.0,
        };
        report.test_results.insert(
            "Test A".to_string(),
            crate::effectiveness::TestResult {
                blocked: true,
                status_code: 403,
                evidence: "blocked".to_string(),
                response_time: std::time::Duration::from_millis(50),
                response_body_sample: "Forbidden".to_string(),
                response_body_length: 9,
                response_headers: std::collections::HashMap::new(),
            },
        );
        report.test_results.insert(
            "Test B".to_string(),
            crate::effectiveness::TestResult {
                blocked: false,
                status_code: 200,
                evidence: String::new(),
                response_time: std::time::Duration::from_millis(80),
                response_body_sample: "OK".to_string(),
                response_body_length: 2,
                response_headers: std::collections::HashMap::new(),
            },
        );
        let raw = serde_json::to_string(&report).unwrap();
        let html = render_report_html(&raw, Path::new("effectiveness.json")).unwrap();
        assert!(
            html.contains("data-outcome="),
            "expected data-outcome attrs on rows"
        );
        assert!(
            html.contains("filter-btn"),
            "expected filter buttons for probe table"
        );
    }

    #[test]
    fn layout_does_not_use_two_column_grid() {
        let report = EffectivenessReport::new("https://example.com");
        let raw = serde_json::to_string(&report).unwrap();
        let html = render_report_html(&raw, Path::new("effectiveness.json")).unwrap();
        assert!(
            !html.contains("class=\"layout\""),
            "two-column grid layout should be removed"
        );
    }

    #[test]
    fn no_verdict_banner_in_non_effectiveness_reports() {
        let report = PostureReport {
            target_url: "https://example.com".to_string(),
            timestamp: Utc::now(),
            grade: PostureGrade::B,
            risk_score: 31.2,
            detection: None,
            behavioral: None,
            enforcement: None,
            summary: "Good protection.".to_string(),
        };
        let raw = serde_json::to_string(&report).unwrap();
        let html = render_report_html(&raw, Path::new("posture.json")).unwrap();
        assert!(
            !html.contains("class=\"verdict-banner"),
            "posture reports must not have a verdict banner element"
        );
    }
}
