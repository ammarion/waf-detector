//! Deterministic public surface discovery for effectiveness testing.
//!
//! This module inventories likely public-facing endpoints and classifies them so
//! effectiveness testing can reason about path-scoped protection gaps rather than
//! only the originally supplied URL.

use anyhow::Result;
use std::collections::{HashMap, HashSet};

use super::report::{
    DiscoveredEndpoint, EndpointClassification, SurfaceDiscoverySummary, SurfaceFinding,
};
use super::static_detection::{calculate_similarity, EndpointSuggestion, StaticPageAnalysis};
use super::TestResult;

const CURATED_PUBLIC_PATHS: &[&str] = &[
    "/api/",
    "/api/v1/",
    "/login",
    "/search",
    "/admin",
    "/health",
    "/status",
    "/metrics",
    "/graphql",
    "/openapi.json",
    "/robots.txt",
    "/.well-known/",
    "/.auth/login/aad",
    "/api/health",
];

pub fn build_candidate_paths(
    target_url: &str,
    static_analysis: Option<&StaticPageAnalysis>,
) -> Result<Vec<String>> {
    let normalized = normalize_target_url(target_url)?;
    let parsed = url::Url::parse(&normalized)?;
    let current_path = parsed.path().to_string();
    let base_origin = format!(
        "{}://{}",
        parsed.scheme(),
        parsed.host_str().unwrap_or_default()
    );

    let mut seen = HashSet::new();
    let mut paths = Vec::new();

    if current_path.is_empty() || current_path == "/" {
        push_path("/", &mut seen, &mut paths);
    } else {
        push_path(&current_path, &mut seen, &mut paths);
    }

    for path in CURATED_PUBLIC_PATHS {
        push_path(path, &mut seen, &mut paths);
    }

    if let Some(analysis) = static_analysis {
        for suggestion in &analysis.suggestions {
            if let Some(path) = suggestion_path(suggestion, &base_origin) {
                push_path(&path, &mut seen, &mut paths);
            }
        }
    }

    Ok(paths)
}

pub fn classify_endpoint(
    path: &str,
    full_url: &str,
    baseline: &TestResult,
    probe: Option<&TestResult>,
) -> DiscoveredEndpoint {
    let path_lower = path.to_ascii_lowercase();
    let body_lower = baseline.response_body_sample.to_ascii_lowercase();
    let content_type = baseline.response_headers.get("content-type").cloned();
    let auth_required = baseline.status_code == 401
        || baseline.response_headers.contains_key("www-authenticate")
        || (baseline.status_code == 403
            && (body_lower.contains("login")
                || body_lower.contains("sign in")
                || body_lower.contains("authenticate")));
    let challenge_hint = baseline.response_headers.contains_key("cf-mitigated")
        || body_lower.contains("captcha")
        || body_lower.contains("challenge");
    let blocked_or_challenged = baseline.status_code != 0 && (baseline.blocked || challenge_hint);

    let query_responsive = probe.is_some_and(|candidate| {
        if candidate.status_code == 0 || baseline.status_code == 0 {
            return false;
        }
        let similarity = calculate_similarity(
            &baseline.response_body_sample,
            &candidate.response_body_sample,
        );
        let base_len = baseline.response_body_length as f64;
        let probe_len = candidate.response_body_length as f64;
        let len_diff_ratio = if base_len > 0.0 {
            ((base_len - probe_len).abs() / base_len).min(1.0)
        } else {
            0.0
        };

        candidate.status_code != baseline.status_code || similarity < 0.95 || len_diff_ratio >= 0.05
    });

    let operational_path = is_operational_path(&path_lower);
    let static_hint = is_static_endpoint(&path_lower, content_type.as_deref(), query_responsive);

    let classification = if baseline.status_code == 0 {
        EndpointClassification::Unknown
    } else if auth_required {
        EndpointClassification::Authenticated
    } else if blocked_or_challenged {
        EndpointClassification::Protected
    } else if operational_path {
        EndpointClassification::Operational
    } else if query_responsive {
        EndpointClassification::Interactive
    } else if static_hint {
        EndpointClassification::Static
    } else {
        EndpointClassification::Unknown
    };

    let mut evidence = Vec::new();
    evidence.push(format!("status={}", baseline.status_code));
    if let Some(content_type) = &content_type {
        evidence.push(format!("content-type={content_type}"));
    }
    if auth_required {
        evidence.push("auth boundary".to_string());
    }
    if blocked_or_challenged {
        evidence.push("blocked or challenged".to_string());
    }
    if query_responsive {
        evidence.push("query-responsive".to_string());
    }
    if operational_path {
        evidence.push("operational-path".to_string());
    }

    DiscoveredEndpoint {
        path: path.to_string(),
        url: full_url.to_string(),
        status_code: baseline.status_code,
        content_type,
        classification,
        auth_required,
        blocked_or_challenged,
        query_responsive,
        evidence,
    }
}

pub fn summarize_discovery(
    target_url: &str,
    endpoints: Vec<DiscoveredEndpoint>,
    root_static: bool,
) -> SurfaceDiscoverySummary {
    let mut classification_counts = HashMap::new();
    let mut reachable_endpoints = 0usize;
    let mut public_endpoints = 0usize;
    let mut findings = Vec::new();

    for endpoint in &endpoints {
        *classification_counts
            .entry(endpoint.classification.to_string())
            .or_insert(0usize) += 1;

        if endpoint.status_code != 0 {
            reachable_endpoints += 1;
        }

        if endpoint.status_code != 0
            && !endpoint.auth_required
            && !endpoint.blocked_or_challenged
            && (200..400).contains(&endpoint.status_code)
        {
            public_endpoints += 1;
        }

        if is_operational_path(&endpoint.path.to_ascii_lowercase())
            && endpoint.status_code != 0
            && !endpoint.auth_required
            && !endpoint.blocked_or_challenged
            && (200..400).contains(&endpoint.status_code)
        {
            findings.push(SurfaceFinding {
                severity: "MEDIUM".to_string(),
                category: "Public Operational Endpoint".to_string(),
                endpoint: endpoint.path.clone(),
                description: format!(
                    "Operational endpoint {} is publicly reachable",
                    endpoint.path
                ),
                evidence: endpoint.evidence.join(", "),
            });
        }

        if is_adminish_path(&endpoint.path.to_ascii_lowercase())
            && endpoint.status_code != 0
            && !endpoint.auth_required
            && !endpoint.blocked_or_challenged
            && (200..400).contains(&endpoint.status_code)
        {
            findings.push(SurfaceFinding {
                severity: "HIGH".to_string(),
                category: "Administrative Surface".to_string(),
                endpoint: endpoint.path.clone(),
                description: format!(
                    "Administrative-looking endpoint {} is publicly reachable",
                    endpoint.path
                ),
                evidence: endpoint.evidence.join(", "),
            });
        }

        if is_api_surface_path(&endpoint.path.to_ascii_lowercase())
            && endpoint.status_code != 0
            && (200..500).contains(&endpoint.status_code)
        {
            findings.push(SurfaceFinding {
                severity: "LOW".to_string(),
                category: "Public API Surface".to_string(),
                endpoint: endpoint.path.clone(),
                description: format!(
                    "Public-facing API or schema-related endpoint {} responded during discovery",
                    endpoint.path
                ),
                evidence: endpoint.evidence.join(", "),
            });
        }
    }

    let current_path = url::Url::parse(
        &normalize_target_url(target_url).unwrap_or_else(|_| target_url.to_string()),
    )
    .ok()
    .map(|url| url.path().to_string())
    .filter(|path| !path.is_empty())
    .unwrap_or_else(|| "/".to_string());

    let preferred_endpoint = endpoints
        .iter()
        .find(|endpoint| {
            endpoint.classification == EndpointClassification::Interactive
                && endpoint.status_code != 0
                && !endpoint.auth_required
                && !endpoint.blocked_or_challenged
        })
        .or_else(|| {
            endpoints.iter().find(|endpoint| {
                endpoint.classification == EndpointClassification::Operational
                    && endpoint.status_code != 0
                    && !endpoint.auth_required
                    && !endpoint.blocked_or_challenged
            })
        })
        .map(|endpoint| endpoint.url.clone());

    if root_static {
        if let Some(preferred) = &preferred_endpoint {
            if let Ok(preferred_url) = url::Url::parse(preferred) {
                if preferred_url.path() != current_path {
                    findings.push(SurfaceFinding {
                        severity: "LOW".to_string(),
                        category: "Static Root, Dynamic Alternate Path".to_string(),
                        endpoint: preferred_url.path().to_string(),
                        description:
                            "The supplied target appears static, but a more dynamic public-facing path was discovered"
                                .to_string(),
                        evidence: format!("preferred_endpoint={preferred}"),
                    });
                }
            }
        }
    }

    SurfaceDiscoverySummary {
        probed_endpoints: endpoints.len(),
        reachable_endpoints,
        public_endpoints,
        preferred_endpoint,
        classification_counts,
        endpoints,
        findings,
    }
}

fn normalize_target_url(target_url: &str) -> Result<String> {
    if target_url.starts_with("http://") || target_url.starts_with("https://") {
        Ok(target_url.to_string())
    } else {
        Ok(format!("https://{target_url}"))
    }
}

fn push_path(path: &str, seen: &mut HashSet<String>, paths: &mut Vec<String>) {
    let normalized = if path.is_empty() { "/" } else { path };
    if seen.insert(normalized.to_string()) {
        paths.push(normalized.to_string());
    }
}

fn suggestion_path(suggestion: &EndpointSuggestion, base_origin: &str) -> Option<String> {
    if suggestion.endpoint == "Consider testing the origin server directly" {
        return None;
    }

    if let Ok(url) = url::Url::parse(&suggestion.endpoint) {
        let suggestion_origin =
            format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
        if suggestion_origin == base_origin {
            return Some(url.path().to_string());
        }
    }

    None
}

fn is_operational_path(path: &str) -> bool {
    [
        "/health",
        "/status",
        "/metrics",
        "/ready",
        "/readyz",
        "/livez",
        "/api/health",
        "/actuator",
    ]
    .iter()
    .any(|needle| path.contains(needle))
}

fn is_adminish_path(path: &str) -> bool {
    ["/admin", "/manage", "/console", "/dashboard"]
        .iter()
        .any(|needle| path.contains(needle))
}

fn is_api_surface_path(path: &str) -> bool {
    ["/api", "/graphql", "openapi", "swagger", "/.well-known"]
        .iter()
        .any(|needle| path.contains(needle))
}

fn is_static_endpoint(path: &str, content_type: Option<&str>, query_responsive: bool) -> bool {
    if query_responsive {
        return false;
    }

    if let Some(content_type) = content_type {
        let content_type = content_type.to_ascii_lowercase();
        if content_type.starts_with("text/html")
            || content_type.starts_with("text/plain")
            || content_type.starts_with("text/css")
            || content_type.starts_with("application/javascript")
            || content_type.starts_with("text/javascript")
            || content_type.starts_with("image/")
        {
            return true;
        }
    }

    path == "/"
        || path.ends_with(".txt")
        || path.ends_with(".html")
        || path.ends_with(".xml")
        || path.ends_with(".json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;

    fn test_result(status_code: u16, body: &str, headers: &[(&str, &str)]) -> TestResult {
        let mut response_headers = HashMap::new();
        for (name, value) in headers {
            response_headers.insert((*name).to_string(), (*value).to_string());
        }
        TestResult {
            blocked: status_code == 403,
            status_code,
            evidence: String::new(),
            response_time: Duration::from_millis(1),
            response_body_sample: body.to_string(),
            response_body_length: body.len(),
            response_headers,
        }
    }

    #[test]
    fn test_build_candidate_paths_contains_curated_and_suggested_paths() {
        let analysis = StaticPageAnalysis {
            is_likely_static: true,
            confidence: 0.9,
            indicators: Vec::new(),
            suggestions: vec![EndpointSuggestion {
                endpoint: "https://example.com/contact".to_string(),
                description: "Contact".to_string(),
                rationale: "Test".to_string(),
            }],
        };

        let paths = build_candidate_paths("https://example.com/", Some(&analysis)).unwrap();
        assert!(paths.contains(&"/".to_string()));
        assert!(paths.contains(&"/health".to_string()));
        assert!(paths.contains(&"/graphql".to_string()));
        assert!(paths.contains(&"/contact".to_string()));
    }

    #[test]
    fn test_classify_endpoint_detects_operational_public_path() {
        let baseline = test_result(200, "ok", &[("content-type", "text/plain")]);
        let probe = test_result(200, "ok", &[("content-type", "text/plain")]);
        let endpoint = classify_endpoint(
            "/health",
            "https://example.com/health",
            &baseline,
            Some(&probe),
        );
        assert_eq!(endpoint.classification, EndpointClassification::Operational);
        assert!(!endpoint.auth_required);
    }

    #[test]
    fn test_classify_endpoint_detects_interactive_path() {
        let baseline = test_result(
            200,
            "{\"ok\":true}",
            &[("content-type", "application/json")],
        );
        let probe = test_result(
            200,
            "{\"ok\":true,\"echo\":\"1\"}",
            &[("content-type", "application/json")],
        );
        let endpoint =
            classify_endpoint("/api/", "https://example.com/api/", &baseline, Some(&probe));
        assert_eq!(endpoint.classification, EndpointClassification::Interactive);
        assert!(endpoint.query_responsive);
    }

    #[test]
    fn test_summarize_discovery_prefers_interactive_endpoint_and_flags_static_root() {
        let endpoints = vec![
            DiscoveredEndpoint {
                path: "/".to_string(),
                url: "https://example.com/".to_string(),
                status_code: 200,
                content_type: Some("text/html".to_string()),
                classification: EndpointClassification::Static,
                auth_required: false,
                blocked_or_challenged: false,
                query_responsive: false,
                evidence: vec!["status=200".to_string()],
            },
            DiscoveredEndpoint {
                path: "/api/".to_string(),
                url: "https://example.com/api/".to_string(),
                status_code: 200,
                content_type: Some("application/json".to_string()),
                classification: EndpointClassification::Interactive,
                auth_required: false,
                blocked_or_challenged: false,
                query_responsive: true,
                evidence: vec!["status=200".to_string(), "query-responsive".to_string()],
            },
        ];

        let summary = summarize_discovery("https://example.com/", endpoints, true);
        assert_eq!(
            summary.preferred_endpoint,
            Some("https://example.com/api/".to_string())
        );
        assert!(summary
            .findings
            .iter()
            .any(|finding| { finding.category == "Static Root, Dynamic Alternate Path" }));
    }
}
