mod compiler;
mod config;
mod frontend;
mod har;
mod live;
mod openapi;
mod planner;

pub use compiler::{CompilerInputs, SurfaceMapCompiler};
pub use config::{
    AuthHeaderValue, AuthProfile, ManifestRouteOverride, ResolvedAuthProfile, RouteAuthHeaders,
    WafHardeningManifest, AUTH_PROFILE_ENV,
};
pub use live::{LiveSurfaceVerifier, SurfaceVerificationMode};
pub use planner::{PlannedRoute, RouteAwarePlan, RouteAwarePlanner};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    FrontendRepo,
    OpenApi,
    Har,
    Manifest,
    LiveVerification,
}

impl DiscoverySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FrontendRepo => "frontend_repo",
            Self::OpenApi => "openapi",
            Self::Har => "har",
            Self::Manifest => "manifest",
            Self::LiveVerification => "live_verification",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryInput {
    pub source: DiscoverySource,
    pub location: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthClass {
    None,
    Optional,
    Required,
    #[default]
    Unknown,
}

impl AuthClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Optional => "optional",
            Self::Required => "required",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParserTraits {
    #[serde(default)]
    pub json: bool,
    #[serde(default)]
    pub form: bool,
    #[serde(default)]
    pub multipart: bool,
    #[serde(default)]
    pub graphql: bool,
    #[serde(default)]
    pub query: bool,
    #[serde(default)]
    pub header_sensitive: bool,
    #[serde(default)]
    pub same_origin_api: bool,
    #[serde(default)]
    pub dynamic_segments: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum RoutePriority {
    Critical,
    High,
    #[default]
    Medium,
    Low,
}

impl RoutePriority {
    pub fn rank(self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SampleRequest {
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveVerification {
    pub method: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub reachable: bool,
    pub auth_class: AuthClass,
    pub observed_action: String,
    pub confidence_delta: f64,
    pub verified_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceEndpoint {
    pub endpoint_id: String,
    pub path_template: String,
    pub execution_path: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub content_types: Vec<String>,
    pub auth_class: AuthClass,
    pub parser_traits: ParserTraits,
    pub confidence: f64,
    pub priority: RoutePriority,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub discovery_sources: Vec<DiscoverySource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_request: Option<SampleRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_verification: Option<LiveVerification>,
    #[serde(default)]
    pub excluded: bool,
}

impl SurfaceEndpoint {
    pub fn supports_get_like(&self) -> bool {
        self.methods
            .iter()
            .any(|method| matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS"))
    }

    pub fn is_static_like(&self) -> bool {
        let path = self.path_template.to_ascii_lowercase();
        path.starts_with("/_next/")
            || path.starts_with("/assets/")
            || path.starts_with("/static/")
            || path.ends_with(".js")
            || path.ends_with(".css")
            || path.ends_with(".png")
            || path.ends_with(".svg")
            || path.contains("/health")
            || path.contains("/status")
    }

    pub fn execution_url(&self, target_url: &str) -> anyhow::Result<String> {
        let mut url = url::Url::parse(target_url)
            .or_else(|_| url::Url::parse(&format!("https://{target_url}")))?;
        url.set_path(&self.execution_path);
        if let Some(sample) = &self.sample_request {
            url.set_query(sample.query.as_deref());
        } else {
            url.set_query(None);
        }
        Ok(url.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SurfaceMapSummary {
    pub total_endpoints: usize,
    pub route_aware_endpoints: usize,
    pub auth_required_endpoints: usize,
    pub unauthenticated_endpoints: usize,
    #[serde(default)]
    pub sources: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RefinedSurfaceMapStats {
    pub verified_endpoints: usize,
    pub selected_endpoints: usize,
    pub covered_endpoints: usize,
    pub partial_coverage_endpoints: usize,
    pub uncovered_auth_required_endpoints: usize,
    pub unresolved_parameterized_endpoints: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceMap {
    pub schema_version: String,
    pub target_base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_hint: Option<String>,
    #[serde(default)]
    pub inputs: Vec<DiscoveryInput>,
    #[serde(default)]
    pub endpoints: Vec<SurfaceEndpoint>,
    pub summary: SurfaceMapSummary,
}

impl Default for SurfaceMap {
    fn default() -> Self {
        Self {
            schema_version: "surface-map/v1".to_string(),
            target_base_url: String::new(),
            repo_origin: None,
            repo_ref: None,
            vendor_hint: None,
            inputs: Vec::new(),
            endpoints: Vec::new(),
            summary: SurfaceMapSummary::default(),
        }
    }
}

pub(crate) fn merge_string_lists(
    values: &mut Vec<String>,
    extra: impl IntoIterator<Item = String>,
) {
    for value in extra {
        if !values
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&value))
        {
            values.push(value);
        }
    }
    values.sort_by_key(|value| value.to_ascii_lowercase());
}

pub(crate) fn merge_discovery_sources(
    values: &mut Vec<DiscoverySource>,
    extra: impl IntoIterator<Item = DiscoverySource>,
) {
    for value in extra {
        if !values.contains(&value) {
            values.push(value);
        }
    }
    values.sort_by_key(|value| value.as_str().to_string());
}

pub(crate) fn stronger_auth_class(left: AuthClass, right: AuthClass) -> AuthClass {
    use AuthClass::{None, Optional, Required, Unknown};

    match (left, right) {
        (Required, _) | (_, Required) => Required,
        (Optional, _) | (_, Optional) => Optional,
        (Unknown, other) => other,
        (other, Unknown) => other,
        (None, None) => None,
    }
}

pub(crate) fn merge_parser_traits(left: &mut ParserTraits, right: &ParserTraits) {
    left.json |= right.json;
    left.form |= right.form;
    left.multipart |= right.multipart;
    left.graphql |= right.graphql;
    left.query |= right.query;
    left.header_sensitive |= right.header_sensitive;
    left.same_origin_api |= right.same_origin_api;
    left.dynamic_segments |= right.dynamic_segments;
}

pub(crate) fn infer_priority(
    path_template: &str,
    methods: &[String],
    tags: &[String],
    auth_class: AuthClass,
) -> RoutePriority {
    let path = path_template.to_ascii_lowercase();
    let tag_blob = tags.join(" ").to_ascii_lowercase();
    let is_mutation = methods
        .iter()
        .any(|method| matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE"));

    if path.contains("tokenize")
        || path.contains("detokenize")
        || path.contains("bulk")
        || path.contains("upload")
        || path.contains("graphql")
        || path.contains("admin")
        || tag_blob.contains("graphql")
    {
        return RoutePriority::Critical;
    }

    if path.contains("search")
        || path.contains("query")
        || path.contains("webhook")
        || tag_blob.contains("search")
        || is_mutation
        || auth_class == AuthClass::Required
    {
        return RoutePriority::High;
    }

    if path.contains("health")
        || path.contains("status")
        || path.starts_with("/assets/")
        || path.starts_with("/static/")
        || path.starts_with("/_next/")
    {
        return RoutePriority::Low;
    }

    RoutePriority::Medium
}

pub(crate) fn stronger_priority(left: RoutePriority, right: RoutePriority) -> RoutePriority {
    if left.rank() >= right.rank() {
        left
    } else {
        right
    }
}

pub(crate) fn materialize_path_template(path_template: &str) -> String {
    let mut output = String::with_capacity(path_template.len());
    let chars = path_template.chars().collect::<Vec<_>>();
    let mut index = 0usize;

    while index < chars.len() {
        match chars[index] {
            '{' => {
                while index < chars.len() && chars[index] != '}' {
                    index += 1;
                }
                if index < chars.len() {
                    index += 1;
                }
                output.push_str("sample");
            }
            ':' => {
                output.push_str("sample");
                index += 1;
                while index < chars.len()
                    && (chars[index].is_ascii_alphanumeric()
                        || matches!(chars[index], '_' | '-' | '$'))
                {
                    index += 1;
                }
            }
            ch => {
                output.push(ch);
                index += 1;
            }
        }
    }

    if output.is_empty() {
        "/".to_string()
    } else {
        output
    }
}

pub(crate) fn stable_endpoint_id(
    methods: &[String],
    path_template: &str,
    auth_class: AuthClass,
    content_types: &[String],
) -> String {
    use sha2::{Digest, Sha256};

    let mut method_list = methods.to_vec();
    method_list.sort();
    let mut content_list = content_types.to_vec();
    content_list.sort();
    let payload = format!(
        "{}|{}|{}|{}",
        method_list.join(","),
        path_template.to_ascii_lowercase(),
        auth_class.as_str(),
        content_list.join(",").to_ascii_lowercase()
    );
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    format!(
        "ep-{:016x}",
        u64::from_be_bytes(hasher.finalize()[..8].try_into().unwrap())
    )
}

pub(crate) fn summarize_surface_map(endpoints: &[SurfaceEndpoint]) -> SurfaceMapSummary {
    let mut summary = SurfaceMapSummary {
        total_endpoints: endpoints.len(),
        ..Default::default()
    };

    for endpoint in endpoints {
        if !endpoint.excluded {
            summary.route_aware_endpoints += 1;
        }

        match endpoint.auth_class {
            AuthClass::Required => summary.auth_required_endpoints += 1,
            AuthClass::None => summary.unauthenticated_endpoints += 1,
            _ => {}
        }

        for source in &endpoint.discovery_sources {
            *summary
                .sources
                .entry(source.as_str().to_string())
                .or_insert(0) += 1;
        }
    }

    summary
}

pub(crate) fn normalize_relative_or_absolute_path(
    raw: &str,
    target_base_url: &str,
) -> Option<(String, Option<String>)> {
    if raw.trim().is_empty() {
        return None;
    }

    if let Ok(parsed) = Url::parse(raw) {
        let path = if parsed.path().is_empty() {
            "/".to_string()
        } else {
            parsed.path().to_string()
        };
        return Some((path, parsed.query().map(|query| query.to_string())));
    }

    let base = Url::parse(target_base_url)
        .or_else(|_| Url::parse(&format!("https://{target_base_url}")))
        .ok()?;
    let joined = base.join(raw).ok()?;
    let path = if joined.path().is_empty() {
        "/".to_string()
    } else {
        joined.path().to_string()
    };
    Some((path, joined.query().map(|query| query.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_materialize_path_template_replaces_dynamic_segments() {
        assert_eq!(
            materialize_path_template("/api/tokens/{id}/versions/:version"),
            "/api/tokens/sample/versions/sample"
        );
    }

    #[test]
    fn test_stable_endpoint_id_is_deterministic() {
        let first = stable_endpoint_id(
            &["POST".to_string(), "GET".to_string()],
            "/api/tokenize",
            AuthClass::Required,
            &["application/json".to_string()],
        );
        let second = stable_endpoint_id(
            &["GET".to_string(), "POST".to_string()],
            "/api/tokenize",
            AuthClass::Required,
            &["application/json".to_string()],
        );
        assert_eq!(first, second);
    }

    #[test]
    fn test_normalize_relative_or_absolute_path() {
        let normalized = normalize_relative_or_absolute_path(
            "https://api.example.com/v1/tokenize?view=full",
            "https://app.example.com",
        )
        .unwrap();
        assert_eq!(normalized.0, "/v1/tokenize");
        assert_eq!(normalized.1.as_deref(), Some("view=full"));
    }
}
