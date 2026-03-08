use crate::surface::{AuthClass, ParserTraits, RoutePriority};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use url::Url;

pub const AUTH_PROFILE_ENV: &str = "WAF_DETECTOR_AUTH_PROFILE";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthHeaderValue {
    Plain(String),
    Inline {
        value: String,
    },
    EnvRef {
        env: String,
        #[serde(default)]
        default: Option<String>,
    },
}

impl AuthHeaderValue {
    fn resolve(&self) -> Option<String> {
        match self {
            Self::Plain(value) => Some(value.clone()),
            Self::Inline { value } => Some(value.clone()),
            Self::EnvRef { env, default } => std::env::var(env).ok().or_else(|| default.clone()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouteAuthHeaders {
    pub path_prefix: String,
    #[serde(default)]
    pub headers: HashMap<String, AuthHeaderValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthProfile {
    #[serde(default)]
    pub headers: HashMap<String, AuthHeaderValue>,
    #[serde(default)]
    pub route_headers: Vec<RouteAuthHeaders>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedRouteHeaders {
    path_prefix: String,
    headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedAuthProfile {
    global_headers: Vec<(String, String)>,
    route_headers: Vec<ResolvedRouteHeaders>,
}

impl ResolvedAuthProfile {
    pub fn from_profile(profile: AuthProfile) -> Self {
        let global_headers = resolve_headers(profile.headers);
        let mut route_headers = profile
            .route_headers
            .into_iter()
            .map(|entry| ResolvedRouteHeaders {
                path_prefix: normalize_path_prefix(&entry.path_prefix),
                headers: resolve_headers(entry.headers),
            })
            .filter(|entry| !entry.headers.is_empty())
            .collect::<Vec<_>>();
        route_headers.sort_by_key(|entry| entry.path_prefix.len());

        Self {
            global_headers,
            route_headers,
        }
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(path.as_ref())?;
        let profile = serde_yml::from_str::<AuthProfile>(&raw).map_err(|err| {
            anyhow!(
                "failed to parse auth profile {}: {err}",
                path.as_ref().display()
            )
        })?;
        Ok(Self::from_profile(profile))
    }

    pub fn from_env_path() -> Result<Option<Self>> {
        let Some(path) = std::env::var(AUTH_PROFILE_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return Ok(None);
        };

        Ok(Some(Self::from_path(path)?))
    }

    pub fn is_empty(&self) -> bool {
        self.global_headers.is_empty() && self.route_headers.is_empty()
    }

    pub fn headers_for_url(&self, url: &str) -> Vec<(String, String)> {
        let path = Url::parse(url)
            .ok()
            .map(|parsed| normalize_path_prefix(parsed.path()))
            .unwrap_or_else(|| normalize_path_prefix(url));

        let mut merged = Vec::new();
        merge_headers(&mut merged, self.global_headers.iter().cloned());
        for route_headers in &self.route_headers {
            if path.starts_with(&route_headers.path_prefix) {
                merge_headers(&mut merged, route_headers.headers.iter().cloned());
            }
        }
        merged
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestRouteOverride {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_path: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub content_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_class: Option<AuthClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<RoutePriority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parser_traits: Option<ParserTraits>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub exclude: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WafHardeningManifest {
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub priority_routes: Vec<String>,
    #[serde(default)]
    pub exclude_routes: Vec<String>,
    #[serde(default)]
    pub route_overrides: Vec<ManifestRouteOverride>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_hint: Option<String>,
    #[serde(default)]
    pub auth_required_routes: Vec<String>,
}

impl WafHardeningManifest {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(path.as_ref())?;
        serde_yml::from_str::<Self>(&raw).map_err(|err| {
            anyhow!(
                "failed to parse manifest {}: {err}",
                path.as_ref().display()
            )
        })
    }
}

fn resolve_headers(headers: HashMap<String, AuthHeaderValue>) -> Vec<(String, String)> {
    let mut resolved = headers
        .into_iter()
        .filter_map(|(name, value)| value.resolve().map(|resolved| (name, resolved)))
        .collect::<Vec<_>>();
    resolved.sort_by_key(|(name, _)| name.to_ascii_lowercase());
    resolved
}

fn normalize_path_prefix(path_prefix: &str) -> String {
    if path_prefix.trim().is_empty() {
        return "/".to_string();
    }
    let trimmed = path_prefix.trim();
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else if let Ok(url) = Url::parse(trimmed) {
        url.path().to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn merge_headers(
    headers: &mut Vec<(String, String)>,
    extra: impl IntoIterator<Item = (String, String)>,
) {
    for (name, value) in extra {
        if let Some(existing) = headers
            .iter_mut()
            .find(|(existing_name, _)| existing_name.eq_ignore_ascii_case(&name))
        {
            *existing = (name, value);
        } else {
            headers.push((name, value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_resolved_auth_profile_uses_env_and_route_headers() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::set_var("WAF_TEST_TOKEN", "secret-token");
        let profile = AuthProfile {
            headers: HashMap::from([(
                "Authorization".to_string(),
                AuthHeaderValue::EnvRef {
                    env: "WAF_TEST_TOKEN".to_string(),
                    default: None,
                },
            )]),
            route_headers: vec![RouteAuthHeaders {
                path_prefix: "/api/private".to_string(),
                headers: HashMap::from([(
                    "X-Route-Key".to_string(),
                    AuthHeaderValue::Plain("route-only".to_string()),
                )]),
            }],
        };

        let resolved = ResolvedAuthProfile::from_profile(profile);
        let headers = resolved.headers_for_url("https://example.com/api/private/tokens");
        assert!(headers
            .iter()
            .any(|(name, value)| name == "Authorization" && value == "secret-token"));
        assert!(headers
            .iter()
            .any(|(name, value)| name == "X-Route-Key" && value == "route-only"));
        std::env::remove_var("WAF_TEST_TOKEN");
    }

    #[test]
    fn test_manifest_and_auth_profile_load_from_yaml() {
        let tempdir = TempDir::new().expect("tempdir");
        let manifest_path = tempdir.path().join("waf-hardening.yaml");
        let auth_path = tempdir.path().join("auth-profile.yaml");
        fs::write(
            &manifest_path,
            "vendor_hint: cloudflare\npriority_routes:\n  - /api/tokenize\n",
        )
        .unwrap();
        fs::write(
            &auth_path,
            "headers:\n  Authorization:\n    value: unused\n",
        )
        .unwrap();

        let manifest = WafHardeningManifest::from_path(&manifest_path).unwrap();
        assert_eq!(manifest.vendor_hint.as_deref(), Some("cloudflare"));

        let resolved = ResolvedAuthProfile::from_path(&auth_path).unwrap();
        assert_eq!(resolved.headers_for_url("https://example.com").len(), 1);
    }
}
