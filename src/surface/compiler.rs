use crate::active::normalize_target_url;
use crate::surface::config::{ManifestRouteOverride, WafHardeningManifest};
use crate::surface::frontend::extract_frontend_endpoints;
use crate::surface::har::extract_har_endpoints;
use crate::surface::openapi::extract_openapi_endpoints;
use crate::surface::{
    infer_priority, materialize_path_template, merge_discovery_sources, merge_parser_traits,
    merge_string_lists, stable_endpoint_id, stronger_auth_class, stronger_priority,
    summarize_surface_map, AuthClass, DiscoveryInput, DiscoverySource, RoutePriority,
    SurfaceEndpoint, SurfaceMap,
};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

#[derive(Debug, Clone, Default)]
pub struct CompilerInputs {
    pub target_url: String,
    pub repo: Option<String>,
    pub spec: Option<PathBuf>,
    pub har: Option<PathBuf>,
    pub manifest: Option<PathBuf>,
}

pub struct SurfaceMapCompiler;

impl Default for SurfaceMapCompiler {
    fn default() -> Self {
        Self
    }
}

impl SurfaceMapCompiler {
    pub fn new() -> Self {
        Self
    }

    pub fn compile(&self, inputs: CompilerInputs) -> Result<SurfaceMap> {
        let target_base_url = normalize_target_url(&inputs.target_url)?;
        let manifest = inputs
            .manifest
            .as_ref()
            .map(WafHardeningManifest::from_path)
            .transpose()?;

        let mut surface_map = SurfaceMap {
            target_base_url: target_base_url.clone(),
            vendor_hint: manifest
                .as_ref()
                .and_then(|entry| entry.vendor_hint.clone()),
            ..SurfaceMap::default()
        };
        let mut endpoints = Vec::new();
        let mut repo_checkout = None::<TempDir>;

        if let Some(repo) = &inputs.repo {
            let prepared = prepare_repo_checkout(repo)?;
            if prepared.cleanup.is_some() {
                repo_checkout = prepared.cleanup;
            }
            surface_map.repo_origin = prepared.origin;
            surface_map.repo_ref = prepared.reference;
            surface_map.inputs.push(DiscoveryInput {
                source: DiscoverySource::FrontendRepo,
                location: repo.to_string(),
            });
            endpoints.extend(extract_frontend_endpoints(
                &prepared.path,
                &target_base_url,
            )?);
        }

        if let Some(spec_path) = &inputs.spec {
            surface_map.inputs.push(DiscoveryInput {
                source: DiscoverySource::OpenApi,
                location: spec_path.display().to_string(),
            });
            endpoints.extend(extract_openapi_endpoints(spec_path, &target_base_url)?);
        }

        if let Some(har_path) = &inputs.har {
            surface_map.inputs.push(DiscoveryInput {
                source: DiscoverySource::Har,
                location: har_path.display().to_string(),
            });
            endpoints.extend(extract_har_endpoints(har_path, &target_base_url)?);
        }

        surface_map.endpoints = merge_endpoints(endpoints);
        if let Some(manifest) = manifest {
            apply_manifest(&mut surface_map, manifest)?;
        }
        surface_map.summary = summarize_surface_map(&surface_map.endpoints);

        drop(repo_checkout);
        Ok(surface_map)
    }
}

struct PreparedRepoCheckout {
    path: PathBuf,
    origin: Option<String>,
    reference: Option<String>,
    cleanup: Option<TempDir>,
}

fn prepare_repo_checkout(repo: &str) -> Result<PreparedRepoCheckout> {
    if looks_like_remote_repo(repo) {
        let tempdir = TempDir::new()?;
        let status = Command::new("git")
            .args(["clone", "--depth", "1", repo])
            .arg(tempdir.path())
            .status()
            .map_err(|err| anyhow!("failed to invoke git clone for {repo}: {err}"))?;
        if !status.success() {
            return Err(anyhow!(
                "failed to clone {repo}; make sure git.corp credentials are configured or provide a local checkout/exported snapshot"
            ));
        }
        return Ok(PreparedRepoCheckout {
            path: tempdir.path().to_path_buf(),
            origin: Some(repo.to_string()),
            reference: git_stdout(tempdir.path(), ["rev-parse", "--short", "HEAD"]),
            cleanup: Some(tempdir),
        });
    }

    let path = PathBuf::from(repo);
    if !path.exists() {
        return Err(anyhow!("repo path does not exist: {}", path.display()));
    }

    Ok(PreparedRepoCheckout {
        origin: git_stdout(&path, ["config", "--get", "remote.origin.url"]),
        reference: git_stdout(&path, ["rev-parse", "--short", "HEAD"]),
        path,
        cleanup: None,
    })
}

fn looks_like_remote_repo(repo: &str) -> bool {
    repo.starts_with("http://")
        || repo.starts_with("https://")
        || repo.starts_with("ssh://")
        || repo.starts_with("git@")
}

fn git_stdout<const N: usize>(path: &Path, args: [&str; N]) -> Option<String> {
    Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn merge_endpoints(endpoints: Vec<SurfaceEndpoint>) -> Vec<SurfaceEndpoint> {
    let mut merged = HashMap::<String, SurfaceEndpoint>::new();

    for mut endpoint in endpoints {
        let key = format!(
            "{}|{}",
            endpoint.path_template.to_ascii_lowercase(),
            endpoint.execution_path.to_ascii_lowercase()
        );
        endpoint.path_template = normalize_path_template(&endpoint.path_template);
        endpoint.execution_path = normalize_execution_path(&endpoint.execution_path);
        if endpoint.priority == RoutePriority::Medium {
            endpoint.priority = infer_priority(
                &endpoint.path_template,
                &endpoint.methods,
                &endpoint.tags,
                endpoint.auth_class,
            );
        }

        merged
            .entry(key)
            .and_modify(|existing| merge_endpoint(existing, &endpoint))
            .or_insert(endpoint);
    }

    let mut merged_endpoints = merged.into_values().collect::<Vec<_>>();
    merged_endpoints.sort_by(|left, right| {
        right
            .priority
            .rank()
            .cmp(&left.priority.rank())
            .then_with(|| right.confidence.total_cmp(&left.confidence))
            .then_with(|| left.path_template.cmp(&right.path_template))
    });
    for endpoint in &mut merged_endpoints {
        endpoint.endpoint_id = stable_endpoint_id(
            &endpoint.methods,
            &endpoint.path_template,
            endpoint.auth_class,
            &endpoint.content_types,
        );
    }
    merged_endpoints
}

fn merge_endpoint(existing: &mut SurfaceEndpoint, incoming: &SurfaceEndpoint) {
    merge_string_lists(&mut existing.methods, incoming.methods.iter().cloned());
    merge_string_lists(
        &mut existing.content_types,
        incoming.content_types.iter().cloned(),
    );
    merge_string_lists(&mut existing.tags, incoming.tags.iter().cloned());
    merge_discovery_sources(
        &mut existing.discovery_sources,
        incoming.discovery_sources.iter().copied(),
    );
    merge_parser_traits(&mut existing.parser_traits, &incoming.parser_traits);
    existing.auth_class = stronger_auth_class(existing.auth_class, incoming.auth_class);
    existing.confidence = existing.confidence.max(incoming.confidence);
    existing.priority = stronger_priority(existing.priority, incoming.priority);
    existing.excluded |= incoming.excluded;

    if existing.sample_request.is_none() {
        existing.sample_request = incoming.sample_request.clone();
    }
    if incoming.live_verification.is_some() {
        existing.live_verification = incoming.live_verification.clone();
    }
}

fn apply_manifest(surface_map: &mut SurfaceMap, manifest: WafHardeningManifest) -> Result<()> {
    if !manifest.targets.is_empty()
        && !manifest
            .targets
            .iter()
            .any(|target| target.eq_ignore_ascii_case(&surface_map.target_base_url))
    {
        let target_host = url::Url::parse(&surface_map.target_base_url)
            .ok()
            .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()));
        let matches_target = manifest.targets.iter().any(|target| {
            url::Url::parse(target)
                .ok()
                .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
                .zip(target_host.clone())
                .map(|(left, right)| left == right)
                .unwrap_or(false)
        });
        if !matches_target {
            return Err(anyhow!(
                "manifest targets do not include {}",
                surface_map.target_base_url
            ));
        }
    }

    surface_map.inputs.push(DiscoveryInput {
        source: DiscoverySource::Manifest,
        location: "waf-hardening.yaml".to_string(),
    });
    if surface_map.vendor_hint.is_none() {
        surface_map.vendor_hint = manifest.vendor_hint.clone();
    }

    for endpoint in &mut surface_map.endpoints {
        if manifest
            .priority_routes
            .iter()
            .any(|path| path_matches(path, &endpoint.path_template))
        {
            endpoint.priority = stronger_priority(endpoint.priority, RoutePriority::High);
        }
        if manifest
            .exclude_routes
            .iter()
            .any(|path| path_matches(path, &endpoint.path_template))
        {
            endpoint.excluded = true;
        }
        if manifest
            .auth_required_routes
            .iter()
            .any(|path| path_matches(path, &endpoint.path_template))
        {
            endpoint.auth_class = AuthClass::Required;
        }
        for route_override in &manifest.route_overrides {
            if path_matches(&route_override.path, &endpoint.path_template) {
                apply_route_override(endpoint, route_override);
            }
        }
        endpoint.endpoint_id = stable_endpoint_id(
            &endpoint.methods,
            &endpoint.path_template,
            endpoint.auth_class,
            &endpoint.content_types,
        );
    }

    Ok(())
}

fn apply_route_override(endpoint: &mut SurfaceEndpoint, route_override: &ManifestRouteOverride) {
    if let Some(execution_path) = &route_override.execution_path {
        endpoint.execution_path = execution_path.clone();
    }
    if !route_override.methods.is_empty() {
        endpoint.methods = route_override
            .methods
            .iter()
            .map(|method| method.to_ascii_uppercase())
            .collect();
    }
    if !route_override.content_types.is_empty() {
        endpoint.content_types = route_override.content_types.clone();
    }
    if let Some(auth_class) = route_override.auth_class {
        endpoint.auth_class = auth_class;
    }
    if let Some(priority) = route_override.priority {
        endpoint.priority = priority;
    }
    if let Some(parser_traits) = &route_override.parser_traits {
        endpoint.parser_traits = parser_traits.clone();
    }
    merge_string_lists(&mut endpoint.tags, route_override.tags.iter().cloned());
    endpoint.excluded |= route_override.exclude;
    merge_discovery_sources(&mut endpoint.discovery_sources, [DiscoverySource::Manifest]);
}

fn path_matches(expected: &str, actual: &str) -> bool {
    let expected = normalize_path_template(expected);
    let actual = normalize_path_template(actual);
    actual == expected || actual.starts_with(&(expected.clone() + "/"))
}

pub(crate) fn normalize_path_template(path: &str) -> String {
    if path.trim().is_empty() {
        return "/".to_string();
    }

    let normalized = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    normalized.replace("//", "/")
}

pub(crate) fn normalize_execution_path(path: &str) -> String {
    let normalized = normalize_path_template(path);
    if normalized.contains('{') || normalized.contains(':') {
        materialize_path_template(&normalized)
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::{AuthClass, DiscoverySource, ParserTraits, RoutePriority};

    fn endpoint(path: &str, source: DiscoverySource) -> SurfaceEndpoint {
        SurfaceEndpoint {
            endpoint_id: String::new(),
            path_template: path.to_string(),
            execution_path: normalize_execution_path(path),
            methods: vec!["POST".to_string()],
            content_types: vec!["application/json".to_string()],
            auth_class: AuthClass::Unknown,
            parser_traits: ParserTraits {
                json: true,
                ..ParserTraits::default()
            },
            confidence: 0.6,
            priority: RoutePriority::Medium,
            tags: Vec::new(),
            discovery_sources: vec![source],
            sample_request: None,
            live_verification: None,
            excluded: false,
        }
    }

    #[test]
    fn test_merge_endpoints_combines_sources_and_methods() {
        let mut left = endpoint("/api/tokenize", DiscoverySource::FrontendRepo);
        left.methods = vec!["GET".to_string()];
        let right = endpoint("/api/tokenize", DiscoverySource::OpenApi);

        let merged = merge_endpoints(vec![left, right]);
        assert_eq!(merged.len(), 1);
        assert!(merged[0].methods.contains(&"GET".to_string()));
        assert!(merged[0].methods.contains(&"POST".to_string()));
        assert_eq!(merged[0].discovery_sources.len(), 2);
    }

    #[test]
    fn test_apply_manifest_updates_route_attributes() {
        let mut surface_map = SurfaceMap {
            target_base_url: "https://example.com".to_string(),
            endpoints: vec![endpoint("/api/tokenize", DiscoverySource::FrontendRepo)],
            ..SurfaceMap::default()
        };
        let manifest = WafHardeningManifest {
            priority_routes: vec!["/api/tokenize".to_string()],
            auth_required_routes: vec!["/api/tokenize".to_string()],
            route_overrides: vec![ManifestRouteOverride {
                path: "/api/tokenize".to_string(),
                tags: vec!["critical".to_string()],
                ..ManifestRouteOverride::default()
            }],
            ..WafHardeningManifest::default()
        };

        apply_manifest(&mut surface_map, manifest).unwrap();
        assert_eq!(surface_map.endpoints[0].auth_class, AuthClass::Required);
        assert_eq!(surface_map.endpoints[0].priority, RoutePriority::High);
        assert!(surface_map.endpoints[0]
            .tags
            .contains(&"critical".to_string()));
    }

    #[test]
    fn test_compile_empty_inputs_produces_empty_surface_map() {
        let compiler = SurfaceMapCompiler::new();
        let surface_map = compiler
            .compile(CompilerInputs {
                target_url: "https://example.com".to_string(),
                ..CompilerInputs::default()
            })
            .unwrap();
        assert!(surface_map.endpoints.is_empty());
        assert_eq!(surface_map.summary.total_endpoints, 0);
    }
}
