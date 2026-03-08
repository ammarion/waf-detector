use std::cmp::Reverse;

use crate::surface::{
    AuthClass, RefinedSurfaceMapStats, RoutePriority, SurfaceEndpoint, SurfaceMap,
};

#[derive(Debug, Clone)]
pub struct PlannedRoute {
    pub endpoint: SurfaceEndpoint,
    pub execution_url: String,
    pub selected: bool,
    pub uncovered: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RouteAwarePlan {
    pub selected_routes: Vec<PlannedRoute>,
    pub deferred_routes: Vec<PlannedRoute>,
    pub stats: RefinedSurfaceMapStats,
}

pub struct RouteAwarePlanner {
    max_routes: usize,
}

impl Default for RouteAwarePlanner {
    fn default() -> Self {
        Self { max_routes: 6 }
    }
}

impl RouteAwarePlanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn plan(
        &self,
        surface_map: &SurfaceMap,
        auth_profile_available: bool,
    ) -> anyhow::Result<RouteAwarePlan> {
        let mut candidates = surface_map.endpoints.clone();
        candidates.sort_by_key(|right| Reverse(route_score(right)));

        let mut plan = RouteAwarePlan::default();
        plan.stats.verified_endpoints = candidates
            .iter()
            .filter(|endpoint| endpoint.live_verification.is_some())
            .count();

        for endpoint in candidates {
            if endpoint.excluded {
                continue;
            }
            if endpoint.parser_traits.dynamic_segments
                && endpoint.execution_path.contains('{')
                && endpoint.execution_path.contains('}')
            {
                plan.stats.unresolved_parameterized_endpoints += 1;
            }
            let mut notes = Vec::new();
            let uncovered = endpoint.auth_class == AuthClass::Required && !auth_profile_available;
            if endpoint.is_static_like() {
                notes.push("suppressed static or health-style endpoint".to_string());
            }
            if uncovered {
                notes.push(
                    "route requires auth but no auth profile was provided; coverage remains partial"
                        .to_string(),
                );
                plan.stats.uncovered_auth_required_endpoints += 1;
            }
            if endpoint
                .live_verification
                .as_ref()
                .map(|verification| !verification.reachable && endpoint.confidence < 0.7)
                .unwrap_or(false)
            {
                notes.push(
                    "live verification suggests the route may not exist on staging".to_string(),
                );
            }

            let execution_url = endpoint.execution_url(&surface_map.target_base_url)?;
            let selected = !endpoint.is_static_like()
                && !uncovered
                && endpoint
                    .live_verification
                    .as_ref()
                    .map(|verification| verification.status != 404)
                    .unwrap_or(true)
                && plan.selected_routes.len() < self.max_routes;

            let planned = PlannedRoute {
                endpoint,
                execution_url,
                selected,
                uncovered,
                notes,
            };

            if planned.selected {
                plan.stats.selected_endpoints += 1;
                plan.stats.covered_endpoints += 1;
                plan.selected_routes.push(planned);
            } else {
                if planned.uncovered {
                    plan.stats.partial_coverage_endpoints += 1;
                }
                plan.deferred_routes.push(planned);
            }
        }

        Ok(plan)
    }
}

fn route_score(endpoint: &SurfaceEndpoint) -> (u8, i32, i32) {
    let auth_score = match endpoint.auth_class {
        AuthClass::Required => 3,
        AuthClass::Optional => 2,
        AuthClass::Unknown => 1,
        AuthClass::None => 0,
    };
    let confidence = (endpoint.confidence * 1000.0) as i32;
    let method_score = if endpoint
        .methods
        .iter()
        .any(|method| matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE"))
    {
        1
    } else {
        0
    };

    (
        priority_score(endpoint.priority) + method_score,
        auth_score,
        confidence,
    )
}

fn priority_score(priority: RoutePriority) -> u8 {
    match priority {
        RoutePriority::Critical => 4,
        RoutePriority::High => 3,
        RoutePriority::Medium => 2,
        RoutePriority::Low => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::{DiscoverySource, ParserTraits};

    fn endpoint(path: &str, priority: RoutePriority, auth_class: AuthClass) -> SurfaceEndpoint {
        SurfaceEndpoint {
            endpoint_id: path.to_string(),
            path_template: path.to_string(),
            execution_path: path.to_string(),
            methods: vec!["POST".to_string()],
            content_types: vec!["application/json".to_string()],
            auth_class,
            parser_traits: ParserTraits {
                json: true,
                ..ParserTraits::default()
            },
            confidence: 0.8,
            priority,
            tags: Vec::new(),
            discovery_sources: vec![DiscoverySource::OpenApi],
            sample_request: None,
            live_verification: None,
            excluded: false,
        }
    }

    #[test]
    fn test_route_aware_planner_keeps_auth_required_routes_visible_without_auth_profile() {
        let planner = RouteAwarePlanner::new();
        let map = SurfaceMap {
            target_base_url: "https://example.com".to_string(),
            endpoints: vec![
                endpoint(
                    "/api/tokenize",
                    RoutePriority::Critical,
                    AuthClass::Required,
                ),
                endpoint("/api/search", RoutePriority::High, AuthClass::None),
            ],
            ..SurfaceMap::default()
        };

        let plan = planner.plan(&map, false).unwrap();
        assert_eq!(plan.selected_routes.len(), 1);
        assert_eq!(
            plan.selected_routes[0].endpoint.path_template,
            "/api/search"
        );
        assert_eq!(plan.stats.uncovered_auth_required_endpoints, 1);
        assert_eq!(plan.stats.partial_coverage_endpoints, 1);
    }
}
