use crate::active::ResolvedTarget;
use crate::http::{HttpClient, HttpResponse};
use crate::surface::{AuthClass, DiscoverySource, LiveVerification, SurfaceEndpoint, SurfaceMap};
use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceVerificationMode {
    LowRiskOnly,
}

#[async_trait]
trait LiveSurfaceHttpAdapter: Send + Sync {
    async fn send(&self, target: &ResolvedTarget, method: &str, url: &str) -> Result<HttpResponse>;
}

struct RealLiveSurfaceHttpAdapter {
    client: HttpClient,
}

impl RealLiveSurfaceHttpAdapter {
    fn new() -> Result<Self> {
        Ok(Self {
            client: HttpClient::new()?,
        })
    }
}

#[async_trait]
impl LiveSurfaceHttpAdapter for RealLiveSurfaceHttpAdapter {
    async fn send(&self, target: &ResolvedTarget, method: &str, url: &str) -> Result<HttpResponse> {
        self.client
            .request_pinned(method, url, &[], None, target.pinned_ip, None)
            .await
    }
}

pub struct LiveSurfaceVerifier {
    mode: SurfaceVerificationMode,
    http: Box<dyn LiveSurfaceHttpAdapter + Send + Sync>,
}

impl LiveSurfaceVerifier {
    pub fn new() -> Result<Self> {
        Ok(Self {
            mode: SurfaceVerificationMode::LowRiskOnly,
            http: Box::new(RealLiveSurfaceHttpAdapter::new()?),
        })
    }

    #[cfg(test)]
    fn with_adapter(adapter: Box<dyn LiveSurfaceHttpAdapter + Send + Sync>) -> Self {
        Self {
            mode: SurfaceVerificationMode::LowRiskOnly,
            http: adapter,
        }
    }

    pub async fn refine(
        &self,
        surface_map: &SurfaceMap,
        target: &ResolvedTarget,
    ) -> Result<SurfaceMap> {
        let mut refined = surface_map.clone();
        for endpoint in &mut refined.endpoints {
            if endpoint.excluded {
                continue;
            }
            let method = verification_method(endpoint, self.mode);
            let url = endpoint.execution_url(&target.normalized_url)?;
            match self.http.send(target, method, &url).await {
                Ok(response) => apply_live_observation(endpoint, method, &response),
                Err(err) => {
                    tracing::warn!(
                        "live verification failed for {} {}: {}",
                        method,
                        endpoint.path_template,
                        err
                    );
                }
            }
        }
        refined.summary = crate::surface::summarize_surface_map(&refined.endpoints);
        Ok(refined)
    }
}

fn verification_method(endpoint: &SurfaceEndpoint, _mode: SurfaceVerificationMode) -> &'static str {
    if endpoint.methods.iter().any(|method| method == "GET") {
        "GET"
    } else if endpoint.methods.iter().any(|method| method == "HEAD") {
        "HEAD"
    } else {
        "OPTIONS"
    }
}

pub(crate) fn apply_live_observation(
    endpoint: &mut SurfaceEndpoint,
    method: &str,
    response: &HttpResponse,
) {
    let lower_body = response.body.to_ascii_lowercase();
    let lower_headers = response
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
    let content_type = response.headers.get("content-type").cloned();
    let (reachable, auth_class, observed_action, confidence_delta) = match response.status {
        200..=299 => (true, AuthClass::None, "allowed".to_string(), 0.12),
        401 | 403 => (true, AuthClass::Required, "auth_required".to_string(), 0.18),
        404 => (false, endpoint.auth_class, "not_found".to_string(), -0.18),
        405 => (
            true,
            endpoint.auth_class,
            "method_not_allowed".to_string(),
            0.10,
        ),
        429 => (true, endpoint.auth_class, "rate_limited".to_string(), 0.08),
        status if status >= 500 => (true, endpoint.auth_class, "error".to_string(), -0.05),
        _ => (true, endpoint.auth_class, "unknown".to_string(), 0.02),
    };

    let observed_action = if lower_body.contains("challenge")
        || lower_body.contains("captcha")
        || lower_headers.contains("cf-mitigated")
    {
        "challenge".to_string()
    } else {
        observed_action
    };

    endpoint.auth_class = if matches!(response.status, 401 | 403) {
        AuthClass::Required
    } else if endpoint.auth_class == AuthClass::Unknown {
        auth_class
    } else {
        endpoint.auth_class
    };
    endpoint.confidence = (endpoint.confidence + confidence_delta).clamp(0.05, 0.99);
    endpoint.live_verification = Some(LiveVerification {
        method: method.to_string(),
        status: response.status,
        content_type,
        reachable,
        auth_class: endpoint.auth_class,
        observed_action,
        confidence_delta,
        verified_at: Utc::now(),
    });
    if reachable {
        crate::surface::merge_discovery_sources(
            &mut endpoint.discovery_sources,
            [DiscoverySource::LiveVerification],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active::{ActiveTargetProfile, ResolvedTarget};
    use crate::effectiveness::consent::{ScopeTarget, TargetClass};
    use std::collections::{HashMap, VecDeque};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    struct MockAdapter {
        responses: Mutex<VecDeque<HttpResponse>>,
    }

    #[async_trait]
    impl LiveSurfaceHttpAdapter for MockAdapter {
        async fn send(
            &self,
            _target: &ResolvedTarget,
            _method: &str,
            _url: &str,
        ) -> Result<HttpResponse> {
            Ok(self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("mock response"))
        }
    }

    fn target() -> ResolvedTarget {
        ResolvedTarget {
            original_url: "https://example.com".to_string(),
            normalized_url: "https://example.com/".to_string(),
            host: "example.com".to_string(),
            port: 443,
            registered_target: ScopeTarget {
                host: "example.com".to_string(),
                class: TargetClass::Public,
            },
            active_target_profile: ActiveTargetProfile::Public,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            pinned_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        }
    }

    #[tokio::test]
    async fn test_live_refinement_marks_auth_required_routes() {
        let verifier = LiveSurfaceVerifier::with_adapter(Box::new(MockAdapter {
            responses: Mutex::new(VecDeque::from(vec![HttpResponse {
                status: 401,
                headers: HashMap::new(),
                body: String::new(),
                url: "https://example.com/api/private".to_string(),
            }])),
        }));
        let map = SurfaceMap {
            target_base_url: "https://example.com".to_string(),
            endpoints: vec![SurfaceEndpoint {
                endpoint_id: "ep-1".to_string(),
                path_template: "/api/private".to_string(),
                execution_path: "/api/private".to_string(),
                methods: vec!["POST".to_string()],
                content_types: vec!["application/json".to_string()],
                auth_class: AuthClass::Unknown,
                parser_traits: Default::default(),
                confidence: 0.5,
                priority: crate::surface::RoutePriority::High,
                tags: Vec::new(),
                discovery_sources: vec![DiscoverySource::FrontendRepo],
                sample_request: None,
                live_verification: None,
                excluded: false,
            }],
            ..SurfaceMap::default()
        };

        let refined = verifier.refine(&map, &target()).await.unwrap();
        assert_eq!(refined.endpoints[0].auth_class, AuthClass::Required);
        assert!(refined.endpoints[0].confidence > 0.5);
    }
}
