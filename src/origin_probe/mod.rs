//! Origin IP probe — detect WAF bypass via unprotected endpoints sharing origin IP.
//!
//! Some WAF deployments front only the primary hostname, leaving health/metrics/status
//! endpoints reachable directly at the same origin IP. An attacker can send a request
//! directly to the origin IP with `Host: <main-domain>` and bypass the WAF entirely.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

use crate::active::ResolvedTarget;
use crate::http::HttpClient;

pub const WELL_KNOWN_BYPASS_PATHS: &[&str] = &[
    "/health",
    "/healthz",
    "/healthcheck",
    "/status",
    "/metrics",
    "/ping",
    "/ready",
    "/alive",
    "/__health",
    "/actuator/health",
    "/api/health",
    "/robots.txt",
    "/favicon.ico",
];

const BLOCK_KEYWORDS: &[&str] = &[
    "access denied",
    "request blocked",
    "forbidden",
    "blocked",
];

const BLOCK_STATUS_CODES: &[u16] = &[403, 406, 429, 503];

const WAF_PROBE_MARKER: &str = "<waf-probe-marker>";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginProbeConfig {
    pub timeout: Duration,
    pub delay_ms: u64,
    pub max_paths_to_check: usize,
    pub send_attack_probe: bool,
}

impl Default for OriginProbeConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            delay_ms: 200,
            max_paths_to_check: WELL_KNOWN_BYPASS_PATHS.len(),
            send_attack_probe: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginFinding {
    pub bypass_path: String,
    pub bypass_url: String,
    pub origin_ip: IpAddr,
    pub status_on_bypass_path: u16,
    pub status_on_main_via_origin: u16,
    pub waf_bypassed: bool,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginProbeReport {
    pub target_url: String,
    pub target_host: String,
    pub origin_ip: IpAddr,
    pub findings: Vec<OriginFinding>,
    pub bypass_confirmed: bool,
}

pub struct OriginProber {
    config: OriginProbeConfig,
    http: HttpClient,
}

impl OriginProber {
    pub fn new(config: OriginProbeConfig) -> Result<Self> {
        Ok(Self {
            config,
            http: HttpClient::new()?,
        })
    }

    pub async fn run(&self, target: &ResolvedTarget) -> Result<OriginProbeReport> {
        let origin_ip = target.pinned_ip;
        let base_url = target.normalized_url.trim_end_matches('/');
        let paths = &WELL_KNOWN_BYPASS_PATHS[..self
            .config
            .max_paths_to_check
            .min(WELL_KNOWN_BYPASS_PATHS.len())];

        let mut findings = Vec::new();

        for path in paths {
            let bypass_url = format!("{base_url}{path}");

            let bypass_resp = self
                .http
                .request_pinned(
                    "GET",
                    &bypass_url,
                    &[],
                    None,
                    origin_ip,
                    Some(self.config.timeout),
                )
                .await;

            let bypass_status = match bypass_resp {
                Ok(ref r) => r.status,
                Err(_) => {
                    self.sleep_delay().await;
                    continue;
                }
            };

            // Only record paths that respond (2xx or 3xx)
            if !(200..=399).contains(&bypass_status) {
                self.sleep_delay().await;
                continue;
            }

            let mut evidence = vec![format!(
                "bypass path {} responded with HTTP {}",
                path, bypass_status
            )];

            let (main_status, waf_bypassed) = if self.config.send_attack_probe {
                self.sleep_delay().await;

                let probe_url =
                    format!("{}?waf_probe={WAF_PROBE_MARKER}", base_url);
                let host_header = vec![(
                    "Host".to_string(),
                    target.host.clone(),
                )];

                let probe_resp = self
                    .http
                    .request_pinned(
                        "GET",
                        &probe_url,
                        &host_header,
                        None,
                        origin_ip,
                        Some(self.config.timeout),
                    )
                    .await;

                match probe_resp {
                    Ok(r) => {
                        let body_lower = r.body.to_lowercase();
                        let blocked_by_status = BLOCK_STATUS_CODES.contains(&r.status);
                        let blocked_by_body = BLOCK_KEYWORDS
                            .iter()
                            .any(|kw| body_lower.contains(kw));
                        let bypassed = !blocked_by_status && !blocked_by_body;
                        if bypassed {
                            evidence.push(format!(
                                "main target via origin IP returned HTTP {} without block keywords",
                                r.status
                            ));
                        }
                        (r.status, bypassed)
                    }
                    Err(e) => {
                        evidence.push(format!("attack probe failed: {e}"));
                        (0, false)
                    }
                }
            } else {
                (0, false)
            };

            findings.push(OriginFinding {
                bypass_path: path.to_string(),
                bypass_url: bypass_url.clone(),
                origin_ip,
                status_on_bypass_path: bypass_status,
                status_on_main_via_origin: main_status,
                waf_bypassed,
                evidence,
            });

            self.sleep_delay().await;
        }

        let bypass_confirmed = findings.iter().any(|f| f.waf_bypassed);

        Ok(OriginProbeReport {
            target_url: target.normalized_url.clone(),
            target_host: target.host.clone(),
            origin_ip,
            findings,
            bypass_confirmed,
        })
    }

    async fn sleep_delay(&self) {
        if self.config.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
        }
    }
}
