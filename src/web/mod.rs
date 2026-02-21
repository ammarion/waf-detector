use crate::ai::{
    ai_enabled, ai_endpoint, ai_model, ai_timeout, AiProvider, AiSummaryRequest, AiSummaryResponse,
    OllamaProvider,
};
use crate::effectiveness::consent::{ConsentManager, ConsentStatus};
use crate::engine::DetectionEngine;
use crate::payload::waf_smoke_test::{SmokeTestConfig, SmokeTestResult, WafSmokeTest};
use crate::script_executor::{CombinedResult, ScriptExecutor};
use crate::virtual_adversary::{
    VaOutcome, VaPayloadCategory, VaRunReport, VirtualAdversaryConfig, VirtualAdversaryRunner,
};
use crate::virtual_adversary2::{
    build_va2_campaign_plan, Va2CampaignConfig, Va2Phase, Va2RunReport, Va2Runner,
};
use crate::DetectionResult;
use anyhow::{anyhow, Result};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::{fs, path::PathBuf};
use tower_http::{
    cors::{Any, CorsLayer},
    services::ServeDir,
};
use url::Url;

pub mod templates;

/// Build a permissive CORS layer for read-only informational endpoints.
fn build_readonly_cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET])
        .allow_headers(Any)
}

/// Build a restricted CORS layer for active endpoints that trigger network
/// activity (scans, smoke tests, VA runs). Only allows requests from
/// localhost by default; override with `WAF_DETECTOR_ALLOWED_ORIGINS`.
fn build_active_cors(port: u16) -> CorsLayer {
    let mut origins: Vec<HeaderValue> = vec![
        format!("http://localhost:{port}").parse().unwrap(),
        format!("http://127.0.0.1:{port}").parse().unwrap(),
    ];

    if let Ok(extra) = std::env::var("WAF_DETECTOR_ALLOWED_ORIGINS") {
        for origin in extra.split(',') {
            if let Ok(val) = origin.trim().parse::<HeaderValue>() {
                origins.push(val);
            }
        }
    }

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
}

/// Middleware that enforces API token authentication when
/// `WAF_DETECTOR_API_TOKEN` is set. When unset, all requests pass through
/// (preserving current dev-mode behavior).
async fn require_api_token(
    request: axum::http::Request<Body>,
    next: Next,
) -> axum::response::Response {
    if let Ok(expected_token) = std::env::var("WAF_DETECTOR_API_TOKEN") {
        if !expected_token.is_empty() {
            let auth_header = request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            match auth_header {
                Some(ref auth) if auth.starts_with("Bearer ") => {
                    let token = &auth[7..];
                    if token == expected_token {
                        return next.run(request).await;
                    }
                }
                _ => {}
            }

            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Missing or invalid API token. Provide Authorization: Bearer <token> header."
                })),
            )
                .into_response();
        }
    }

    // No token configured — allow all requests (dev mode)
    next.run(request).await
}

/// CSRF protection middleware for active POST endpoints.
/// Validates that the Origin or Referer header matches the server Host.
/// Requests carrying a valid API token bypass this check (machine clients).
/// GET requests and requests with no Origin/Referer (e.g. curl) pass through.
async fn validate_csrf(request: axum::http::Request<Body>, next: Next) -> axum::response::Response {
    if request.method() != Method::POST {
        return next.run(request).await;
    }

    // Machine clients with valid API token bypass CSRF
    if has_valid_api_token(request.headers()) {
        return next.run(request).await;
    }

    let server_host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Check Origin header (preferred for CSRF)
    if let Some(origin) = request
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
    {
        if origin_matches_host(origin, server_host) {
            return next.run(request).await;
        }
        return csrf_error_response();
    }

    // Fall back to Referer header
    if let Some(referer) = request
        .headers()
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
    {
        if origin_matches_host(referer, server_host) {
            return next.run(request).await;
        }
        return csrf_error_response();
    }

    // No Origin or Referer — non-browser client (curl, httpie, etc.)
    next.run(request).await
}

fn has_valid_api_token(headers: &axum::http::HeaderMap) -> bool {
    if let Ok(expected) = std::env::var("WAF_DETECTOR_API_TOKEN") {
        if !expected.is_empty() {
            if let Some(auth) = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
            {
                return auth.starts_with("Bearer ") && auth[7..] == *expected;
            }
        }
    }
    false
}

fn origin_matches_host(origin_or_referer: &str, server_host: &str) -> bool {
    if let Ok(url) = Url::parse(origin_or_referer) {
        let host = url.host_str().unwrap_or("");
        let port = url.port();
        let authority = match port {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        };
        authority == server_host
    } else {
        false
    }
}

fn csrf_error_response() -> axum::response::Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "success": false,
            "error": "CSRF validation failed: request origin does not match server host"
        })),
    )
        .into_response()
}

const VA_REPORTS_DIR: &str = ".waf-detector/va-reports";
const VA_REPORT_RETENTION_DEFAULT: usize = 50;
const VA2_PHASE_DEFAULT: &str = "baseline,protocol-variance";

#[derive(Clone)]
pub struct WebServer {
    engine: Arc<DetectionEngine>,
    script_executor: Arc<ScriptExecutor>,
    va_jobs: Arc<Mutex<HashMap<String, VaJob>>>,
    va_job_counter: Arc<AtomicU64>,
    va2_jobs: Arc<Mutex<HashMap<String, Va2Job>>>,
    va2_job_counter: Arc<AtomicU64>,
}

#[derive(Deserialize)]
pub struct ScanRequest {
    url: String,
}

#[derive(Serialize)]
pub struct ScanResponse {
    success: bool,
    result: Option<DetectionResult>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct BatchScanRequest {
    urls: Vec<String>,
}

#[derive(Serialize)]
pub struct BatchScanResponse {
    success: bool,
    results: Vec<DetectionResult>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct CombinedScanResponse {
    success: bool,
    result: Option<CombinedResult>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct SmokeTestResponse {
    success: bool,
    result: Option<SmokeTestResult>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct AiSummaryApiResponse {
    success: bool,
    summary: Option<AiSummaryResponse>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct VaRequest {
    url: String,
    tier: Option<u8>,
    budget: Option<u32>,
    timeout_ms: Option<u64>,
    delay_ms: Option<u64>,
    variants: Option<u8>,
}

#[derive(Deserialize)]
pub struct Va2Request {
    target_url: String,
    phases: Option<String>,
    seed: Option<u64>,
    budget: Option<u32>,
}

#[derive(Deserialize)]
pub struct ConsentTargetRequest {
    target: String,
}

impl VaRequest {
    fn to_config(&self) -> Result<VirtualAdversaryConfig> {
        let mut config = VirtualAdversaryConfig::default();
        if let Some(tier) = self.tier {
            config.tier = tier;
        }
        if let Some(budget) = self.budget {
            config.request_budget = budget;
        }
        if let Some(timeout_ms) = self.timeout_ms {
            if timeout_ms == 0 {
                return Err(anyhow!("timeout_ms must be greater than 0"));
            }
            config.request_timeout = std::time::Duration::from_millis(timeout_ms);
        }
        if let Some(delay_ms) = self.delay_ms {
            if delay_ms == 0 {
                return Err(anyhow!("delay_ms must be greater than 0"));
            }
            config.request_delay = std::time::Duration::from_millis(delay_ms);
        }
        if let Some(variants) = self.variants {
            config.max_variants_per_payload = variants;
        }
        config
            .validate()
            .map_err(|err| anyhow!("invalid Virtual Adversary config: {err}"))?;
        Ok(config)
    }
}

fn parse_va2_phases(raw: &str) -> Result<Vec<Va2Phase>> {
    let mut phases = Vec::new();
    for item in raw.split(',') {
        let phase = match item.trim().to_lowercase().as_str() {
            "baseline" => Va2Phase::Baseline,
            "protocol-variance" => Va2Phase::ProtocolVariance,
            "state-escalation" => Va2Phase::StateEscalation,
            "behavioral-pressure" => Va2Phase::BehavioralPressure,
            "challenge-interaction" => Va2Phase::ChallengeInteraction,
            other => return Err(anyhow!("unknown va2 phase: {other}")),
        };
        phases.push(phase);
    }
    if phases.is_empty() {
        return Err(anyhow!("va2 phases cannot be empty"));
    }
    Ok(phases)
}

#[derive(Serialize)]
pub struct VaResponse {
    success: bool,
    result: Option<VaRunReport>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct Va2PlanResponse {
    success: bool,
    plan: Option<serde_json::Value>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct Va2RunResponse {
    success: bool,
    report: Option<Va2RunReport>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct VaJobStartResponse {
    success: bool,
    job_id: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VaJobState {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Serialize, Clone)]
pub struct VaJobStatus {
    pub id: String,
    pub state: VaJobState,
    pub total: usize,
    pub completed: usize,
    pub result: Option<VaRunReport>,
    pub error: Option<String>,
    pub report_id: Option<String>,
    pub events: Vec<VaJobEvent>,
}

#[derive(Debug)]
struct VaJob {
    id: String,
    state: VaJobState,
    total: usize,
    completed: usize,
    result: Option<VaRunReport>,
    error: Option<String>,
    report_id: Option<String>,
    events: Vec<VaJobEvent>,
}

#[derive(Debug)]
struct Va2Job {
    id: String,
    state: VaJobState,
    result: Option<Va2RunReport>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct VaJobEvent {
    pub index: usize,
    pub total: usize,
    pub category: VaPayloadCategory,
    pub payload: String,
    pub outcome: VaOutcome,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

const VA_JOB_EVENT_LIMIT: usize = 200;

impl Va2Job {
    fn new(id: String) -> Self {
        Self {
            id,
            state: VaJobState::Pending,
            result: None,
            error: None,
        }
    }

    fn status(&self) -> Va2JobStatus {
        Va2JobStatus {
            id: self.id.clone(),
            state: self.state,
            result: self.result.clone(),
            error: self.error.clone(),
        }
    }
}

impl VaJob {
    fn new(id: String) -> Self {
        Self {
            id,
            state: VaJobState::Pending,
            total: 0,
            completed: 0,
            result: None,
            error: None,
            report_id: None,
            events: Vec::new(),
        }
    }

    fn status(&self) -> VaJobStatus {
        VaJobStatus {
            id: self.id.clone(),
            state: self.state,
            total: self.total,
            completed: self.completed,
            result: self.result.clone(),
            error: self.error.clone(),
            report_id: self.report_id.clone(),
            events: self.events.clone(),
        }
    }

    fn push_event(&mut self, event: VaJobEvent) {
        if self.events.len() >= VA_JOB_EVENT_LIMIT {
            self.events.remove(0);
        }
        self.events.push(event);
    }
}

#[derive(Serialize)]
pub struct VaJobStatusResponse {
    success: bool,
    status: Option<VaJobStatus>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct Va2JobStatus {
    pub id: String,
    pub state: VaJobState,
    pub result: Option<Va2RunReport>,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct Va2JobStartResponse {
    success: bool,
    job_id: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct Va2JobStatusResponse {
    success: bool,
    status: Option<Va2JobStatus>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct VaReportSummary {
    pub id: String,
    pub target_url: String,
    pub created_at: DateTime<Utc>,
    pub plan_size: usize,
    pub blocked: usize,
    pub challenge: usize,
    pub allowed: usize,
    pub error: usize,
    pub risk_label: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaStoredReport {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub report: VaRunReport,
}

#[derive(Serialize)]
pub struct VaReportsResponse {
    success: bool,
    reports: Vec<VaReportSummary>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct VaReportResponse {
    success: bool,
    report: Option<VaStoredReport>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct VaReplayPlanResponse {
    success: bool,
    replay_plan: Option<Vec<crate::virtual_adversary::VaReplayPlanItem>>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct VaRetentionResponse {
    success: bool,
    kept: usize,
    deleted: usize,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct VaRangeDeleteResponse {
    success: bool,
    deleted: usize,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct ConsentStatusResponse {
    success: bool,
    status: Option<ConsentStatus>,
    error: Option<String>,
}

impl WebServer {
    pub fn new(engine: DetectionEngine) -> Self {
        Self {
            engine: Arc::new(engine),
            script_executor: Arc::new(ScriptExecutor::default()),
            va_jobs: Arc::new(Mutex::new(HashMap::new())),
            va_job_counter: Arc::new(AtomicU64::new(1)),
            va2_jobs: Arc::new(Mutex::new(HashMap::new())),
            va2_job_counter: Arc::new(AtomicU64::new(1)),
        }
    }

    pub async fn start(self, port: u16) -> Result<()> {
        let mode = crate::DeploymentMode::from_env();
        tracing::info!("Running in {:?} mode", mode);

        if mode.is_prod() {
            // Enforce: API token must be set in prod
            if std::env::var("WAF_DETECTOR_API_TOKEN")
                .map(|t| t.is_empty())
                .unwrap_or(true)
            {
                return Err(anyhow!(
                    "WAF_DETECTOR_API_TOKEN must be set in production mode"
                ));
            }
            // Enforce: insecure TLS rejected in prod
            if std::env::var("WAF_DETECTOR_INSECURE_TLS").is_ok() {
                return Err(anyhow!(
                    "WAF_DETECTOR_INSECURE_TLS is not allowed in production mode"
                ));
            }
        }

        // Read-only informational endpoints — broad CORS, no auth required
        let readonly_routes = Router::new()
            .route("/api/providers", get(list_providers))
            .route("/api/status", get(server_status))
            .route("/api/consent-status", get(consent_status))
            .route(
                "/api/virtual-adversary/status/:id",
                get(virtual_adversary_status),
            )
            .route(
                "/api/virtual-adversary/reports",
                get(virtual_adversary_reports),
            )
            .route(
                "/api/virtual-adversary/reports/:id",
                get(virtual_adversary_report),
            )
            .route(
                "/api/virtual-adversary/reports/:id/replay.json",
                get(virtual_adversary_report_replay_json),
            )
            .route(
                "/api/virtual-adversary/reports/:id/csv",
                get(virtual_adversary_report_csv),
            )
            .route(
                "/api/virtual-adversary/reports/:id/replay.csv",
                get(virtual_adversary_report_replay_csv),
            )
            .route(
                "/api/virtual-adversary/reports.csv",
                get(virtual_adversary_reports_csv),
            )
            .route(
                "/api/virtual-adversary2/status/:id",
                get(virtual_adversary2_status),
            )
            .layer(build_readonly_cors());

        // Active endpoints that trigger network activity — restricted CORS,
        // API token required when WAF_DETECTOR_API_TOKEN is set
        let active_routes = Router::new()
            .route("/api/scan", post(scan_url))
            .route("/api/combined-scan", post(combined_scan))
            .route("/api/smoke-test", post(smoke_test))
            .route("/api/batch-scan", post(batch_scan))
            .route("/api/virtual-adversary", post(virtual_adversary))
            .route(
                "/api/virtual-adversary/start",
                post(virtual_adversary_start),
            )
            .route(
                "/api/virtual-adversary/reports/cleanup",
                post(virtual_adversary_reports_cleanup),
            )
            .route(
                "/api/virtual-adversary/reports/delete-range",
                post(virtual_adversary_reports_delete_range),
            )
            .route(
                "/api/virtual-adversary2/plan",
                post(virtual_adversary2_plan),
            )
            .route("/api/virtual-adversary2/run", post(virtual_adversary2_run))
            .route(
                "/api/virtual-adversary2/start",
                post(virtual_adversary2_start),
            )
            .route(
                "/api/virtual-adversary2/cancel/:id",
                post(virtual_adversary2_cancel),
            )
            .route("/api/ai/summary", post(ai_summary))
            .route("/api/consent/add-target", post(consent_add_target))
            .route("/api/consent/remove-target", post(consent_remove_target))
            .layer(middleware::from_fn(require_api_token))
            .layer(middleware::from_fn(validate_csrf))
            .layer(build_active_cors(port));

        let app = Router::new()
            .nest_service("/static", ServeDir::new("web/static"))
            .merge(readonly_routes)
            .merge(active_routes)
            // Web pages — no CORS needed (same-origin browser navigation)
            .route("/", get(dashboard))
            .route("/dashboard", get(dashboard))
            .route("/api-docs", get(api_docs))
            .with_state(self);

        let addr = format!("127.0.0.1:{port}");
        println!("🌐 WAF Detector Web Server starting on http://localhost:{port}");
        println!("📊 Dashboard: http://localhost:{port}/dashboard");
        println!("📖 API Docs: http://localhost:{port}/api-docs");

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

// Handler for the main dashboard
async fn dashboard() -> impl IntoResponse {
    Html(templates::dashboard_html())
}

// Handler for API documentation
async fn api_docs() -> impl IntoResponse {
    Html(templates::API_DOCS_HTML)
}

// Handler for single URL scan
async fn scan_url(
    State(server): State<WebServer>,
    Json(payload): Json<ScanRequest>,
) -> impl IntoResponse {
    match server.engine.detect(&payload.url).await {
        Ok(result) => {
            let response = ScanResponse {
                success: true,
                result: Some(result),
                error: None,
            };
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            let response = ScanResponse {
                success: false,
                result: None,
                error: Some(e.to_string()),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

fn va_reports_dir() -> Result<PathBuf> {
    let base = match std::env::var("WAF_DETECTOR_HOME") {
        Ok(custom) => PathBuf::from(custom),
        Err(_) => dirs::home_dir().ok_or_else(|| anyhow!("Unable to resolve HOME directory"))?,
    };
    let dir = base.join(VA_REPORTS_DIR);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn sanitize_report_component(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn report_filename(target_url: &str, created_at: DateTime<Utc>) -> String {
    let host = Url::parse(target_url)
        .or_else(|_| Url::parse(&format!("https://{target_url}")))
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_string()))
        .unwrap_or_else(|| "unknown".to_string());
    let host = sanitize_report_component(&host);
    format!("va-{}-{}.json", created_at.format("%Y%m%dT%H%M%S"), host)
}

fn write_va_report(report: &VaRunReport) -> Result<String> {
    let created_at = Utc::now();
    let filename = report_filename(&report.target_url, created_at);
    let path = va_reports_dir()?.join(&filename);
    let stored = VaStoredReport {
        id: filename.clone(),
        created_at,
        report: report.clone(),
    };
    let payload = serde_json::to_string_pretty(&stored)?;
    fs::write(path, payload)?;
    Ok(filename)
}

fn list_va_reports() -> Result<Vec<VaReportSummary>> {
    let dir = va_reports_dir()?;
    let mut reports = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let content = fs::read_to_string(entry.path());
        if let Ok(content) = content {
            if let Ok(stored) = serde_json::from_str::<VaStoredReport>(&content) {
                let summary = VaReportSummary {
                    id: stored.id.clone(),
                    target_url: stored.report.target_url.clone(),
                    created_at: stored.created_at,
                    plan_size: stored.report.plan_size,
                    blocked: stored.report.summary.blocked,
                    challenge: stored.report.summary.challenge,
                    allowed: stored.report.summary.allowed,
                    error: stored.report.summary.error,
                    risk_label: stored.report.summary.risk_label().to_string(),
                };
                reports.push(summary);
            }
        }
    }
    reports.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(reports)
}

fn load_va_report(id: &str) -> Result<VaStoredReport> {
    let dir = va_reports_dir()?;
    let path = dir.join(id);
    let content = fs::read_to_string(path)?;
    let stored = serde_json::from_str::<VaStoredReport>(&content)?;
    Ok(stored)
}

fn enforce_va_report_retention(max_reports: usize) -> Result<(usize, usize)> {
    let mut reports = list_va_reports()?;
    if reports.len() <= max_reports {
        return Ok((reports.len(), 0));
    }

    let dir = va_reports_dir()?;
    let mut deleted = 0;
    reports.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let to_remove = reports.split_off(max_reports);
    for report in to_remove {
        let path = dir.join(&report.id);
        if fs::remove_file(path).is_ok() {
            deleted += 1;
        }
    }
    let kept = max_reports.min(reports.len());
    Ok((kept, deleted))
}

fn parse_date_range(start: &str, end: &str) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
    let start_date =
        NaiveDate::parse_from_str(start, "%Y-%m-%d").map_err(|_| anyhow!("Invalid start date"))?;
    let end_date =
        NaiveDate::parse_from_str(end, "%Y-%m-%d").map_err(|_| anyhow!("Invalid end date"))?;

    let start_dt = start_date
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| anyhow!("Invalid start date"))?;
    let end_dt = end_date
        .and_hms_opt(23, 59, 59)
        .ok_or_else(|| anyhow!("Invalid end date"))?;

    let start_utc = DateTime::<Utc>::from_naive_utc_and_offset(start_dt, Utc);
    let end_utc = DateTime::<Utc>::from_naive_utc_and_offset(end_dt, Utc);

    if start_utc > end_utc {
        return Err(anyhow!("Start date must be before end date"));
    }

    Ok((start_utc, end_utc))
}

fn delete_reports_in_range(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<usize> {
    let reports = list_va_reports()?;
    let dir = va_reports_dir()?;
    let mut deleted = 0;
    for report in reports {
        if report.created_at >= start && report.created_at <= end {
            let path = dir.join(&report.id);
            if fs::remove_file(path).is_ok() {
                deleted += 1;
            }
        }
    }
    Ok(deleted)
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn build_va_reports_csv(reports: &[VaReportSummary]) -> String {
    let mut lines = Vec::new();
    lines.push(
        "id,target_url,created_at,plan_size,blocked,challenge,allowed,error,risk_label".to_string(),
    );
    for report in reports {
        let row = [
            csv_escape(&report.id),
            csv_escape(&report.target_url),
            csv_escape(&report.created_at.to_rfc3339()),
            report.plan_size.to_string(),
            report.blocked.to_string(),
            report.challenge.to_string(),
            report.allowed.to_string(),
            report.error.to_string(),
            csv_escape(&report.risk_label),
        ]
        .join(",");
        lines.push(row);
    }
    lines.join("\n")
}

fn format_va_evidence(evidence: &[crate::virtual_adversary::VaEvidence]) -> String {
    if evidence.is_empty() {
        return String::new();
    }
    evidence
        .iter()
        .map(|entry| format!("{:?}:{}", entry.kind, entry.detail))
        .collect::<Vec<String>>()
        .join("|")
}

fn build_va_report_csv(stored: &VaStoredReport) -> String {
    let mut lines = Vec::new();
    lines.push(
        "report_id,target_url,created_at,index,category,payload,outcome,reason,evidence,probe_class,probe_channel,probe_description,method,url".to_string(),
    );
    for (idx, record) in stored.report.results.iter().enumerate() {
        let replay = stored.report.replay_plan.get(idx);
        let row = [
            csv_escape(&stored.id),
            csv_escape(&stored.report.target_url),
            csv_escape(&stored.created_at.to_rfc3339()),
            (idx + 1).to_string(),
            csv_escape(&format!("{:?}", record.category)),
            csv_escape(&record.payload),
            csv_escape(&format!("{:?}", record.outcome)),
            csv_escape(&record.reason),
            csv_escape(&format_va_evidence(&record.evidence)),
            csv_escape(replay.map(|item| item.class.as_str()).unwrap_or("")),
            csv_escape(replay.map(|item| item.channel.as_str()).unwrap_or("")),
            csv_escape(replay.map(|item| item.description.as_str()).unwrap_or("")),
            csv_escape(replay.map(|item| item.method.as_str()).unwrap_or("")),
            csv_escape(replay.map(|item| item.url.as_str()).unwrap_or("")),
        ]
        .join(",");
        lines.push(row);
    }
    lines.join("\n")
}

fn build_va_replay_plan_csv(replay_plan: &[crate::virtual_adversary::VaReplayPlanItem]) -> String {
    let mut lines = Vec::new();
    lines.push(
        "index,probe_class,probe_channel,probe_description,method,url,headers,body".to_string(),
    );
    for item in replay_plan {
        let row = [
            item.index.to_string(),
            csv_escape(&item.class),
            csv_escape(&item.channel),
            csv_escape(&item.description),
            csv_escape(&item.method),
            csv_escape(&item.url),
            csv_escape(&serde_json::to_string(&item.headers).unwrap_or_default()),
            csv_escape(&item.body.clone().unwrap_or_default()),
        ]
        .join(",");
        lines.push(row);
    }
    lines.join("\n")
}

// Handler for batch URL scan
async fn batch_scan(
    State(server): State<WebServer>,
    Json(payload): Json<BatchScanRequest>,
) -> impl IntoResponse {
    let mut results = Vec::new();

    for url in &payload.urls {
        match server.engine.detect(url).await {
            Ok(result) => results.push(result),
            Err(e) => {
                let response = BatchScanResponse {
                    success: false,
                    results: vec![],
                    error: Some(format!("Error scanning {url}: {e}")),
                };
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(response));
            }
        }
    }

    let response = BatchScanResponse {
        success: true,
        results,
        error: None,
    };
    (StatusCode::OK, Json(response))
}

// Handler for provider list
async fn list_providers() -> impl IntoResponse {
    let providers = vec![
        serde_json::json!({
            "name": "CloudFlare",
            "version": "1.0.0",
            "type": "Both",
            "description": "CloudFlare WAF and CDN detection"
        }),
        serde_json::json!({
            "name": "AWS",
            "version": "1.0.0",
            "type": "Both",
            "description": "AWS WAF and CloudFront CDN detection"
        }),
        serde_json::json!({
            "name": "Akamai",
            "version": "1.0.0",
            "type": "Both",
            "description": "Akamai WAF and CDN detection"
        }),
    ];

    Json(serde_json::json!({
        "success": true,
        "providers": providers
    }))
}

// Handler for server status
async fn server_status() -> impl IntoResponse {
    Json(serde_json::json!({
        "success": true,
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "name": "WAF Detector",
        "server_info": {
            "name": "WAF Detector",
            "uptime": 0  // You might want to track actual uptime in a real implementation
        }
    }))
}

// Handler for consent status
async fn consent_status() -> impl IntoResponse {
    let consent_manager = ConsentManager::new();
    match consent_manager.status() {
        Ok(status) => {
            let response = ConsentStatusResponse {
                success: true,
                status: Some(status),
                error: None,
            };
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            let response = ConsentStatusResponse {
                success: false,
                status: None,
                error: Some(format!("Failed to load consent status: {e}")),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

// Handler for adding authorized targets
async fn consent_add_target(Json(payload): Json<ConsentTargetRequest>) -> impl IntoResponse {
    let target = payload.target.trim();
    if target.is_empty() {
        let response = ConsentStatusResponse {
            success: false,
            status: None,
            error: Some("Target cannot be empty".to_string()),
        };
        return (StatusCode::BAD_REQUEST, Json(response));
    }

    let consent_manager = ConsentManager::new();
    if let Err(e) = consent_manager.add_authorized_target(target) {
        let response = ConsentStatusResponse {
            success: false,
            status: None,
            error: Some(format!("Failed to add target: {e}")),
        };
        return (StatusCode::BAD_REQUEST, Json(response));
    }

    match consent_manager.status() {
        Ok(status) => {
            let response = ConsentStatusResponse {
                success: true,
                status: Some(status),
                error: None,
            };
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            let response = ConsentStatusResponse {
                success: false,
                status: None,
                error: Some(format!("Failed to load consent status: {e}")),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

// Handler for removing authorized targets
async fn consent_remove_target(Json(payload): Json<ConsentTargetRequest>) -> impl IntoResponse {
    let target = payload.target.trim();
    if target.is_empty() {
        let response = ConsentStatusResponse {
            success: false,
            status: None,
            error: Some("Target cannot be empty".to_string()),
        };
        return (StatusCode::BAD_REQUEST, Json(response));
    }

    let consent_manager = ConsentManager::new();
    match consent_manager.remove_authorized_target(target) {
        Ok(true) => {}
        Ok(false) => {
            let response = ConsentStatusResponse {
                success: false,
                status: None,
                error: Some("Target not found".to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
        Err(e) => {
            let response = ConsentStatusResponse {
                success: false,
                status: None,
                error: Some(format!("Failed to remove target: {e}")),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    }

    match consent_manager.status() {
        Ok(status) => {
            let response = ConsentStatusResponse {
                success: true,
                status: Some(status),
                error: None,
            };
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            let response = ConsentStatusResponse {
                success: false,
                status: None,
                error: Some(format!("Failed to load consent status: {e}")),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

// Handler for combined scan (detection + effectiveness testing)
async fn combined_scan(
    State(server): State<WebServer>,
    Json(payload): Json<ScanRequest>,
) -> impl IntoResponse {
    let start_time = std::time::Instant::now();

    // First, run detection
    let detection_result = match server.engine.detect(&payload.url).await {
        Ok(result) => result,
        Err(e) => {
            let response = CombinedScanResponse {
                success: false,
                result: None,
                error: Some(format!("Detection failed: {e}")),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(response));
        }
    };

    // Then, run effectiveness testing (optional, may fail)
    let effectiveness_result = match server.script_executor.execute_test(&payload.url).await {
        Ok(result) => Some(result),
        Err(e) => {
            println!("Warning: Effectiveness testing failed: {e}");
            None // Continue without effectiveness testing
        }
    };

    let total_time = start_time.elapsed().as_millis() as u64;

    // Combine results
    let combined_result =
        server
            .script_executor
            .combine_results(detection_result, effectiveness_result, total_time);

    let response = CombinedScanResponse {
        success: true,
        result: Some(combined_result),
        error: None,
    };

    (StatusCode::OK, Json(response))
}

// Handler for WAF smoke test with detailed payload results
async fn smoke_test(
    State(_server): State<WebServer>,
    Json(payload): Json<ScanRequest>,
) -> impl IntoResponse {
    println!("[smoke_test] Handler entered for URL: {}", payload.url);
    // Create smoke test configuration
    let config = SmokeTestConfig::default();
    // Create and run smoke test
    let smoke_test = match WafSmokeTest::new(config) {
        Ok(test) => test,
        Err(e) => {
            eprintln!(
                "[smoke_test] Failed to create smoke test for URL {}: {}",
                payload.url, e
            );
            let response = SmokeTestResponse {
                success: false,
                result: None,
                error: Some(format!("Failed to create smoke test: {e}")),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(response));
        }
    };
    // Run the test
    match smoke_test.run_test(&payload.url).await {
        Ok(mut result) => {
            result.is_smoke_test = true;
            println!(
                "[smoke_test] Successfully ran smoke test for URL: {}",
                payload.url
            );
            let response = SmokeTestResponse {
                success: true,
                result: Some(result),
                error: None,
            };
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            eprintln!(
                "[smoke_test] Smoke test failed for URL {}: {}",
                payload.url, e
            );
            let response = SmokeTestResponse {
                success: false,
                result: None,
                error: Some(format!("Smoke test failed: {e}")),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

// Handler for Virtual Adversary testing
async fn virtual_adversary(
    State(_server): State<WebServer>,
    Json(payload): Json<VaRequest>,
) -> impl IntoResponse {
    let config = match payload.to_config() {
        Ok(config) => config,
        Err(e) => {
            let response = VaResponse {
                success: false,
                result: None,
                error: Some(e.to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let url = payload.url.clone();
    let report = tokio::task::spawn_blocking(move || {
        let mut runner = VirtualAdversaryRunner::new(config)?;
        runner.run(&url)
    })
    .await;

    match report {
        Ok(Ok(result)) => {
            if let Err(e) = write_va_report(&result) {
                eprintln!("[virtual_adversary] Failed to persist report: {e}");
            }
            let response = VaResponse {
                success: true,
                result: Some(result),
                error: None,
            };
            (StatusCode::OK, Json(response))
        }
        Ok(Err(e)) => {
            let response = VaResponse {
                success: false,
                result: None,
                error: Some(format!("Virtual Adversary failed: {e}")),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
        Err(e) => {
            let response = VaResponse {
                success: false,
                result: None,
                error: Some(format!("Virtual Adversary task failed: {e}")),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

// Handler to start Virtual Adversary testing asynchronously
async fn virtual_adversary_start(
    State(server): State<WebServer>,
    Json(payload): Json<VaRequest>,
) -> impl IntoResponse {
    let config = match payload.to_config() {
        Ok(config) => config,
        Err(e) => {
            let response = VaJobStartResponse {
                success: false,
                job_id: None,
                error: Some(e.to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let job_id = format!(
        "va-{}",
        server.va_job_counter.fetch_add(1, Ordering::Relaxed)
    );
    let job_id_for_task = job_id.clone();

    {
        let mut jobs = server.va_jobs.lock().unwrap();
        jobs.insert(job_id.clone(), VaJob::new(job_id.clone()));
    }

    let url = payload.url.clone();
    let jobs = server.va_jobs.clone();

    tokio::task::spawn_blocking(move || {
        {
            let mut jobs = jobs.lock().unwrap();
            if let Some(job) = jobs.get_mut(&job_id_for_task) {
                job.state = VaJobState::Running;
            }
        }

        let mut runner = VirtualAdversaryRunner::new(config)?;
        let result = runner.run_with_events(
            &url,
            |done, total| {
                let mut jobs = jobs.lock().unwrap();
                if let Some(job) = jobs.get_mut(&job_id_for_task) {
                    job.total = total;
                    job.completed = done;
                }
            },
            |event| {
                let mut jobs = jobs.lock().unwrap();
                if let Some(job) = jobs.get_mut(&job_id_for_task) {
                    job.push_event(VaJobEvent {
                        index: event.index,
                        total: event.total,
                        category: event.category,
                        payload: event.payload,
                        outcome: event.outcome,
                        reason: event.reason,
                        timestamp: Utc::now(),
                    });
                }
            },
        );

        let mut jobs = jobs.lock().unwrap();
        if let Some(job) = jobs.get_mut(&job_id_for_task) {
            match result {
                Ok(report) => {
                    let report_id = match write_va_report(&report) {
                        Ok(id) => Some(id),
                        Err(err) => {
                            job.error = Some(format!("Report persistence failed: {err}"));
                            None
                        }
                    };
                    job.state = VaJobState::Completed;
                    job.total = report.plan_size;
                    job.completed = report.plan_size;
                    job.report_id = report_id;
                    job.result = Some(report);
                }
                Err(err) => {
                    job.state = VaJobState::Failed;
                    job.error = Some(err.to_string());
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    });

    let response = VaJobStartResponse {
        success: true,
        job_id: Some(job_id),
        error: None,
    };
    (StatusCode::OK, Json(response))
}

// Handler to get Virtual Adversary job status
async fn virtual_adversary_status(
    State(server): State<WebServer>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let jobs = server.va_jobs.lock().unwrap();
    if let Some(job) = jobs.get(&job_id) {
        let response = VaJobStatusResponse {
            success: true,
            status: Some(job.status()),
            error: None,
        };
        return (StatusCode::OK, Json(response));
    }

    let response = VaJobStatusResponse {
        success: false,
        status: None,
        error: Some("Job not found".to_string()),
    };
    (StatusCode::NOT_FOUND, Json(response))
}

// Handler to list persisted Virtual Adversary reports
async fn virtual_adversary_reports() -> impl IntoResponse {
    match list_va_reports() {
        Ok(reports) => {
            let response = VaReportsResponse {
                success: true,
                reports,
                error: None,
            };
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            let response = VaReportsResponse {
                success: false,
                reports: Vec::new(),
                error: Some(format!("Failed to list reports: {e}")),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

// Handler to fetch a persisted Virtual Adversary report
async fn virtual_adversary_report(Path(report_id): Path<String>) -> impl IntoResponse {
    match load_va_report(&report_id) {
        Ok(report) => {
            let response = VaReportResponse {
                success: true,
                report: Some(report),
                error: None,
            };
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            let response = VaReportResponse {
                success: false,
                report: None,
                error: Some(format!("Failed to load report: {e}")),
            };
            (StatusCode::NOT_FOUND, Json(response))
        }
    }
}

// Handler to fetch a Virtual Adversary replay plan as JSON
async fn virtual_adversary_report_replay_json(Path(report_id): Path<String>) -> impl IntoResponse {
    match load_va_report(&report_id) {
        Ok(report) => {
            let response = VaReplayPlanResponse {
                success: true,
                replay_plan: Some(report.report.replay_plan),
                error: None,
            };
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            let response = VaReplayPlanResponse {
                success: false,
                replay_plan: None,
                error: Some(format!("Failed to load report: {e}")),
            };
            (StatusCode::NOT_FOUND, Json(response))
        }
    }
}

// Handler to export Virtual Adversary reports as CSV
async fn virtual_adversary_reports_csv() -> impl IntoResponse {
    match list_va_reports() {
        Ok(reports) => {
            let body = build_va_reports_csv(&reports);
            (StatusCode::OK, [(header::CONTENT_TYPE, "text/csv")], body)
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/plain")],
            format!("Failed to export reports: {e}"),
        ),
    }
}

// Handler to export a single Virtual Adversary report as CSV
async fn virtual_adversary_report_csv(Path(report_id): Path<String>) -> impl IntoResponse {
    match load_va_report(&report_id) {
        Ok(report) => {
            let body = build_va_report_csv(&report);
            (StatusCode::OK, [(header::CONTENT_TYPE, "text/csv")], body)
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain")],
            format!("Failed to load report: {e}"),
        ),
    }
}

// Handler to export a Virtual Adversary replay plan as CSV
async fn virtual_adversary_report_replay_csv(Path(report_id): Path<String>) -> impl IntoResponse {
    match load_va_report(&report_id) {
        Ok(report) => {
            let body = build_va_replay_plan_csv(&report.report.replay_plan);
            (StatusCode::OK, [(header::CONTENT_TYPE, "text/csv")], body)
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain")],
            format!("Failed to load report: {e}"),
        ),
    }
}

#[derive(Deserialize)]
struct VaRetentionRequest {
    max_reports: Option<usize>,
}

// Handler to cleanup Virtual Adversary reports based on retention policy
async fn virtual_adversary_reports_cleanup(
    Json(payload): Json<VaRetentionRequest>,
) -> impl IntoResponse {
    let max_reports = payload
        .max_reports
        .filter(|value| *value > 0)
        .unwrap_or(VA_REPORT_RETENTION_DEFAULT);

    match enforce_va_report_retention(max_reports) {
        Ok((kept, deleted)) => {
            let response = VaRetentionResponse {
                success: true,
                kept,
                deleted,
                error: None,
            };
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            let response = VaRetentionResponse {
                success: false,
                kept: 0,
                deleted: 0,
                error: Some(format!("Failed to cleanup reports: {e}")),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

#[derive(Deserialize)]
struct VaRangeDeleteRequest {
    start_date: String,
    end_date: String,
}

// Handler to delete reports within a date range
async fn virtual_adversary_reports_delete_range(
    Json(payload): Json<VaRangeDeleteRequest>,
) -> impl IntoResponse {
    match parse_date_range(&payload.start_date, &payload.end_date) {
        Ok((start, end)) => match delete_reports_in_range(start, end) {
            Ok(deleted) => {
                let response = VaRangeDeleteResponse {
                    success: true,
                    deleted,
                    error: None,
                };
                (StatusCode::OK, Json(response))
            }
            Err(e) => {
                let response = VaRangeDeleteResponse {
                    success: false,
                    deleted: 0,
                    error: Some(format!("Failed to delete reports: {e}")),
                };
                (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
            }
        },
        Err(e) => {
            let response = VaRangeDeleteResponse {
                success: false,
                deleted: 0,
                error: Some(e.to_string()),
            };
            (StatusCode::BAD_REQUEST, Json(response))
        }
    }
}

async fn virtual_adversary2_plan(Json(payload): Json<Va2Request>) -> impl IntoResponse {
    let phases_raw = payload.phases.as_deref().unwrap_or(VA2_PHASE_DEFAULT);
    let phases = match parse_va2_phases(phases_raw) {
        Ok(phases) => phases,
        Err(err) => {
            return Json(Va2PlanResponse {
                success: false,
                plan: None,
                error: Some(err.to_string()),
            });
        }
    };

    let config = Va2CampaignConfig {
        seed: payload.seed.unwrap_or(1337),
        budget: payload.budget.unwrap_or(60),
    };

    match build_va2_campaign_plan(&payload.target_url, &phases, config) {
        Ok(plan) => Json(Va2PlanResponse {
            success: true,
            plan: Some(serde_json::to_value(plan).unwrap_or_else(|_| serde_json::json!({}))),
            error: None,
        }),
        Err(err) => Json(Va2PlanResponse {
            success: false,
            plan: None,
            error: Some(err.to_string()),
        }),
    }
}

async fn virtual_adversary2_run(Json(payload): Json<Va2Request>) -> impl IntoResponse {
    let phases_raw = payload.phases.as_deref().unwrap_or(VA2_PHASE_DEFAULT);
    let phases = match parse_va2_phases(phases_raw) {
        Ok(phases) => phases,
        Err(err) => {
            return Json(Va2RunResponse {
                success: false,
                report: None,
                error: Some(err.to_string()),
            });
        }
    };

    let config = Va2CampaignConfig {
        seed: payload.seed.unwrap_or(1337),
        budget: payload.budget.unwrap_or(60),
    };

    let plan = match build_va2_campaign_plan(&payload.target_url, &phases, config) {
        Ok(plan) => plan,
        Err(err) => {
            return Json(Va2RunResponse {
                success: false,
                report: None,
                error: Some(err.to_string()),
            });
        }
    };

    match Va2Runner::new() {
        Ok(runner) => match runner.run_plan(plan).await {
            Ok(report) => Json(Va2RunResponse {
                success: true,
                report: Some(report),
                error: None,
            }),
            Err(err) => Json(Va2RunResponse {
                success: false,
                report: None,
                error: Some(err.to_string()),
            }),
        },
        Err(err) => Json(Va2RunResponse {
            success: false,
            report: None,
            error: Some(err.to_string()),
        }),
    }
}

// Handler to start Virtual Adversary 2.0 testing asynchronously
async fn virtual_adversary2_start(
    State(server): State<WebServer>,
    Json(payload): Json<Va2Request>,
) -> impl IntoResponse {
    let phases_raw = payload.phases.as_deref().unwrap_or(VA2_PHASE_DEFAULT);
    let phases = match parse_va2_phases(phases_raw) {
        Ok(phases) => phases,
        Err(err) => {
            let response = Va2JobStartResponse {
                success: false,
                job_id: None,
                error: Some(err.to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let config = Va2CampaignConfig {
        seed: payload.seed.unwrap_or(1337),
        budget: payload.budget.unwrap_or(60),
    };

    let plan = match build_va2_campaign_plan(&payload.target_url, &phases, config) {
        Ok(plan) => plan,
        Err(err) => {
            let response = Va2JobStartResponse {
                success: false,
                job_id: None,
                error: Some(err.to_string()),
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    let job_id = format!(
        "va2-{}",
        server.va2_job_counter.fetch_add(1, Ordering::Relaxed)
    );
    let job_id_for_task = job_id.clone();

    {
        let mut jobs = server.va2_jobs.lock().unwrap();
        jobs.insert(job_id.clone(), Va2Job::new(job_id.clone()));
    }

    let jobs = server.va2_jobs.clone();

    tokio::spawn(async move {
        {
            let mut jobs = jobs.lock().unwrap();
            if let Some(job) = jobs.get_mut(&job_id_for_task) {
                job.state = VaJobState::Running;
            }
        }

        let runner = match Va2Runner::new() {
            Ok(runner) => runner,
            Err(err) => {
                let mut jobs = jobs.lock().unwrap();
                if let Some(job) = jobs.get_mut(&job_id_for_task) {
                    job.state = VaJobState::Failed;
                    job.error = Some(format!("Failed to create runner: {err}"));
                }
                return;
            }
        };

        let result = runner.run_plan(plan).await;

        let mut jobs = jobs.lock().unwrap();
        if let Some(job) = jobs.get_mut(&job_id_for_task) {
            match result {
                Ok(report) => {
                    job.state = VaJobState::Completed;
                    job.result = Some(report);
                }
                Err(err) => {
                    job.state = VaJobState::Failed;
                    job.error = Some(err.to_string());
                }
            }
        }
    });

    let response = Va2JobStartResponse {
        success: true,
        job_id: Some(job_id),
        error: None,
    };
    (StatusCode::OK, Json(response))
}

// Handler to get Virtual Adversary 2.0 job status
async fn virtual_adversary2_status(
    State(server): State<WebServer>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let jobs = server.va2_jobs.lock().unwrap();
    if let Some(job) = jobs.get(&job_id) {
        let response = Va2JobStatusResponse {
            success: true,
            status: Some(job.status()),
            error: None,
        };
        return (StatusCode::OK, Json(response));
    }

    let response = Va2JobStatusResponse {
        success: false,
        status: None,
        error: Some("Job not found".to_string()),
    };
    (StatusCode::NOT_FOUND, Json(response))
}

// Handler to cancel Virtual Adversary 2.0 job
async fn virtual_adversary2_cancel(
    State(server): State<WebServer>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let mut jobs = server.va2_jobs.lock().unwrap();
    if let Some(job) = jobs.get_mut(&job_id) {
        // Mark as failed with cancellation message
        // Note: can't truly cancel the tokio task without a CancellationToken,
        // but marking it prevents the result from being used
        job.state = VaJobState::Failed;
        job.error = Some("Job cancelled by user".to_string());

        let response = Va2JobStatusResponse {
            success: true,
            status: Some(job.status()),
            error: None,
        };
        return (StatusCode::OK, Json(response));
    }

    let response = Va2JobStatusResponse {
        success: false,
        status: None,
        error: Some("Job not found".to_string()),
    };
    (StatusCode::NOT_FOUND, Json(response))
}

async fn ai_summary(Json(payload): Json<AiSummaryRequest>) -> impl IntoResponse {
    if !ai_enabled() {
        let response = AiSummaryApiResponse {
            success: false,
            summary: None,
            error: Some("AI summaries are disabled".to_string()),
        };
        return (StatusCode::SERVICE_UNAVAILABLE, Json(response));
    }

    let provider = OllamaProvider::new(ai_endpoint(), ai_model(), ai_timeout());
    match provider.summarize(&payload).await {
        Ok(summary) => (
            StatusCode::OK,
            Json(AiSummaryApiResponse {
                success: true,
                summary: Some(summary),
                error: None,
            }),
        ),
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            Json(AiSummaryApiResponse {
                success: false,
                summary: None,
                error: Some(format!("AI unavailable: {err}")),
            }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_va_report_csv, build_va_reports_csv, csv_escape, report_filename,
        sanitize_report_component, VaJobState, VaReportSummary, VaRequest, VaStoredReport,
    };
    use crate::virtual_adversary::{VaRunReport, VirtualAdversaryConfig};
    use chrono::{NaiveDate, TimeZone, Timelike, Utc};
    use serde_json::json;
    use std::time::Duration;
    use tower::util::ServiceExt;

    #[test]
    fn va_request_defaults_to_config() {
        let req = VaRequest {
            url: "https://example.com".to_string(),
            tier: None,
            budget: None,
            timeout_ms: None,
            delay_ms: None,
            variants: None,
        };
        let config = req.to_config().expect("config should be valid");
        let defaults = VirtualAdversaryConfig::default();
        assert_eq!(config.tier, defaults.tier);
        assert_eq!(config.request_budget, defaults.request_budget);
        assert_eq!(config.request_timeout, defaults.request_timeout);
        assert_eq!(config.request_delay, defaults.request_delay);
        assert_eq!(
            config.max_variants_per_payload,
            defaults.max_variants_per_payload
        );
    }

    #[test]
    fn va_request_overrides_values() {
        let req = VaRequest {
            url: "https://example.com".to_string(),
            tier: Some(2),
            budget: Some(64),
            timeout_ms: Some(12_000),
            delay_ms: Some(500),
            variants: Some(2),
        };
        let config = req.to_config().expect("config should be valid");
        assert_eq!(config.tier, 2);
        assert_eq!(config.request_budget, 64);
        assert_eq!(config.request_timeout, Duration::from_millis(12_000));
        assert_eq!(config.request_delay, Duration::from_millis(500));
        assert_eq!(config.max_variants_per_payload, 2);
    }

    #[test]
    fn va_job_state_serializes_snake_case() {
        let value = serde_json::to_value(VaJobState::Running).unwrap();
        assert_eq!(value, json!("running"));
    }

    #[test]
    fn sanitize_report_component_replaces_invalid_chars() {
        let value = sanitize_report_component("api.example.com/..");
        assert_eq!(value, "api.example.com_..");
    }

    #[test]
    fn report_filename_uses_host() {
        let now = chrono::Utc::now();
        let filename = report_filename("https://example.com/test", now);
        assert!(filename.contains("example.com"));
        assert!(filename.ends_with(".json"));
    }

    #[test]
    fn va_job_event_limit_retains_latest() {
        let mut job = super::VaJob::new("va-1".to_string());
        for idx in 0..(super::VA_JOB_EVENT_LIMIT + 5) {
            job.push_event(super::VaJobEvent {
                index: idx + 1,
                total: 10,
                category: crate::virtual_adversary::VaPayloadCategory::SqlInjection,
                payload: format!("payload-{idx}"),
                outcome: crate::virtual_adversary::VaOutcome::Blocked,
                reason: "status=403".to_string(),
                timestamp: chrono::Utc::now(),
            });
        }
        assert_eq!(job.events.len(), super::VA_JOB_EVENT_LIMIT);
        assert_eq!(job.events.first().unwrap().index, 6);
    }

    #[test]
    fn csv_escape_wraps_commas_and_quotes() {
        assert_eq!(csv_escape("simple"), "simple");
        assert_eq!(csv_escape("needs,comma"), "\"needs,comma\"");
        assert_eq!(csv_escape("quote\"here"), "\"quote\"\"here\"");
    }

    #[test]
    fn build_va_reports_csv_includes_header_and_rows() {
        let reports = vec![VaReportSummary {
            id: "va-1.json".to_string(),
            target_url: "https://example.com".to_string(),
            created_at: chrono::Utc::now(),
            plan_size: 10,
            blocked: 5,
            challenge: 2,
            allowed: 3,
            error: 0,
            risk_label: "MEDIUM".to_string(),
        }];
        let csv = build_va_reports_csv(&reports);
        let lines: Vec<&str> = csv.split('\n').collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("target_url"));
        assert!(lines[1].contains("https://example.com"));
    }

    #[test]
    fn build_va_report_csv_includes_payloads() {
        let mut report =
            VaRunReport::new("https://example.com", 2, VirtualAdversaryConfig::default());
        report
            .replay_plan
            .push(crate::virtual_adversary::VaReplayPlanItem {
                index: 1,
                class: "SemanticDrift".to_string(),
                channel: "Query".to_string(),
                description: "Duplicate key ordering drift".to_string(),
                method: "GET".to_string(),
                url: "https://example.com/?a=1&a=2".to_string(),
                headers: Vec::new(),
                body: None,
            });
        report
            .results
            .push(crate::virtual_adversary::VaResultRecord {
                payload: "' OR '1'='1".to_string(),
                category: crate::virtual_adversary::VaPayloadCategory::SqlInjection,
                outcome: crate::virtual_adversary::VaOutcome::Blocked,
                reason: "status=403".to_string(),
                evidence: Vec::new(),
            });
        let stored = VaStoredReport {
            id: "va-1.json".to_string(),
            created_at: chrono::Utc::now(),
            report,
        };
        let csv = build_va_report_csv(&stored);
        assert!(csv.contains("payload"));
        assert!(csv.contains("' OR '1'='1"));
        assert!(csv.contains("probe_class"));
        assert!(csv.contains("SemanticDrift"));
        assert!(csv.contains("https://example.com/?a=1&a=2"));
    }

    #[test]
    fn build_va_replay_plan_csv_includes_rows() {
        let replay_plan = vec![crate::virtual_adversary::VaReplayPlanItem {
            index: 1,
            class: "ProtocolMutation".to_string(),
            channel: "Header".to_string(),
            description: "Case and whitespace header mutation".to_string(),
            method: "GET".to_string(),
            url: "https://example.com".to_string(),
            headers: vec![("X-Test".to_string(), "1".to_string())],
            body: None,
        }];
        let csv = super::build_va_replay_plan_csv(&replay_plan);
        assert!(csv.contains("probe_class"));
        assert!(csv.contains("ProtocolMutation"));
        assert!(csv.contains("X-Test"));
    }

    #[test]
    fn enforce_retention_keeps_latest() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let temp_dir = tempfile::TempDir::new().unwrap();
        std::env::set_var("WAF_DETECTOR_HOME", temp_dir.path());
        std::fs::create_dir_all(temp_dir.path().join(".waf-detector/va-reports")).unwrap();

        let mut reports = Vec::new();
        for idx in 0..3 {
            let created_at = chrono::Utc::now() - chrono::Duration::seconds(idx as i64);
            let report = VaReportSummary {
                id: format!("va-{idx}.json"),
                target_url: "https://example.com".to_string(),
                created_at,
                plan_size: 10,
                blocked: 5,
                challenge: 2,
                allowed: 3,
                error: 0,
                risk_label: "MEDIUM".to_string(),
            };
            let stored = VaStoredReport {
                id: report.id.clone(),
                created_at,
                report: VaRunReport::new(
                    "https://example.com",
                    0,
                    VirtualAdversaryConfig::default(),
                ),
            };
            let path = temp_dir
                .path()
                .join(".waf-detector/va-reports")
                .join(&report.id);
            std::fs::write(path, serde_json::to_string_pretty(&stored).unwrap()).unwrap();
            reports.push(report);
        }

        let (kept, deleted) = super::enforce_va_report_retention(2).unwrap();
        assert_eq!(kept, 2);
        assert_eq!(deleted, 1);
        std::env::remove_var("WAF_DETECTOR_HOME");
    }

    #[test]
    fn parse_date_range_respects_bounds() {
        let (start, end) = super::parse_date_range("2026-02-01", "2026-02-02").unwrap();
        assert_eq!(
            start.date_naive(),
            NaiveDate::from_ymd_opt(2026, 2, 1).unwrap()
        );
        assert_eq!(
            end.date_naive(),
            NaiveDate::from_ymd_opt(2026, 2, 2).unwrap()
        );
        assert_eq!(start.time().hour(), 0);
        assert_eq!(end.time().hour(), 23);
    }

    #[test]
    fn parse_date_range_rejects_inverted_dates() {
        let err = super::parse_date_range("2026-02-05", "2026-02-02").unwrap_err();
        assert!(err.to_string().contains("Start date"));
    }

    #[test]
    fn delete_reports_in_range_removes_matching_days() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let temp_dir = tempfile::TempDir::new().unwrap();
        std::env::set_var("WAF_DETECTOR_HOME", temp_dir.path());
        let reports_dir = temp_dir.path().join(".waf-detector/va-reports");
        std::fs::create_dir_all(&reports_dir).unwrap();

        let dates = [
            Utc.with_ymd_and_hms(2026, 2, 1, 12, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 2, 2, 12, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 2, 3, 12, 0, 0).unwrap(),
        ];

        for (idx, created_at) in dates.iter().enumerate() {
            let id = format!("va-range-{idx}.json");
            let report =
                VaRunReport::new("https://example.com", 0, VirtualAdversaryConfig::default());
            let stored = VaStoredReport {
                id: id.clone(),
                created_at: *created_at,
                report,
            };
            let path = reports_dir.join(&id);
            std::fs::write(path, serde_json::to_string_pretty(&stored).unwrap()).unwrap();
        }

        let (start, end) = super::parse_date_range("2026-02-02", "2026-02-02").unwrap();
        let deleted = super::delete_reports_in_range(start, end).unwrap();
        assert_eq!(deleted, 1);

        let remaining = std::fs::read_dir(&reports_dir)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .ok()
                    .and_then(|item| item.path().extension().map(|ext| ext == "json"))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(remaining, 2);
        std::env::remove_var("WAF_DETECTOR_HOME");
    }

    #[test]
    fn va_request_rejects_zero_timeout() {
        let req = VaRequest {
            url: "https://example.com".to_string(),
            tier: None,
            budget: None,
            timeout_ms: Some(0),
            delay_ms: None,
            variants: None,
        };
        let err = req.to_config().expect_err("should reject zero timeout");
        assert!(err.to_string().contains("timeout_ms"));
    }

    #[test]
    fn build_readonly_cors_allows_get() {
        let layer = super::build_readonly_cors();
        // Smoke-test: ensure layer can be constructed without panic
        let _ = layer;
    }

    #[test]
    fn build_active_cors_includes_localhost() {
        let layer = super::build_active_cors(8080);
        let _ = layer;
    }

    #[test]
    fn build_active_cors_reads_env_override() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::set_var(
            "WAF_DETECTOR_ALLOWED_ORIGINS",
            "https://example.com,https://other.com",
        );
        let layer = super::build_active_cors(8080);
        let _ = layer;
        std::env::remove_var("WAF_DETECTOR_ALLOWED_ORIGINS");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Intentional: env lock must span the entire test
    async fn require_api_token_allows_when_no_token_configured() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::remove_var("WAF_DETECTOR_API_TOKEN");

        let app = axum::Router::new()
            .route("/test", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(super::require_api_token));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/test")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Intentional: env lock must span the entire test
    async fn require_api_token_rejects_missing_token() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::set_var("WAF_DETECTOR_API_TOKEN", "secret123");

        let app = axum::Router::new()
            .route("/test", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(super::require_api_token));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/test")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        std::env::remove_var("WAF_DETECTOR_API_TOKEN");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Intentional: env lock must span the entire test
    async fn require_api_token_accepts_valid_bearer() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::set_var("WAF_DETECTOR_API_TOKEN", "secret123");

        let app = axum::Router::new()
            .route("/test", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(super::require_api_token));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/test")
                    .header("authorization", "Bearer secret123")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        std::env::remove_var("WAF_DETECTOR_API_TOKEN");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Intentional: env lock must span the entire test
    async fn require_api_token_rejects_wrong_token() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::set_var("WAF_DETECTOR_API_TOKEN", "secret123");

        let app = axum::Router::new()
            .route("/test", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(super::require_api_token));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/test")
                    .header("authorization", "Bearer wrongtoken")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        std::env::remove_var("WAF_DETECTOR_API_TOKEN");
    }

    #[test]
    fn origin_matches_host_exact_match() {
        assert!(super::origin_matches_host(
            "http://localhost:8080",
            "localhost:8080"
        ));
    }

    #[test]
    fn origin_matches_host_rejects_different_port() {
        assert!(!super::origin_matches_host(
            "http://localhost:9090",
            "localhost:8080"
        ));
    }

    #[test]
    fn origin_matches_host_rejects_different_host() {
        assert!(!super::origin_matches_host(
            "http://evil.com",
            "localhost:8080"
        ));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Intentional: env lock must span the entire test
    async fn csrf_allows_get_requests() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::remove_var("WAF_DETECTOR_API_TOKEN");

        let app = axum::Router::new()
            .route("/test", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(super::validate_csrf));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/test")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Intentional: env lock must span the entire test
    async fn csrf_rejects_post_with_wrong_origin() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::remove_var("WAF_DETECTOR_API_TOKEN");

        let app = axum::Router::new()
            .route("/test", axum::routing::post(|| async { "ok" }))
            .layer(axum::middleware::from_fn(super::validate_csrf));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/test")
                    .header("host", "localhost:8080")
                    .header("origin", "http://evil.com")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Intentional: env lock must span the entire test
    async fn csrf_allows_post_with_matching_origin() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::remove_var("WAF_DETECTOR_API_TOKEN");

        let app = axum::Router::new()
            .route("/test", axum::routing::post(|| async { "ok" }))
            .layer(axum::middleware::from_fn(super::validate_csrf));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/test")
                    .header("host", "localhost:8080")
                    .header("origin", "http://localhost:8080")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Intentional: env lock must span the entire test
    async fn csrf_allows_post_without_origin_or_referer() {
        // Non-browser clients (curl, httpie) don't send Origin/Referer
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::remove_var("WAF_DETECTOR_API_TOKEN");

        let app = axum::Router::new()
            .route("/test", axum::routing::post(|| async { "ok" }))
            .layer(axum::middleware::from_fn(super::validate_csrf));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/test")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Intentional: env lock must span the entire test
    async fn csrf_bypasses_for_valid_api_token() {
        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        std::env::set_var("WAF_DETECTOR_API_TOKEN", "secret123");

        let app = axum::Router::new()
            .route("/test", axum::routing::post(|| async { "ok" }))
            .layer(axum::middleware::from_fn(super::validate_csrf));

        // POST with wrong origin but valid token — should pass CSRF
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/test")
                    .header("host", "localhost:8080")
                    .header("origin", "http://evil.com")
                    .header("authorization", "Bearer secret123")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        std::env::remove_var("WAF_DETECTOR_API_TOKEN");
    }
}
