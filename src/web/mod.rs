use crate::effectiveness::consent::{ConsentManager, ConsentStatus};
use crate::engine::DetectionEngine;
use crate::payload::waf_smoke_test::{SmokeTestConfig, SmokeTestResult, WafSmokeTest};
use crate::script_executor::{CombinedResult, ScriptExecutor};
use crate::virtual_adversary::{
    VaOutcome, VaPayloadCategory, VaRunReport, VirtualAdversaryConfig, VirtualAdversaryRunner,
};
use crate::DetectionResult;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::{fs, path::PathBuf};
use url::Url;
use tower_http::{cors::CorsLayer, services::ServeDir};

pub mod templates;

const VA_REPORTS_DIR: &str = ".waf-detector/va-reports";

#[derive(Clone)]
pub struct WebServer {
    engine: Arc<DetectionEngine>,
    script_executor: Arc<ScriptExecutor>,
    va_jobs: Arc<Mutex<HashMap<String, VaJob>>>,
    va_job_counter: Arc<AtomicU64>,
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

#[derive(Serialize)]
pub struct VaResponse {
    success: bool,
    result: Option<VaRunReport>,
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
        }
    }

    pub async fn start(self, port: u16) -> Result<()> {
        let app = Router::new()
            // Static files
            .nest_service("/static", ServeDir::new("web/static"))
            // API routes
            .route("/api/scan", post(scan_url))
            .route("/api/combined-scan", post(combined_scan))
            .route("/api/smoke-test", post(smoke_test))
            .route("/api/batch-scan", post(batch_scan))
            .route("/api/virtual-adversary", post(virtual_adversary))
            .route("/api/virtual-adversary/start", post(virtual_adversary_start))
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
            .route("/api/consent-status", get(consent_status))
            .route("/api/consent/add-target", post(consent_add_target))
            .route("/api/consent/remove-target", post(consent_remove_target))
            .route("/api/providers", get(list_providers))
            .route("/api/status", get(server_status))
            // Web pages
            .route("/", get(dashboard))
            .route("/dashboard", get(dashboard))
            .route("/api-docs", get(api_docs))
            // Add CORS for development
            .layer(CorsLayer::permissive())
            .with_state(self);

        let addr = format!("0.0.0.0:{port}");
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
    Html(templates::DASHBOARD_HTML)
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
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Unable to resolve HOME directory"))?;
    let dir = home.join(VA_REPORTS_DIR);
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
    format!(
        "va-{}-{}.json",
        created_at.format("%Y%m%dT%H%M%S"),
        host
    )
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

#[cfg(test)]
mod tests {
    use super::{report_filename, sanitize_report_component, VaJobState, VaRequest};
    use crate::virtual_adversary::VirtualAdversaryConfig;
    use std::time::Duration;
    use serde_json::json;

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
}
