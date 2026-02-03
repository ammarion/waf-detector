use crate::effectiveness::consent::{ConsentManager, ConsentStatus};
use crate::engine::DetectionEngine;
use crate::payload::waf_smoke_test::{SmokeTestConfig, SmokeTestResult, WafSmokeTest};
use crate::script_executor::{CombinedResult, ScriptExecutor};
use crate::virtual_adversary::{VaRunReport, VirtualAdversaryConfig, VirtualAdversaryRunner};
use crate::DetectionResult;
use anyhow::{anyhow, Result};
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
use tower_http::{cors::CorsLayer, services::ServeDir};

pub mod templates;

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
}

#[derive(Debug)]
struct VaJob {
    id: String,
    state: VaJobState,
    total: usize,
    completed: usize,
    result: Option<VaRunReport>,
    error: Option<String>,
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
        }
    }
}

#[derive(Serialize)]
pub struct VaJobStatusResponse {
    success: bool,
    status: Option<VaJobStatus>,
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
        let result = runner.run_with_progress(&url, |done, total| {
            let mut jobs = jobs.lock().unwrap();
            if let Some(job) = jobs.get_mut(&job_id_for_task) {
                job.total = total;
                job.completed = done;
            }
        });

        let mut jobs = jobs.lock().unwrap();
        if let Some(job) = jobs.get_mut(&job_id_for_task) {
            match result {
                Ok(report) => {
                    job.state = VaJobState::Completed;
                    job.total = report.plan_size;
                    job.completed = report.plan_size;
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

#[cfg(test)]
mod tests {
    use super::{VaJobState, VaRequest};
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
