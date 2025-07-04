use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tower_http::{services::ServeDir, cors::CorsLayer};
use serde::{Deserialize, Serialize};
use crate::engine::DetectionEngine;
use crate::DetectionResult;
use crate::script_executor::{ScriptExecutor, CombinedResult};
use anyhow::Result;

pub mod templates;

#[derive(Clone)]
pub struct WebServer {
    engine: Arc<DetectionEngine>,
    script_executor: Arc<ScriptExecutor>,
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

impl WebServer {
    pub fn new(engine: DetectionEngine) -> Self {
        Self {
            engine: Arc::new(engine),
            script_executor: Arc::new(ScriptExecutor::default()),
        }
    }

    pub async fn start(self, port: u16) -> Result<()> {
        let app = Router::new()
            // Static files
            .nest_service("/static", ServeDir::new("web/static"))
            // API routes
            .route("/api/scan", post(scan_url))
            .route("/api/combined-scan", post(combined_scan))
            .route("/api/batch-scan", post(batch_scan))
            .route("/api/providers", get(list_providers))
            .route("/api/status", get(server_status))
            // Web pages
            .route("/", get(dashboard))
            .route("/dashboard", get(dashboard))
            .route("/api-docs", get(api_docs))
            // Add CORS for development
            .layer(CorsLayer::permissive())
            .with_state(self);

        let addr = format!("0.0.0.0:{}", port);
        println!("🌐 WAF Detector Web Server starting on http://localhost:{}", port);
        println!("📊 Dashboard: http://localhost:{}/dashboard", port);
        println!("📖 API Docs: http://localhost:{}/api-docs", port);
        
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
                    error: Some(format!("Error scanning {}: {}", url, e)),
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
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
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
                error: Some(format!("Detection failed: {}", e)),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(response));
        }
    };
    
    // Then, run effectiveness testing (optional, may fail)
    let effectiveness_result = match server.script_executor.execute_test(&payload.url).await {
        Ok(result) => Some(result),
        Err(e) => {
            println!("Warning: Effectiveness testing failed: {}", e);
            None // Continue without effectiveness testing
        }
    };
    
    let total_time = start_time.elapsed().as_millis() as u64;
    
    // Combine results
    let combined_result = server.script_executor.combine_results(
        detection_result,
        effectiveness_result,
        total_time,
    );
    
    let response = CombinedScanResponse {
        success: true,
        result: Some(combined_result),
        error: None,
    };
    
    (StatusCode::OK, Json(response))
}

 