#![allow(clippy::type_complexity)]

use anyhow::Result;
use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

/// Mock HTTP response configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub delay_ms: Option<u64>,
}

impl Default for MockResponse {
    fn default() -> Self {
        Self {
            status: 200,
            headers: HashMap::new(),
            body: String::new(),
            delay_ms: None,
        }
    }
}

/// Mock server for testing WAF/CDN detection
pub struct MockServer {
    responses: Arc<Mutex<HashMap<String, MockResponse>>>,
    request_log: Arc<Mutex<Vec<RecordedRequest>>>,
    listener: Option<TcpListener>,
    addr: Option<SocketAddr>,
}

/// Recorded request for verification
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: String,
}

impl MockServer {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            responses: Arc::new(Mutex::new(HashMap::new())),
            request_log: Arc::new(Mutex::new(Vec::new())),
            listener: None,
            addr: None,
        })
    }

    /// Start the mock server
    pub async fn start(&mut self) -> Result<String> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        self.addr = Some(addr);

        let responses = self.responses.clone();
        let request_log = self.request_log.clone();

        let app = Router::new()
            .route("/*path", get(handle_request))
            .route("/*path", post(handle_request))
            .route("/", get(handle_request))
            .route("/", post(handle_request))
            .with_state((responses, request_log));

        self.listener = Some(listener);

        // Spawn server in background
        let listener = self.listener.take().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Ok(format!("http://{addr}"))
    }

    /// Configure a response for a specific path
    pub fn mock_response(&self, path: &str, response: MockResponse) {
        self.responses
            .lock()
            .unwrap()
            .insert(path.to_string(), response);
    }

    /// Mock CloudFlare response
    pub fn mock_cloudflare(&self, path: &str) {
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "7e6789abc123def0-DFW".to_string());
        headers.insert("server".to_string(), "cloudflare".to_string());
        headers.insert("cf-cache-status".to_string(), "HIT".to_string());

        self.mock_response(
            path,
            MockResponse {
                status: 200,
                headers,
                body: r#"<!DOCTYPE html>
<html>
<head><title>Protected by CloudFlare</title></head>
<body>
    <div class="cf-browser-verification">
        <!-- CloudFlare Browser Check -->
    </div>
</body>
</html>"#
                    .to_string(),
                delay_ms: None,
            },
        );
    }

    /// Mock AWS CloudFront response
    pub fn mock_aws_cloudfront(&self, path: &str) {
        let mut headers = HashMap::new();
        headers.insert("x-amz-cf-id".to_string(), "EXAMPLE-ID123".to_string());
        headers.insert("x-amz-cf-pop".to_string(), "DFW50-C1".to_string());
        headers.insert("x-cache".to_string(), "Hit from cloudfront".to_string());
        headers.insert(
            "via".to_string(),
            "1.1 123456789abcdef.cloudfront.net (CloudFront)".to_string(),
        );

        self.mock_response(
            path,
            MockResponse {
                status: 200,
                headers,
                body: r#"<!DOCTYPE html><html><body>AWS CloudFront Test</body></html>"#.to_string(),
                delay_ms: None,
            },
        );
    }

    /// Mock Akamai response
    pub fn mock_akamai(&self, path: &str) {
        let mut headers = HashMap::new();
        headers.insert("x-akamai-edgescape".to_string(), "georegion=US".to_string());
        headers.insert("x-check-cacheable".to_string(), "YES".to_string());
        headers.insert("server".to_string(), "AkamaiGHost".to_string());

        self.mock_response(
            path,
            MockResponse {
                status: 200,
                headers,
                body: r#"<!DOCTYPE html><html><body>Akamai Edge Server</body></html>"#.to_string(),
                delay_ms: None,
            },
        );
    }

    /// Mock Fastly response
    pub fn mock_fastly(&self, path: &str) {
        let mut headers = HashMap::new();
        headers.insert("x-served-by".to_string(), "cache-dfw8520-DFW".to_string());
        headers.insert("x-cache".to_string(), "HIT".to_string());
        headers.insert("x-cache-hits".to_string(), "1".to_string());
        headers.insert(
            "x-timer".to_string(),
            "S1234567890.123456,VS0,VE1".to_string(),
        );
        headers.insert("via".to_string(), "1.1 varnish".to_string());

        self.mock_response(
            path,
            MockResponse {
                status: 200,
                headers,
                body: r#"<!DOCTYPE html><html><body>Fastly CDN</body></html>"#.to_string(),
                delay_ms: None,
            },
        );
    }

    /// Mock blocked WAF response
    pub fn mock_waf_blocked(&self, path: &str, waf_name: &str) {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());

        let body = match waf_name {
            "cloudflare" => {
                headers.insert("cf-ray".to_string(), "7e6789abc123def0-DFW".to_string());
                r#"<!DOCTYPE html>
<html>
<head><title>Access Denied</title></head>
<body>
    <h1>Error 1020</h1>
    <p>Access denied. Your request was blocked by our security service.</p>
    <p>Ray ID: 7e6789abc123def0</p>
</body>
</html>"#
            }
            "aws" => {
                headers.insert("x-amzn-requestid".to_string(), "123456789".to_string());
                r#"<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body>
    <h1>403 Forbidden</h1>
    <p>The request could not be satisfied.</p>
    <p>Request blocked by AWS WAF.</p>
</body>
</html>"#
            }
            _ => {
                r#"<!DOCTYPE html>
<html>
<head><title>Access Denied</title></head>
<body>
    <h1>Access Denied</h1>
    <p>Your request has been blocked by our security policy.</p>
</body>
</html>"#
            }
        };

        self.mock_response(
            path,
            MockResponse {
                status: 403,
                headers,
                body: body.to_string(),
                delay_ms: None,
            },
        );
    }

    /// Get recorded requests
    pub fn get_requests(&self) -> Vec<RecordedRequest> {
        self.request_log.lock().unwrap().clone()
    }

    /// Clear recorded requests
    pub fn clear_requests(&self) {
        self.request_log.lock().unwrap().clear();
    }

    /// Get the server URL
    pub fn url(&self) -> String {
        self.addr
            .map(|addr| format!("http://{addr}"))
            .unwrap_or_default()
    }
}

async fn handle_request(
    State((responses, request_log)): State<(
        Arc<Mutex<HashMap<String, MockResponse>>>,
        Arc<Mutex<Vec<RecordedRequest>>>,
    )>,
    axum::extract::Path(path): axum::extract::Path<String>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    body: String,
) -> Response {
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        format!("/{path}")
    };

    // Record the request
    let mut recorded_headers = HashMap::new();
    for (name, value) in &headers {
        if let Ok(v) = value.to_str() {
            recorded_headers.insert(name.to_string(), v.to_string());
        }
    }

    let recorded = RecordedRequest {
        method: "GET".to_string(), // Simplified for now
        path: path.clone(),
        headers: recorded_headers,
        query_params: params,
        body: body.clone(),
    };

    request_log.lock().unwrap().push(recorded);

    // Get configured response
    let response = {
        let responses = responses.lock().unwrap();
        responses.get(&path).cloned().unwrap_or_default()
    };

    // Apply delay if configured
    if let Some(delay_ms) = response.delay_ms {
        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
    }

    // Build response
    let mut builder =
        Response::builder().status(StatusCode::from_u16(response.status).unwrap_or(StatusCode::OK));

    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }

    builder.body(Body::from(response.body)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_server() {
        let mut server = MockServer::new().await.unwrap();
        let url = match server.start().await {
            Ok(url) => url,
            Err(e) => {
                if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                    if io_err.kind() == std::io::ErrorKind::PermissionDenied {
                        eprintln!("Skipping mock server test: {}", e);
                        return;
                    }
                }
                panic!("Mock server failed to start: {e}");
            }
        };

        // Mock a CloudFlare response
        server.mock_cloudflare("/test");

        // Make a request
        let client = reqwest::Client::new();
        let resp = client.get(format!("{url}/test")).send().await.unwrap();

        assert_eq!(resp.status(), 200);
        assert!(resp.headers().get("cf-ray").is_some());
    }
}
