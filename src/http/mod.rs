use anyhow::Result;
use reqwest::{Client, Response};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HttpClient {
    client: Client,
}

impl Default for HttpClient {
    fn default() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub url: String,
}

impl HttpClient {
    pub fn new() -> Result<Self> {
        let disable_proxy = std::env::var("WAF_DETECTOR_NO_PROXY").is_ok() || cfg!(test);
        let make_builder = |force_no_proxy: bool| {
            let mut builder = Client::builder()
                .timeout(Duration::from_secs(10))
                .pool_max_idle_per_host(10)
                .tcp_keepalive(Duration::from_secs(60))
                // Use a realistic browser User-Agent to avoid immediate blocking
                .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

            if disable_proxy || force_no_proxy {
                builder = builder.no_proxy();
            }
            if std::env::var("WAF_DETECTOR_INSECURE_TLS").is_ok() {
                builder = builder.danger_accept_invalid_certs(true);
            }
            builder
        };

        let client = match catch_unwind(AssertUnwindSafe(|| make_builder(false).build())) {
            Ok(Ok(client)) => client,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => {
                eprintln!(
                    "⚠️  HTTP client initialization panicked; retrying without system proxy."
                );
                make_builder(true).build()?
            }
        };

        Ok(Self { client })
    }

    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        let response = self.client.get(url).send().await?;
        self.response_to_http_response(response, url).await
    }

    pub async fn get_with_headers(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        let mut request = self.client.get(url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.send().await?;
        self.response_to_http_response(response, url).await
    }

    pub async fn post(&self, url: &str, body: &str) -> Result<HttpResponse> {
        let response = self
            .client
            .post(url)
            .body(body.to_string())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await?;
        self.response_to_http_response(response, url).await
    }

    pub async fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
    ) -> Result<HttpResponse> {
        let method = reqwest::Method::from_bytes(method.as_bytes())?;
        let mut request = self.client.request(method, url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if let Some(body) = body {
            request = request.body(body.to_string());
        }
        let response = request.send().await?;
        self.response_to_http_response(response, url).await
    }

    pub async fn head(&self, url: &str) -> Result<HttpResponse> {
        let response = self.client.head(url).send().await?;
        self.response_to_http_response(response, url).await
    }

    async fn response_to_http_response(
        &self,
        response: Response,
        url: &str,
    ) -> Result<HttpResponse> {
        let status = response.status().as_u16();

        let mut headers = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.to_string().to_lowercase(), value_str.to_string());
            }
        }

        // Safe body reading with size limit (max 10MB)
        // This prevents memory exhaustion from malicious large responses
        use futures::StreamExt;
        const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10 MB

        let mut body_bytes = Vec::new();
        let mut stream = response.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            if body_bytes.len() + chunk.len() > MAX_BODY_SIZE {
                println!("⚠️  Response body too large, truncating at {MAX_BODY_SIZE} bytes");
                break;
            }
            body_bytes.extend_from_slice(&chunk);
        }

        let body = String::from_utf8_lossy(&body_bytes).to_string();

        Ok(HttpResponse {
            status,
            headers,
            body,
            url: url.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_http_client_creation() {
        let client = HttpClient::new();
        assert!(client.is_ok());
    }

    #[test]
    fn test_http_response_structure() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx".to_string());

        let response = HttpResponse {
            status: 200,
            headers,
            body: "test body".to_string(),
            url: "https://example.com".to_string(),
        };

        assert_eq!(response.status, 200);
        assert_eq!(response.body, "test body");
        assert_eq!(response.headers.get("server"), Some(&"nginx".to_string()));
    }
}
