use reqwest::{Client, Response};
use std::collections::HashMap;
use std::time::Duration;
use anyhow::Result;

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
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(10)
            .tcp_keepalive(Duration::from_secs(60))
            .user_agent("WAF-Detector/1.0")
            .danger_accept_invalid_certs(true) // For testing purposes
            .build()?;
            
        Ok(Self { client })
    }
    
    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        let response = self.client.get(url).send().await?;
        self.response_to_http_response(response, url).await
    }
    
    pub async fn post(&self, url: &str, body: &str) -> Result<HttpResponse> {
        let response = self.client
            .post(url)
            .body(body.to_string())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await?;
        self.response_to_http_response(response, url).await
    }
    
    pub async fn head(&self, url: &str) -> Result<HttpResponse> {
        let response = self.client.head(url).send().await?;
        self.response_to_http_response(response, url).await
    }
    
    async fn response_to_http_response(&self, response: Response, url: &str) -> Result<HttpResponse> {
        let status = response.status().as_u16();
        
        let mut headers = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.to_string().to_lowercase(), value_str.to_string());
            }
        }
        
        let body = response.text().await.unwrap_or_default();
        
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