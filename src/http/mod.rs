use anyhow::Result;
use reqwest::{Client, Response};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Once;
use std::time::Duration;
use url::Url;

use crate::surface::ResolvedAuthProfile;

static INSECURE_TLS_WARNED: Once = Once::new();

pub fn warn_insecure_tls() {
    INSECURE_TLS_WARNED.call_once(|| {
        tracing::warn!("Insecure TLS mode active — certificates not validated");
    });
}

#[derive(Debug, Clone)]
pub struct HttpClient {
    client: Client,
    disable_proxy: bool,
    insecure_tls: bool,
    default_timeout: Duration,
    user_agent: String,
    auth_profile: Option<ResolvedAuthProfile>,
}

impl Default for HttpClient {
    fn default() -> Self {
        Self {
            client: Client::new(),
            disable_proxy: false,
            insecure_tls: false,
            default_timeout: Duration::from_secs(10),
            user_agent: default_user_agent(),
            auth_profile: None,
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

fn default_user_agent() -> String {
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()
}

impl HttpClient {
    pub fn new() -> Result<Self> {
        let disable_proxy = std::env::var("WAF_DETECTOR_NO_PROXY").is_ok() || cfg!(test);
        let insecure_tls = std::env::var("WAF_DETECTOR_INSECURE_TLS").is_ok();
        let default_timeout = Duration::from_secs(10);
        let user_agent = default_user_agent();
        let client = Self::build_client_with_settings(
            disable_proxy,
            insecure_tls,
            default_timeout,
            &user_agent,
            None,
            None,
        )?;

        Ok(Self {
            client,
            disable_proxy,
            insecure_tls,
            default_timeout,
            user_agent,
            auth_profile: ResolvedAuthProfile::from_env_path()?,
        })
    }

    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        self.send_request("GET", url, &[], None, None, None).await
    }

    pub async fn get_with_headers(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        let owned_headers = headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect::<Vec<_>>();
        self.send_request("GET", url, &owned_headers, None, None, None)
            .await
    }

    pub async fn post(&self, url: &str, body: &str) -> Result<HttpResponse> {
        self.send_request(
            "POST",
            url,
            &[(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )],
            Some(body),
            None,
            None,
        )
        .await
    }

    pub async fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
    ) -> Result<HttpResponse> {
        self.send_request(method, url, headers, body, None, None)
            .await
    }

    pub async fn request_pinned(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
        resolved_ip: IpAddr,
        timeout: Option<Duration>,
    ) -> Result<HttpResponse> {
        self.send_request(method, url, headers, body, Some(resolved_ip), timeout)
            .await
    }

    pub async fn head(&self, url: &str) -> Result<HttpResponse> {
        self.send_request("HEAD", url, &[], None, None, None).await
    }

    async fn send_request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
        resolved_ip: Option<IpAddr>,
        timeout: Option<Duration>,
    ) -> Result<HttpResponse> {
        let method = reqwest::Method::from_bytes(method.as_bytes())?;
        let client = if resolved_ip.is_none() && timeout.is_none() {
            self.client.clone()
        } else {
            self.build_request_client(url, resolved_ip, timeout)?
        };
        let mut request = client.request(method, url);
        let merged_headers = self.merge_auth_headers(url, headers);
        for (name, value) in &merged_headers {
            request = request.header(name, value);
        }
        if let Some(body) = body {
            request = request.body(body.to_string());
        }
        let response = request.send().await?;
        self.response_to_http_response(response, url).await
    }

    fn merge_auth_headers(&self, url: &str, headers: &[(String, String)]) -> Vec<(String, String)> {
        let mut merged = headers.to_vec();
        if let Some(profile) = &self.auth_profile {
            for (name, value) in profile.headers_for_url(url) {
                if merged
                    .iter()
                    .any(|(existing_name, _)| existing_name.eq_ignore_ascii_case(&name))
                {
                    continue;
                }
                merged.push((name, value));
            }
        }
        merged
    }

    fn build_request_client(
        &self,
        url: &str,
        resolved_ip: Option<IpAddr>,
        timeout: Option<Duration>,
    ) -> Result<Client> {
        let timeout = timeout.unwrap_or(self.default_timeout);
        let resolution = if let Some(ip) = resolved_ip {
            let parsed = Url::parse(url).or_else(|_| Url::parse(&format!("https://{url}")))?;
            let hostname = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("URL missing host for pinned request"))?
                .to_string();
            let port = parsed.port_or_known_default().unwrap_or(443);
            Some((hostname, SocketAddr::new(ip, port)))
        } else {
            None
        };

        Self::build_client_with_settings(
            self.disable_proxy,
            self.insecure_tls,
            timeout,
            &self.user_agent,
            resolution.as_ref().map(|(hostname, _)| hostname.as_str()),
            resolution.as_ref().map(|(_, socket_addr)| *socket_addr),
        )
    }

    fn build_client_with_settings(
        disable_proxy: bool,
        insecure_tls: bool,
        timeout: Duration,
        user_agent: &str,
        resolved_host: Option<&str>,
        resolved_addr: Option<SocketAddr>,
    ) -> Result<Client> {
        let make_builder = |force_no_proxy: bool| {
            let mut builder = Client::builder()
                .timeout(timeout)
                .pool_max_idle_per_host(10)
                .tcp_keepalive(Duration::from_secs(60))
                .user_agent(user_agent.to_string());

            if disable_proxy || force_no_proxy {
                builder = builder.no_proxy();
            }
            if insecure_tls {
                builder = builder.danger_accept_invalid_certs(true);
                warn_insecure_tls();
            }
            if let (Some(host), Some(addr)) = (resolved_host, resolved_addr) {
                builder = builder.resolve(host, addr);
            }
            builder
        };

        match catch_unwind(AssertUnwindSafe(|| make_builder(false).build())) {
            Ok(Ok(client)) => Ok(client),
            Ok(Err(err)) => Err(err.into()),
            Err(_) => {
                eprintln!(
                    "⚠️  HTTP client initialization panicked; retrying without system proxy."
                );
                Ok(make_builder(true).build()?)
            }
        }
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
                let key = name.to_string().to_lowercase();
                // A response can carry many Set-Cookie headers, and a plain
                // `insert` keeps only the last one. That silently defeats every
                // cookie-based signature: www.cloudflare.com returns five
                // Set-Cookie headers and the `__cf_bm` bot-management cookie is
                // not reliably among the last, so detection depended on header
                // ordering. Accumulate them instead, newline-separated because
                // cookie values legitimately contain commas (`Expires=...`) and
                // comma-joining would corrupt them.
                //
                // Restricted to set-cookie on purpose: for every other header,
                // last-wins is the pre-existing behavior and consumers may parse
                // the value as a single scalar.
                if key == "set-cookie" {
                    headers
                        .entry(key)
                        .and_modify(|existing: &mut String| {
                            existing.push('\n');
                            existing.push_str(value_str);
                        })
                        .or_insert_with(|| value_str.to_string());
                } else {
                    headers.insert(key, value_str.to_string());
                }
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

    /// Multiple Set-Cookie headers must all survive into `HttpResponse`.
    ///
    /// They previously did not: each was `insert`ed into the same map key, so
    /// only the last one remained. Every cookie-based signature therefore
    /// depended on header ordering -- www.cloudflare.com returns five
    /// Set-Cookie headers, and its `__cf_bm` bot-management cookie is not
    /// reliably last.
    #[tokio::test]
    async fn accumulates_every_set_cookie_header() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("set-cookie", "first=1; Path=/")
            .with_header("set-cookie", "__cf_bm=abc123; Path=/; HttpOnly")
            .with_header("set-cookie", "last=2; Path=/")
            .with_body("ok")
            .create_async()
            .await;

        let client = HttpClient::new().expect("client");
        let response = client.get(&server.url()).await.expect("request");
        mock.assert_async().await;

        let cookies = response
            .headers
            .get("set-cookie")
            .expect("set-cookie must be captured");
        for expected in ["first=1", "__cf_bm=abc123", "last=2"] {
            assert!(
                cookies.contains(expected),
                "lost {expected} from the accumulated Set-Cookie value: {cookies:?}"
            );
        }
        // Newline-separated, because cookie values contain commas in `Expires`
        // and comma-joining would corrupt them.
        assert_eq!(cookies.lines().count(), 3, "got {cookies:?}");
    }

    use crate::surface::{AuthHeaderValue, AuthProfile, RouteAuthHeaders};

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

    #[test]
    fn test_auth_profile_headers_are_merged_without_overwriting_explicit_headers() {
        let profile = ResolvedAuthProfile::from_profile(AuthProfile {
            headers: HashMap::from([(
                "Authorization".to_string(),
                AuthHeaderValue::Plain("Bearer secret".to_string()),
            )]),
            route_headers: vec![RouteAuthHeaders {
                path_prefix: "/api/private".to_string(),
                headers: HashMap::from([(
                    "X-Route-Key".to_string(),
                    AuthHeaderValue::Plain("route".to_string()),
                )]),
            }],
        });
        let client = HttpClient {
            auth_profile: Some(profile),
            ..HttpClient::default()
        };

        let merged = client.merge_auth_headers(
            "https://example.com/api/private",
            &[("Authorization".to_string(), "Bearer override".to_string())],
        );
        assert!(merged
            .iter()
            .any(|(name, value)| name == "Authorization" && value == "Bearer override"));
        assert!(merged
            .iter()
            .any(|(name, value)| name == "X-Route-Key" && value == "route"));
    }
}
