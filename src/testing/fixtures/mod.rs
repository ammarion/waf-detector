use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureResponse {
    pub status: u16,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureRecord {
    pub request: FixtureRequest,
    pub response: FixtureResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FixtureSet {
    #[serde(default)]
    pub seed: u64,
    #[serde(default)]
    pub records: Vec<FixtureRecord>,
}

#[derive(Debug, Clone)]
pub struct FixtureReplay {
    pub response: FixtureResponse,
    pub latency: Duration,
}

#[derive(Debug, Default)]
pub struct FixtureRuntime {
    index: HashMap<String, FixtureResponse>,
}

impl FixtureRuntime {
    pub fn from_set(set: FixtureSet) -> Self {
        let mut index = HashMap::new();
        for record in set.records {
            let key = request_match_key(&record.request);
            index.insert(key, record.response);
        }
        Self { index }
    }

    pub fn replay(&self, request: &FixtureRequest) -> Option<FixtureReplay> {
        let key = request_match_key(request);
        self.index.get(&key).cloned().map(|response| FixtureReplay {
            latency: Duration::from_millis(response.latency_ms),
            response,
        })
    }
}

pub fn request_match_key(request: &FixtureRequest) -> String {
    let mut header_pairs: Vec<_> = request.headers.iter().collect();
    header_pairs.sort_by_key(|(key, _)| key.to_lowercase());
    let headers_serialized = header_pairs
        .into_iter()
        .map(|(key, value)| format!("{}={}", key.to_lowercase(), value))
        .collect::<Vec<_>>()
        .join("|");

    let body_hash = format!("{:x}", md5::compute(request.body.as_bytes()));
    let header_hash = format!("{:x}", md5::compute(headers_serialized.as_bytes()));
    format!(
        "{}:{}:{}:{}:{}",
        request.method.to_uppercase(),
        request.path,
        request.query,
        header_hash,
        body_hash
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_key_is_stable_with_header_order() {
        let mut first_headers = HashMap::new();
        first_headers.insert("X-Trace".to_string(), "abc".to_string());
        first_headers.insert("Content-Type".to_string(), "application/json".to_string());

        let mut second_headers = HashMap::new();
        second_headers.insert("Content-Type".to_string(), "application/json".to_string());
        second_headers.insert("X-Trace".to_string(), "abc".to_string());

        let first = FixtureRequest {
            method: "POST".to_string(),
            path: "/scan".to_string(),
            query: "a=1".to_string(),
            headers: first_headers,
            body: "{\"ok\":true}".to_string(),
        };
        let second = FixtureRequest {
            method: "POST".to_string(),
            path: "/scan".to_string(),
            query: "a=1".to_string(),
            headers: second_headers,
            body: "{\"ok\":true}".to_string(),
        };

        assert_eq!(request_match_key(&first), request_match_key(&second));
    }

    #[test]
    fn runtime_replays_response_and_latency() {
        let request = FixtureRequest {
            method: "GET".to_string(),
            path: "/status".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body: String::new(),
        };
        let response = FixtureResponse {
            status: 200,
            headers: HashMap::new(),
            body: "ok".to_string(),
            latency_ms: 40,
        };
        let runtime = FixtureRuntime::from_set(FixtureSet {
            seed: 7,
            records: vec![FixtureRecord {
                request: request.clone(),
                response,
            }],
        });

        let replay = runtime.replay(&request).expect("fixture must match");
        assert_eq!(replay.response.status, 200);
        assert_eq!(replay.response.body, "ok");
        assert_eq!(replay.latency.as_millis(), 40);
    }
}
