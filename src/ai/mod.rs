use anyhow::{anyhow, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSummaryRequest {
    pub result: Value,
    pub context: AiSummaryContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSummaryContext {
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSummaryResponse {
    pub verdict: String,
    pub one_liner: String,
    pub key_points: Vec<String>,
    pub next_steps: Vec<String>,
    pub caveats: Vec<String>,
}

#[async_trait]
pub trait AiProvider {
    async fn summarize(&self, request: &AiSummaryRequest) -> Result<AiSummaryResponse>;
}

pub struct OllamaProvider {
    endpoint: String,
    model: String,
    timeout: Duration,
}

impl OllamaProvider {
    pub fn new(endpoint: String, model: String, timeout: Duration) -> Self {
        Self {
            endpoint,
            model,
            timeout,
        }
    }

    fn client(&self) -> Result<Client> {
        Ok(Client::builder().timeout(self.timeout).build()?)
    }
}

#[async_trait]
impl AiProvider for OllamaProvider {
    async fn summarize(&self, request: &AiSummaryRequest) -> Result<AiSummaryResponse> {
        let prompt = build_prompt(&request.result, &request.context.mode);
        let body = json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false
        });

        let client = self.client()?;
        let url = format!("{}/api/generate", self.endpoint.trim_end_matches('/'));
        let response = client.post(url).json(&body).send().await?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "AI provider error: HTTP {}",
                response.status().as_u16()
            ));
        }
        let payload: Value = response.json().await?;
        let raw = payload
            .get("response")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        parse_ai_response(raw)
    }
}

pub fn ai_enabled() -> bool {
    matches!(
        std::env::var("WAF_DETECTOR_AI_ENABLED")
            .unwrap_or_default()
            .to_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    )
}

pub fn ai_endpoint() -> String {
    std::env::var("WAF_DETECTOR_AI_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:11434".to_string())
}

pub fn ai_model() -> String {
    std::env::var("WAF_DETECTOR_AI_MODEL").unwrap_or_else(|_| "llama3.2:3b".to_string())
}

pub fn ai_timeout() -> Duration {
    let value = std::env::var("WAF_DETECTOR_AI_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(4000);
    Duration::from_millis(value)
}

pub fn build_prompt(result: &Value, mode: &str) -> String {
    let input = summarize_input(result, mode);
    format!(
        "You are a security analyst. Return STRICT JSON only.\\n\\n\
Schema:\\n\
{{\\n  \\\"verdict\\\": \\\"Weak|Moderate|Strong\\\",\\n  \\\"one_liner\\\": \\\"...\\\",\\n  \\\"key_points\\\": [\\\"...\\\"],\\n  \\\"next_steps\\\": [\\\"...\\\"],\\n  \\\"caveats\\\": [\\\"...\\\"]\\n}}\\n\\n\
Rules:\\n\
- Use ONLY the data provided below.\\n\
- Do NOT infer vulnerabilities.\\n\
- If evidence is limited, say so in caveats.\\n\\n\
Input:\\n{}",
        serde_json::to_string_pretty(&input).unwrap_or_else(|_| "{}".to_string())
    )
}

fn summarize_input(result: &Value, mode: &str) -> Value {
    let detected_waf = extract_name_conf(result.get("detected_waf"));
    let detected_cdn = extract_name_conf(result.get("detected_cdn"));
    let evidence = extract_evidence(result.get("evidence"));
    let timing_ms = result.get("detection_time_ms").and_then(|v| v.as_u64());

    let summary = result.get("summary").cloned().unwrap_or(Value::Null);
    let smoke = json!({
        "blocked": summary.get("blocked_count").and_then(|v| v.as_u64()),
        "allowed": summary.get("allowed_count").and_then(|v| v.as_u64()),
        "errors": summary.get("error_count").and_then(|v| v.as_u64()),
        "effectiveness_pct": summary.get("effectiveness_percentage").and_then(|v| v.as_f64())
    });

    json!({
        "mode": mode,
        "url": result.get("url").and_then(|v| v.as_str()).unwrap_or(""),
        "detected_waf": detected_waf,
        "detected_cdn": detected_cdn,
        "evidence": evidence,
        "timing_ms": timing_ms,
        "smoke_summary": smoke
    })
}

fn extract_name_conf(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Object(map)) => json!({
            "name": map.get("name").and_then(|v| v.as_str()).unwrap_or(""),
            "confidence": map.get("confidence").and_then(|v| v.as_f64())
        }),
        Some(Value::String(s)) => json!({ "name": s, "confidence": null }),
        _ => json!(null),
    }
}

fn extract_evidence(value: Option<&Value>) -> Value {
    let mut items = Vec::new();
    if let Some(Value::Array(arr)) = value {
        for entry in arr.iter().take(12) {
            if let Some(desc) = entry.get("description").and_then(|v| v.as_str()) {
                let conf = entry.get("confidence").and_then(|v| v.as_f64());
                items.push(json!({ "description": desc, "confidence": conf }));
            }
        }
    }
    Value::Array(items)
}

pub fn parse_ai_response(raw: &str) -> Result<AiSummaryResponse> {
    if let Ok(parsed) = serde_json::from_str::<AiSummaryResponse>(raw) {
        return Ok(parsed);
    }
    let (start, end) = match (raw.find('{'), raw.rfind('}')) {
        (Some(s), Some(e)) if e > s => (s, e),
        _ => return Err(anyhow!("AI response is not valid JSON")),
    };
    let slice = &raw[start..=end];
    serde_json::from_str::<AiSummaryResponse>(slice)
        .map_err(|_| anyhow!("AI response JSON parse failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_prompt_includes_only_allowed_fields() {
        let result = json!({
            "url": "https://example.com",
            "detected_waf": { "name": "CloudFlare", "confidence": 0.9 },
            "detected_cdn": { "name": "CloudFlare", "confidence": 0.8 },
            "evidence": [
                { "description": "CF-Ray header detected", "confidence": 0.95, "raw_data": "abc" }
            ],
            "summary": {
                "blocked_count": 10,
                "allowed_count": 2,
                "error_count": 0,
                "effectiveness_percentage": 83.3
            },
            "test_results": [
                { "payload": "<script>" }
            ]
        });
        let prompt = build_prompt(&result, "smoke");
        assert!(prompt.contains("CF-Ray header detected"));
        assert!(!prompt.contains("<script>"));
    }

    #[test]
    fn parse_ai_response_accepts_json() {
        let raw = r#"{"verdict":"Weak","one_liner":"x","key_points":["a"],"next_steps":["b"],"caveats":["c"]}"#;
        let parsed = parse_ai_response(raw).unwrap();
        assert_eq!(parsed.verdict, "Weak");
        assert_eq!(parsed.key_points.len(), 1);
    }

    #[test]
    fn parse_ai_response_extracts_embedded_json() {
        let raw = "Here is your summary:\\n{\"verdict\":\"Moderate\",\"one_liner\":\"x\",\"key_points\":[],\"next_steps\":[],\"caveats\":[]}";
        let parsed = parse_ai_response(raw).unwrap();
        assert_eq!(parsed.verdict, "Moderate");
    }
}
