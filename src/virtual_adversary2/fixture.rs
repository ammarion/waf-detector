//! Data-driven fixture replay for deterministic VA2 testing.

use super::{Va2HttpAdapter, Va2HttpRequest, Va2HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureSet {
    pub name: String,
    pub base_url: String,
    pub responses: Vec<FixtureEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureEntry {
    /// Lookup key: "METHOD:path:query"
    pub key: String,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

pub struct FixtureAdapter {
    responses: HashMap<String, FixtureEntry>,
    /// Fallback response for unmatched requests
    fallback_status: u16,
}

impl FixtureAdapter {
    pub fn from_fixture_set(fixture: FixtureSet) -> Self {
        let mut responses = HashMap::new();
        for entry in fixture.responses {
            responses.insert(entry.key.clone(), entry);
        }
        Self {
            responses,
            fallback_status: 200,
        }
    }

    pub fn load(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let fixture: FixtureSet = serde_json::from_str(&data)?;
        Ok(Self::from_fixture_set(fixture))
    }

    fn request_key(req: &Va2HttpRequest) -> String {
        let url = url::Url::parse(&req.url)
            .unwrap_or_else(|_| url::Url::parse("http://invalid").expect("hardcoded URL is valid"));
        // Percent-decode path and query for stable fixture matching
        let path = percent_encoding::percent_decode_str(url.path()).decode_utf8_lossy();
        let raw_query = url.query().unwrap_or("");
        let query = percent_encoding::percent_decode_str(raw_query).decode_utf8_lossy();
        let mut key = format!("{}:{}:{}", req.method, path, query);

        // Extended key format: append header and body components for multi-channel probes
        let probe_headers: Vec<(&str, &str)> = req
            .headers
            .iter()
            .filter(|(k, _)| {
                let kl = k.to_lowercase();
                kl.starts_with("x-") || kl == "referer" || kl == "content-type"
            })
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        if !probe_headers.is_empty() {
            let mut sorted: Vec<_> = probe_headers;
            sorted.sort_by_key(|(k, _)| k.to_lowercase());
            let parts: Vec<String> = sorted.iter().map(|(k, v)| format!("{k}={v}")).collect();
            key.push_str(&format!(":H{{{}}}", parts.join(",")));
        }
        if let Some(body) = &req.body {
            if !body.is_empty() {
                key.push_str(&format!(":B{{{body}}}"));
            }
        }
        key
    }
}

#[async_trait::async_trait]
impl Va2HttpAdapter for FixtureAdapter {
    async fn send(&self, request: &Va2HttpRequest) -> anyhow::Result<Va2HttpResponse> {
        let key = Self::request_key(request);
        if let Some(entry) = self.responses.get(&key) {
            Ok(Va2HttpResponse {
                status: entry.status,
                headers: entry.headers.clone(),
                body: entry.body.clone(),
            })
        } else {
            Ok(Va2HttpResponse {
                status: self.fallback_status,
                headers: HashMap::new(),
                body: String::new(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cloudflare_fixture() -> FixtureSet {
        FixtureSet {
            name: "cloudflare_waf".to_string(),
            base_url: "https://example.com".to_string(),
            responses: vec![
                FixtureEntry {
                    key: "GET:/:/".to_string(),
                    status: 200,
                    headers: {
                        let mut h = HashMap::new();
                        h.insert("cf-ray".to_string(), "abc123-SEA".to_string());
                        h.insert("server".to_string(), "cloudflare".to_string());
                        h
                    },
                    body: "<html>Welcome</html>".to_string(),
                },
                FixtureEntry {
                    key: "GET:/:".to_string(),
                    status: 200,
                    headers: {
                        let mut h = HashMap::new();
                        h.insert("cf-ray".to_string(), "abc123-SEA".to_string());
                        h.insert("server".to_string(), "cloudflare".to_string());
                        h
                    },
                    body: "<html>Welcome</html>".to_string(),
                },
                FixtureEntry {
                    key: "GET:/:search=test".to_string(),
                    status: 200,
                    headers: {
                        let mut h = HashMap::new();
                        h.insert("cf-ray".to_string(), "abc124-SEA".to_string());
                        h
                    },
                    body: "<html>Search results</html>".to_string(),
                },
                FixtureEntry {
                    key: "GET:/:search=1'+OR+'1'='1".to_string(),
                    status: 403,
                    headers: {
                        let mut h = HashMap::new();
                        h.insert("cf-ray".to_string(), "abc125-SEA".to_string());
                        h
                    },
                    body: "<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head><body>access denied</body></html>".to_string(),
                },
                FixtureEntry {
                    key: "GET:/:q=hello".to_string(),
                    status: 200,
                    headers: {
                        let mut h = HashMap::new();
                        h.insert("cf-ray".to_string(), "abc126-SEA".to_string());
                        h
                    },
                    body: "<html>Hello results</html>".to_string(),
                },
                FixtureEntry {
                    key: "GET:/:q=<script>alert(1)</script>".to_string(),
                    status: 403,
                    headers: {
                        let mut h = HashMap::new();
                        h.insert("cf-ray".to_string(), "abc127-SEA".to_string());
                        h
                    },
                    body: "access denied".to_string(),
                },
                FixtureEntry {
                    key: "GET:/../../etc/passwd:".to_string(),
                    status: 403,
                    headers: HashMap::new(),
                    body: "access denied".to_string(),
                },
                FixtureEntry {
                    key: "GET:/:cmd=list".to_string(),
                    status: 200,
                    headers: HashMap::new(),
                    body: "<html>Command list</html>".to_string(),
                },
                FixtureEntry {
                    key: "GET:/:cmd=;cat+/etc/passwd".to_string(),
                    status: 403,
                    headers: HashMap::new(),
                    body: "access denied".to_string(),
                },
                FixtureEntry {
                    key: "GET:/:format=json".to_string(),
                    status: 200,
                    headers: HashMap::new(),
                    body: "{\"status\":\"ok\"}".to_string(),
                },
                FixtureEntry {
                    key: "GET:/:format=../../etc/passwd%00.json".to_string(),
                    status: 403,
                    headers: HashMap::new(),
                    body: "access denied".to_string(),
                },
                FixtureEntry {
                    key: "GET:/:va2=hdr1:H{Referer=https://example.com}".to_string(),
                    status: 200,
                    headers: HashMap::new(),
                    body: "<html>Welcome</html>".to_string(),
                },
                FixtureEntry {
                    key: "GET:/:va2=hdr1:H{Referer=<script>alert(1)</script>}".to_string(),
                    status: 403,
                    headers: HashMap::new(),
                    body: "access denied".to_string(),
                },
                FixtureEntry {
                    key: "GET:/:va2=hdr2:H{X-Search=test}".to_string(),
                    status: 200,
                    headers: HashMap::new(),
                    body: "<html>Welcome</html>".to_string(),
                },
                FixtureEntry {
                    key: "GET:/:va2=hdr2:H{X-Search=1' OR '1'='1}".to_string(),
                    status: 403,
                    headers: HashMap::new(),
                    body: "access denied".to_string(),
                },
                FixtureEntry {
                    key: "POST:/:va2=body1:H{Content-Type=application/x-www-form-urlencoded}:B{search=test}".to_string(),
                    status: 200,
                    headers: HashMap::new(),
                    body: "<html>Search results</html>".to_string(),
                },
                FixtureEntry {
                    key: "POST:/:va2=body1:H{Content-Type=application/x-www-form-urlencoded}:B{search=1'+OR+'1'='1}".to_string(),
                    status: 403,
                    headers: HashMap::new(),
                    body: "access denied".to_string(),
                },
                FixtureEntry {
                    key: "OPTIONS:/api/v1/status:".to_string(),
                    status: 200,
                    headers: HashMap::new(),
                    body: String::new(),
                },
                FixtureEntry {
                    key: "DELETE:/api/v1/status:".to_string(),
                    status: 405,
                    headers: HashMap::new(),
                    body: "method not allowed".to_string(),
                },
            ],
        }
    }

    #[test]
    fn test_fixture_adapter_loads_and_replays() {
        let fixture = cloudflare_fixture();
        let adapter = FixtureAdapter::from_fixture_set(fixture);

        let req = Va2HttpRequest {
            method: "GET".to_string(),
            url: "https://example.com/?search=test".to_string(),
            headers: vec![],
            body: None,
            resolved_ip: None,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resp = rt.block_on(adapter.send(&req)).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("Search results"));
    }

    #[test]
    fn test_fixture_adapter_fallback() {
        let fixture = cloudflare_fixture();
        let adapter = FixtureAdapter::from_fixture_set(fixture);

        let req = Va2HttpRequest {
            method: "GET".to_string(),
            url: "https://example.com/nonexistent?foo=bar".to_string(),
            headers: vec![],
            body: None,
            resolved_ip: None,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resp = rt.block_on(adapter.send(&req)).unwrap();
        assert_eq!(resp.status, 200); // fallback status
        assert!(resp.body.is_empty());
    }

    #[test]
    fn test_fixture_adapter_blocks_attack() {
        let fixture = cloudflare_fixture();
        let adapter = FixtureAdapter::from_fixture_set(fixture);

        let req = Va2HttpRequest {
            method: "GET".to_string(),
            url: "https://example.com/?search=1'+OR+'1'='1".to_string(),
            headers: vec![],
            body: None,
            resolved_ip: None,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resp = rt.block_on(adapter.send(&req)).unwrap();
        assert_eq!(resp.status, 403);
        assert!(resp.body.contains("access denied"));
    }

    #[test]
    fn test_fixture_file_roundtrip() {
        let fixture = cloudflare_fixture();
        let json = serde_json::to_string_pretty(&fixture).unwrap();
        let parsed: FixtureSet = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "cloudflare_waf");
        assert_eq!(parsed.responses.len(), fixture.responses.len());
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn test_va2_with_fixture_cloudflare() {
        use crate::virtual_adversary2::{
            build_va2_campaign_plan, Va2CampaignConfig, Va2Phase, Va2Runner,
        };

        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("WAF_DETECTOR_HOME").ok();
        let temp_dir = tempfile::TempDir::new().unwrap();
        std::env::set_var("WAF_DETECTOR_HOME", temp_dir.path());

        // Write consent
        let consent_path = temp_dir.path().join(".waf-detector-consent.json");
        let record = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "terms_version": "1.0.0",
            "authorized_targets": ["example.com"],
            "acknowledgment": "I AGREE"
        });
        std::fs::write(
            &consent_path,
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        let fixture = cloudflare_fixture();
        let adapter = FixtureAdapter::from_fixture_set(fixture);

        let phases = vec![Va2Phase::Baseline, Va2Phase::ProtocolVariance];
        let config = Va2CampaignConfig {
            seed: 42,
            budget: 60,
        };
        let mut plan = build_va2_campaign_plan("https://example.com", &phases, config).unwrap();
        for step in &mut plan.steps {
            step.delay_ms = 0;
        }

        let runner = Va2Runner::with_adapter(Box::new(adapter)).unwrap();
        let report1 = runner.run_plan(plan.clone()).await.unwrap();

        // Run again to verify determinism
        let adapter2 = FixtureAdapter::from_fixture_set(cloudflare_fixture());
        let runner2 = Va2Runner::with_adapter(Box::new(adapter2)).unwrap();
        let report2 = runner2.run_plan(plan).await.unwrap();

        // Scores must be identical across runs
        assert!(
            (report1.wbf.differential_score - report2.wbf.differential_score).abs() < f64::EPSILON
        );
        assert!((report1.pmi.score - report2.pmi.score).abs() < f64::EPSILON);
        assert_eq!(report1.differential.len(), report2.differential.len());

        // Should have differential results with discrimination
        assert!(!report1.differential.is_empty());
        assert!(report1.wbf.differential_score > 0.0);

        // Cleanup
        if let Some(value) = original_home {
            std::env::set_var("WAF_DETECTOR_HOME", value);
        } else {
            std::env::remove_var("WAF_DETECTOR_HOME");
        }
    }

    #[test]
    fn test_fixture_load_from_file() {
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cloudflare_waf.json");
        let adapter = FixtureAdapter::load(&fixture_path).unwrap();

        let req = Va2HttpRequest {
            method: "GET".to_string(),
            url: "https://example.com/?search=test".to_string(),
            headers: vec![],
            body: None,
            resolved_ip: None,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resp = rt.block_on(adapter.send(&req)).unwrap();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn test_fixture_adapter_post_request() {
        let fixture = cloudflare_fixture();
        let adapter = FixtureAdapter::from_fixture_set(fixture);

        // POST with body — benign
        let req = Va2HttpRequest {
            method: "POST".to_string(),
            url: "https://example.com/?va2=body1".to_string(),
            headers: vec![(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )],
            body: Some("search=test".to_string()),
            resolved_ip: None,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resp = rt.block_on(adapter.send(&req)).unwrap();
        assert_eq!(resp.status, 200);

        // POST with body — attack
        let req_attack = Va2HttpRequest {
            method: "POST".to_string(),
            url: "https://example.com/?va2=body1".to_string(),
            headers: vec![(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )],
            body: Some("search=1'+OR+'1'='1".to_string()),
            resolved_ip: None,
        };
        let resp_attack = rt.block_on(adapter.send(&req_attack)).unwrap();
        assert_eq!(resp_attack.status, 403);
    }

    #[test]
    fn test_fixture_adapter_header_request() {
        let fixture = cloudflare_fixture();
        let adapter = FixtureAdapter::from_fixture_set(fixture);

        // Header benign
        let req = Va2HttpRequest {
            method: "GET".to_string(),
            url: "https://example.com/?va2=hdr1".to_string(),
            headers: vec![("Referer".to_string(), "https://example.com".to_string())],
            body: None,
            resolved_ip: None,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resp = rt.block_on(adapter.send(&req)).unwrap();
        assert_eq!(resp.status, 200);

        // Header attack
        let req_attack = Va2HttpRequest {
            method: "GET".to_string(),
            url: "https://example.com/?va2=hdr1".to_string(),
            headers: vec![(
                "Referer".to_string(),
                "<script>alert(1)</script>".to_string(),
            )],
            body: None,
            resolved_ip: None,
        };
        let resp_attack = rt.block_on(adapter.send(&req_attack)).unwrap();
        assert_eq!(resp_attack.status, 403);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn test_va2_with_fixture_multichannel() {
        use crate::virtual_adversary2::{
            build_va2_campaign_plan, Va2CampaignConfig, Va2Phase, Va2Runner,
        };

        let _guard = crate::test_utils::env_lock()
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let original_home = std::env::var("WAF_DETECTOR_HOME").ok();
        let temp_dir = tempfile::TempDir::new().unwrap();
        std::env::set_var("WAF_DETECTOR_HOME", temp_dir.path());

        let consent_path = temp_dir.path().join(".waf-detector-consent.json");
        let record = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "terms_version": "1.0.0",
            "authorized_targets": ["example.com"],
            "acknowledgment": "I AGREE"
        });
        std::fs::write(
            &consent_path,
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        let fixture = cloudflare_fixture();
        let adapter = FixtureAdapter::from_fixture_set(fixture);

        let phases = vec![Va2Phase::Baseline, Va2Phase::ProtocolVariance];
        let config = Va2CampaignConfig {
            seed: 42,
            budget: 60,
        };
        let mut plan = build_va2_campaign_plan("https://example.com", &phases, config).unwrap();
        for step in &mut plan.steps {
            step.delay_ms = 0;
        }

        let runner = Va2Runner::with_adapter(Box::new(adapter)).unwrap();
        let report = runner.run_plan(plan).await.unwrap();

        // Verify channel_coverage is populated
        let cc = report
            .channel_coverage
            .as_ref()
            .expect("channel_coverage should be present");
        assert!(!cc.channels.is_empty());
        // Cloudflare blocks all channels → should have high coverage
        assert!(
            cc.coverage_score > 0.5,
            "expected good coverage against cloudflare fixture, got {}",
            cc.coverage_score
        );

        // Cleanup
        if let Some(value) = original_home {
            std::env::set_var("WAF_DETECTOR_HOME", value);
        } else {
            std::env::remove_var("WAF_DETECTOR_HOME");
        }
    }
}
