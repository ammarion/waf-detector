use crate::effectiveness::report::{DiscrepancyFinding, ParserDiscrepancySummary, ReplayRequest};
use crate::effectiveness::waffled_techniques::{
    curated_parser_discrepancy_pairs, CuratedDiscrepancyPair, CuratedRequest,
};
use crate::effectiveness::TestResult;
use anyhow::Result;
use async_trait::async_trait;
use std::cmp::Ordering;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateBypassDisposition {
    CandidateBypass,
    NoBypass,
    Inconclusive,
}

#[derive(Debug, Clone)]
pub struct ExecutedDiscrepancyPair {
    pub pair: CuratedDiscrepancyPair,
    pub control_replay: ReplayRequest,
    pub variant_replay: ReplayRequest,
    pub control_result: TestResult,
    pub variant_result: TestResult,
    pub disposition: CandidateBypassDisposition,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct ParserDiscrepancyRun {
    pub summary: ParserDiscrepancySummary,
    pub executed_pairs: Vec<ExecutedDiscrepancyPair>,
}

#[async_trait]
pub trait ParserDiscrepancyExecutor {
    async fn execute_replay(&mut self, request: &ReplayRequest) -> Result<TestResult>;
}

pub async fn execute_campaign<E>(
    executor: &mut E,
    url: &str,
    max_pairs: usize,
    static_or_ambiguous: bool,
) -> Result<ParserDiscrepancyRun>
where
    E: ParserDiscrepancyExecutor + Send,
{
    execute_pairs(
        executor,
        url,
        curated_parser_discrepancy_pairs(max_pairs),
        static_or_ambiguous,
    )
    .await
}

pub async fn execute_pairs<E>(
    executor: &mut E,
    url: &str,
    pairs: Vec<CuratedDiscrepancyPair>,
    static_or_ambiguous: bool,
) -> Result<ParserDiscrepancyRun>
where
    E: ParserDiscrepancyExecutor + Send,
{
    let mut executed_pairs = Vec::with_capacity(pairs.len());

    for pair in pairs {
        let control_replay = replay_from_request(url, &pair.control_request);
        let control_result = executor.execute_replay(&control_replay).await?;
        let variant_replay = replay_from_request(url, &pair.variant_request);
        let variant_result = executor.execute_replay(&variant_replay).await?;
        let (disposition, confidence) =
            classify_candidate_bypass(&control_result, &variant_result, static_or_ambiguous);

        executed_pairs.push(ExecutedDiscrepancyPair {
            pair,
            control_replay,
            variant_replay,
            control_result,
            variant_result,
            disposition,
            confidence,
        });
    }

    let summary = summarize_candidates(&executed_pairs);

    Ok(ParserDiscrepancyRun {
        summary,
        executed_pairs,
    })
}

pub fn classify_candidate_bypass(
    control_result: &TestResult,
    variant_result: &TestResult,
    static_or_ambiguous: bool,
) -> (CandidateBypassDisposition, f64) {
    if control_result.status_code == 0 || variant_result.status_code == 0 {
        return (CandidateBypassDisposition::Inconclusive, 0.0);
    }

    if !control_result.blocked {
        return (CandidateBypassDisposition::Inconclusive, 0.0);
    }

    if variant_result.blocked {
        return (CandidateBypassDisposition::NoBypass, 0.0);
    }

    if (200..400).contains(&variant_result.status_code) {
        let confidence = if static_or_ambiguous { 0.5 } else { 1.0 };
        return (CandidateBypassDisposition::CandidateBypass, confidence);
    }

    if (400..500).contains(&variant_result.status_code) {
        let confidence = if static_or_ambiguous { 0.5 } else { 0.75 };
        return (CandidateBypassDisposition::CandidateBypass, confidence);
    }

    (CandidateBypassDisposition::Inconclusive, 0.0)
}

pub fn summarize_candidates(
    executed_pairs: &[ExecutedDiscrepancyPair],
) -> ParserDiscrepancySummary {
    let candidate_bypasses = executed_pairs
        .iter()
        .filter(|pair| pair.disposition == CandidateBypassDisposition::CandidateBypass)
        .count();

    let mut findings: Vec<DiscrepancyFinding> = Vec::new();
    let mut finding_costs = Vec::new();
    let mut index_by_key: HashMap<(String, String, String), usize> = HashMap::new();

    for pair in executed_pairs
        .iter()
        .filter(|pair| pair.disposition == CandidateBypassDisposition::CandidateBypass)
    {
        let key = (
            pair.pair.content_type.clone(),
            pair.pair.canonical_class.clone(),
            pair.pair.payload_family.clone(),
        );

        if let Some(existing_index) = index_by_key.get(&key).copied() {
            if pair.pair.mutation_cost < finding_costs[existing_index] {
                let suppressed = findings[existing_index].suppressed_variants + 1;
                findings[existing_index] = finding_from_pair(pair, suppressed);
                finding_costs[existing_index] = pair.pair.mutation_cost;
            } else {
                findings[existing_index].suppressed_variants += 1;
            }
            continue;
        }

        index_by_key.insert(key, findings.len());
        findings.push(finding_from_pair(pair, 0));
        finding_costs.push(pair.pair.mutation_cost);
    }

    findings.sort_by(|left, right| {
        left.content_type
            .cmp(&right.content_type)
            .then_with(|| left.canonical_class.cmp(&right.canonical_class))
            .then_with(|| {
                right
                    .confidence
                    .partial_cmp(&left.confidence)
                    .unwrap_or(Ordering::Equal)
            })
    });

    let mut by_content_type = HashMap::new();
    let mut by_canonical_class = HashMap::new();
    for finding in &findings {
        *by_content_type
            .entry(finding.content_type.clone())
            .or_insert(0) += 1;
        *by_canonical_class
            .entry(finding.canonical_class.clone())
            .or_insert(0) += 1;
    }

    ParserDiscrepancySummary {
        executed_pairs: executed_pairs.len(),
        candidate_bypasses,
        unique_bypasses: findings.len(),
        by_content_type,
        by_canonical_class,
        findings,
    }
}

fn replay_from_request(url: &str, request: &CuratedRequest) -> ReplayRequest {
    ReplayRequest {
        method: request.method.clone(),
        url: url.to_string(),
        headers: request.headers.clone(),
        body: request.body.clone(),
    }
}

fn finding_from_pair(
    pair: &ExecutedDiscrepancyPair,
    suppressed_variants: usize,
) -> DiscrepancyFinding {
    DiscrepancyFinding {
        content_type: pair.pair.content_type.clone(),
        canonical_class: pair.pair.canonical_class.clone(),
        severity: "HIGH".to_string(),
        confidence: pair.confidence,
        suppressed_variants,
        evidence: format!(
            "Control blocked (status {}, evidence: {}); variant allowed (status {}, evidence: {})",
            pair.control_result.status_code,
            pair.control_result.evidence,
            pair.variant_result.status_code,
            pair.variant_result.evidence
        ),
        control_replay: pair.control_replay.clone(),
        variant_replay: pair.variant_replay.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effectiveness::{EffectivenessConfig, EffectivenessTest};
    use axum::{
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::any,
        Router,
    };
    use std::sync::Arc;
    use tokio::net::TcpListener;

    #[derive(Clone)]
    struct TestServerState {
        mode: TestServerMode,
    }

    #[derive(Clone, Copy)]
    enum TestServerMode {
        BlockOnlyControl,
        AllowEverything,
    }

    struct TestHttpExecutor {
        client: reqwest::Client,
        config: EffectivenessConfig,
    }

    const TEST_XSS_PAYLOAD: &str = "<script>alert(1)</script>";

    #[async_trait]
    impl ParserDiscrepancyExecutor for TestHttpExecutor {
        async fn execute_replay(&mut self, request: &ReplayRequest) -> Result<TestResult> {
            let mut request_builder = self
                .client
                .request(
                    reqwest::Method::from_bytes(request.method.as_bytes())?,
                    &request.url,
                )
                .body(request.body.clone());
            for (name, value) in &request.headers {
                request_builder = request_builder.header(name, value);
            }

            let response = request_builder.send().await?;
            let status_code = response.status().as_u16();
            let mut headers = HashMap::new();
            for (name, value) in response.headers() {
                if let Ok(value_str) = value.to_str() {
                    headers.insert(name.to_string().to_lowercase(), value_str.to_string());
                }
            }
            let body = response.text().await?;
            let (blocked, reasons) =
                EffectivenessTest::is_blocked(status_code, &body, &headers, None, &self.config);

            Ok(TestResult {
                blocked,
                status_code,
                evidence: if blocked {
                    reasons.join("; ")
                } else {
                    "Request allowed".to_string()
                },
                response_time: std::time::Duration::from_millis(1),
                response_body_sample: body.clone(),
                response_body_length: body.len(),
                response_headers: headers,
            })
        }
    }

    async fn start_test_server(mode: TestServerMode) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(TestServerState { mode });
        let app = Router::new()
            .route("/", any(server_handler))
            .with_state(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}/"), handle)
    }

    async fn server_handler(
        State(state): State<Arc<TestServerState>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> (StatusCode, String) {
        let body_text = String::from_utf8_lossy(&body);
        let content_type = headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();

        match state.mode {
            TestServerMode::BlockOnlyControl => {
                if body_text.contains(TEST_XSS_PAYLOAD) && content_type == "application/json" {
                    return (StatusCode::FORBIDDEN, "Access Denied".to_string());
                }
            }
            TestServerMode::AllowEverything => {}
        }

        (StatusCode::OK, "ok".to_string())
    }

    fn sample_pair(control_ct: &str, variant_ct: &str) -> CuratedDiscrepancyPair {
        CuratedDiscrepancyPair {
            name: "Sample JSON pair".to_string(),
            canonical_class: "content_type_case_drift".to_string(),
            content_type: "application/json".to_string(),
            payload_family: "xss-json".to_string(),
            mutation_cost: 1,
            control_request: CuratedRequest {
                method: "POST".to_string(),
                headers: HashMap::from([("Content-Type".to_string(), control_ct.to_string())]),
                body: format!(r#"{{"field1":"{TEST_XSS_PAYLOAD}"}}"#),
            },
            variant_request: CuratedRequest {
                method: "POST".to_string(),
                headers: HashMap::from([("Content-Type".to_string(), variant_ct.to_string())]),
                body: format!(r#"{{"field1":"{TEST_XSS_PAYLOAD}"}}"#),
            },
        }
    }

    #[test]
    fn test_minimization_prefers_lowest_mutation_cost() {
        let replay = ReplayRequest {
            method: "POST".to_string(),
            url: "https://example.com".to_string(),
            headers: HashMap::new(),
            body: "body".to_string(),
        };
        let blocked = TestResult {
            blocked: true,
            status_code: 403,
            evidence: "blocked".to_string(),
            response_time: std::time::Duration::from_millis(1),
            response_body_sample: String::new(),
            response_body_length: 0,
            response_headers: HashMap::new(),
        };
        let allowed = TestResult {
            blocked: false,
            status_code: 200,
            evidence: "allowed".to_string(),
            response_time: std::time::Duration::from_millis(1),
            response_body_sample: String::new(),
            response_body_length: 0,
            response_headers: HashMap::new(),
        };

        let executed_pairs = vec![
            ExecutedDiscrepancyPair {
                pair: CuratedDiscrepancyPair {
                    name: "Higher cost".to_string(),
                    canonical_class: "duplicate_json_keys".to_string(),
                    content_type: "application/json".to_string(),
                    payload_family: "xss-json".to_string(),
                    mutation_cost: 2,
                    control_request: CuratedRequest {
                        method: "POST".to_string(),
                        headers: HashMap::new(),
                        body: "body".to_string(),
                    },
                    variant_request: CuratedRequest {
                        method: "POST".to_string(),
                        headers: HashMap::new(),
                        body: "body".to_string(),
                    },
                },
                control_replay: replay.clone(),
                variant_replay: replay.clone(),
                control_result: blocked.clone(),
                variant_result: allowed.clone(),
                disposition: CandidateBypassDisposition::CandidateBypass,
                confidence: 1.0,
            },
            ExecutedDiscrepancyPair {
                pair: CuratedDiscrepancyPair {
                    name: "Lower cost".to_string(),
                    canonical_class: "duplicate_json_keys".to_string(),
                    content_type: "application/json".to_string(),
                    payload_family: "xss-json".to_string(),
                    mutation_cost: 1,
                    control_request: CuratedRequest {
                        method: "POST".to_string(),
                        headers: HashMap::new(),
                        body: "body".to_string(),
                    },
                    variant_request: CuratedRequest {
                        method: "POST".to_string(),
                        headers: HashMap::new(),
                        body: "body".to_string(),
                    },
                },
                control_replay: replay.clone(),
                variant_replay: replay,
                control_result: blocked,
                variant_result: allowed,
                disposition: CandidateBypassDisposition::CandidateBypass,
                confidence: 1.0,
            },
        ];

        let summary = summarize_candidates(&executed_pairs);
        assert_eq!(summary.candidate_bypasses, 2);
        assert_eq!(summary.unique_bypasses, 1);
        assert_eq!(summary.findings[0].suppressed_variants, 1);
        assert!(summary.findings[0].evidence.contains("status 403"));
    }

    #[tokio::test]
    async fn test_execute_pairs_candidate_bypass_when_control_is_blocked() {
        let (url, handle) = start_test_server(TestServerMode::BlockOnlyControl).await;
        let mut executor = TestHttpExecutor {
            client: reqwest::Client::new(),
            config: EffectivenessConfig::default(),
        };
        let run = execute_pairs(
            &mut executor,
            &url,
            vec![sample_pair(
                "application/json",
                "application/json; profile=\"waffled\"",
            )],
            false,
        )
        .await
        .unwrap();

        handle.abort();

        assert_eq!(run.summary.executed_pairs, 1);
        assert_eq!(run.summary.candidate_bypasses, 1);
        assert_eq!(run.summary.unique_bypasses, 1);
        assert_eq!(run.summary.findings[0].confidence, 1.0);
    }

    #[tokio::test]
    async fn test_execute_pairs_inconclusive_when_control_is_not_blocked() {
        let (url, handle) = start_test_server(TestServerMode::AllowEverything).await;
        let mut executor = TestHttpExecutor {
            client: reqwest::Client::new(),
            config: EffectivenessConfig::default(),
        };
        let run = execute_pairs(
            &mut executor,
            &url,
            vec![sample_pair(
                "application/json",
                "application/json; profile=\"waffled\"",
            )],
            false,
        )
        .await
        .unwrap();

        handle.abort();

        assert_eq!(run.summary.executed_pairs, 1);
        assert_eq!(run.summary.candidate_bypasses, 0);
        assert_eq!(run.summary.unique_bypasses, 0);
    }
}
