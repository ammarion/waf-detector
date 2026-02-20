use anyhow::Result;
use serde_json::Value;
use std::process::Command;
use std::time::Duration;
use tokio::time::timeout;

/// Capture output from running the WAF detector CLI
pub struct CliOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub json_output: Option<Value>,
}

/// Run the WAF detector CLI with given arguments
pub fn run_detector_cli(args: &[&str]) -> Result<CliOutput> {
    let binary_path = std::env::var("WAF_DETECTOR_BINARY")
        .unwrap_or_else(|_| "./target/debug/waf-detect".to_string());

    let output = Command::new(&binary_path).args(args).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    // Try to parse JSON output if --json flag was used
    let json_output = if args.contains(&"--json") {
        serde_json::from_str(&stdout).ok()
    } else {
        None
    };

    Ok(CliOutput {
        stdout,
        stderr,
        exit_code,
        json_output,
    })
}

/// Run detector CLI asynchronously with timeout
pub async fn run_detector_cli_async(
    args: &[&str],
    timeout_duration: Duration,
) -> Result<CliOutput> {
    let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();

    timeout(
        timeout_duration,
        tokio::task::spawn_blocking(move || {
            let args_refs: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
            run_detector_cli(&args_refs)
        }),
    )
    .await??
}

/// Capture output from a function that prints to stdout/stderr
pub fn capture_output<F>(f: F) -> (String, String)
where
    F: FnOnce(),
{
    // This is a simplified version. In a real implementation,
    // you might want to use gag or similar crate to capture output
    f();
    (String::new(), String::new())
}

/// Parse detection results from JSON output
pub fn parse_detection_results(json: &Value) -> Result<DetectionResults> {
    let waf = json
        .get("detected_waf")
        .and_then(|w| parse_detection_info(w).ok());

    let cdn = json
        .get("detected_cdn")
        .and_then(|c| parse_detection_info(c).ok());

    let evidence = json
        .get("evidence")
        .and_then(|e| e.as_array())
        .map(|arr| arr.iter().filter_map(|v| parse_evidence(v).ok()).collect())
        .unwrap_or_default();

    Ok(DetectionResults {
        waf,
        cdn,
        evidence,
        raw_json: json.clone(),
    })
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DetectionResults {
    pub waf: Option<DetectionInfo>,
    pub cdn: Option<DetectionInfo>,
    pub evidence: Vec<EvidenceInfo>,
    pub raw_json: Value,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DetectionInfo {
    pub name: String,
    pub confidence: f64,
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EvidenceInfo {
    pub method_type: String,
    pub confidence: f64,
    pub description: String,
}

fn parse_detection_info(value: &Value) -> Result<DetectionInfo> {
    Ok(DetectionInfo {
        name: value
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing name"))?
            .to_string(),
        confidence: value
            .get("confidence")
            .and_then(|v| v.as_f64())
            .ok_or_else(|| anyhow::anyhow!("Missing confidence"))?,
        version: value
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

fn parse_evidence(value: &Value) -> Result<EvidenceInfo> {
    let method_type = match value.get("method_type") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(map)) => {
            // Enum serialization: {"Header":"cf-ray"} or similar
            map.keys()
                .next()
                .cloned()
                .unwrap_or_else(|| "unknown".to_string())
        }
        _ => "unknown".to_string(),
    };

    Ok(EvidenceInfo {
        method_type,
        confidence: value
            .get("confidence")
            .and_then(|v| v.as_f64())
            .ok_or_else(|| anyhow::anyhow!("Missing confidence"))?,
        description: value
            .get("description")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing description"))?
            .to_string(),
    })
}

/// Compare two detection results for equality
pub fn compare_detections(
    actual: &DetectionResults,
    expected_waf: Option<&str>,
    expected_cdn: Option<&str>,
) -> Result<()> {
    // Check WAF detection
    match (expected_waf, &actual.waf) {
        (Some(expected), Some(actual)) => {
            if actual.name != expected {
                return Err(anyhow::anyhow!(
                    "WAF mismatch: expected '{}', got '{}'",
                    expected,
                    actual.name
                ));
            }
        }
        (Some(expected), None) => {
            return Err(anyhow::anyhow!(
                "Expected WAF '{}' but none was detected",
                expected
            ));
        }
        (None, Some(actual)) => {
            return Err(anyhow::anyhow!(
                "Unexpected WAF detected: '{}'",
                actual.name
            ));
        }
        (None, None) => {}
    }

    // Check CDN detection
    match (expected_cdn, &actual.cdn) {
        (Some(expected), Some(actual)) => {
            if actual.name != expected {
                return Err(anyhow::anyhow!(
                    "CDN mismatch: expected '{}', got '{}'",
                    expected,
                    actual.name
                ));
            }
        }
        (Some(expected), None) => {
            return Err(anyhow::anyhow!(
                "Expected CDN '{}' but none was detected",
                expected
            ));
        }
        (None, Some(actual)) => {
            return Err(anyhow::anyhow!(
                "Unexpected CDN detected: '{}'",
                actual.name
            ));
        }
        (None, None) => {}
    }

    Ok(())
}

/// Assert that a CLI command succeeds
pub fn assert_cli_success(output: &CliOutput) -> Result<()> {
    if output.exit_code != 0 {
        return Err(anyhow::anyhow!(
            "CLI command failed with exit code {}: {}",
            output.exit_code,
            output.stderr
        ));
    }
    Ok(())
}

/// Create a temporary test directory
pub fn create_test_dir(name: &str) -> Result<tempfile::TempDir> {
    let dir = tempfile::Builder::new()
        .prefix(&format!("waf-detector-test-{name}-"))
        .tempdir()?;
    Ok(dir)
}

/// Wait for a server to be ready
pub async fn wait_for_server(url: &str, max_attempts: u32) -> Result<()> {
    let client = reqwest::Client::new();

    for i in 0..max_attempts {
        match client.get(url).send().await {
            Ok(_) => return Ok(()),
            Err(_) if i < max_attempts - 1 => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Server not ready after {} attempts: {}",
                    max_attempts,
                    e
                ))
            }
        }
    }

    Ok(())
}

/// Generate test report
pub fn generate_test_report(results: &[(String, bool, String)]) -> String {
    let total = results.len();
    let passed = results.iter().filter(|(_, pass, _)| *pass).count();
    let failed = total - passed;

    let mut report = format!(
        "Test Results Summary\n\
         ===================\n\n\
         Total: {}\n\
         Passed: {} ({:.1}%)\n\
         Failed: {} ({:.1}%)\n\n",
        total,
        passed,
        (passed as f64 / total as f64) * 100.0,
        failed,
        (failed as f64 / total as f64) * 100.0
    );

    if failed > 0 {
        report.push_str("Failed Tests:\n");
        for (name, passed, message) in results {
            if !passed {
                report.push_str(&format!("  - {name}: {message}\n"));
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_detection_results() {
        let json = serde_json::json!({
            "detected_waf": {
                "name": "CloudFlare",
                "confidence": 0.95
            },
            "detected_cdn": {
                "name": "CloudFlare",
                "confidence": 0.95
            },
            "evidence": [
                {
                    "method_type": "Header",
                    "confidence": 0.95,
                    "description": "CF-Ray header detected"
                }
            ]
        });

        let results = parse_detection_results(&json).unwrap();
        assert!(results.waf.is_some());
        assert_eq!(results.waf.unwrap().name, "CloudFlare");
        assert_eq!(results.evidence.len(), 1);
    }
}
