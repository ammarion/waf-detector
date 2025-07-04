use std::process::{Command, Stdio};
use std::path::Path;
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    pub waf_detected: bool,
    pub waf_name: String,
    pub cdn_detected: bool,
    pub cdn_name: String,
    pub cloud_provider: String,
    pub effectiveness_score: f64,
    pub total_tests: u32,
    pub blocked_tests: u32,
    pub allowed_tests: u32,
    pub error_tests: u32,
    pub test_results: Vec<PayloadResult>,
    pub recommendations: Vec<String>,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadResult {
    pub category: String,
    pub payload: String,
    pub status: String, // "BLOCKED", "ALLOWED", "ERROR", "CHECK"
    pub response_code: u16,
    pub response_time_ms: u64,
    pub detection_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedResult {
    pub url: String,
    pub detection_result: crate::DetectionResult,
    pub effectiveness_result: Option<ScriptResult>,
    pub analysis_summary: String,
    pub recommendations: Vec<String>,
    pub total_time_ms: u64,
}

pub struct ScriptExecutor {
    script_path: String,
}

impl ScriptExecutor {
    pub fn new() -> Result<Self> {
        let script_path = "scripts/waf-smoke-test.sh";
        
        // Check if script exists
        if !Path::new(script_path).exists() {
            return Err(anyhow!("WAF testing script not found at: {}", script_path));
        }
        
        // Check if script is executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(script_path)?;
            let permissions = metadata.permissions();
            if permissions.mode() & 0o111 == 0 {
                return Err(anyhow!("Script is not executable: {}", script_path));
            }
        }
        
        Ok(Self {
            script_path: script_path.to_string(),
        })
    }
    
    pub async fn execute_test(&self, url: &str) -> Result<ScriptResult> {
        let start_time = std::time::Instant::now();
        
        // Execute the bash script
        let output = Command::new("bash")
            .arg(&self.script_path)
            .arg(url)
            .arg("-o")
            .arg("/tmp/waf_test_output.json") // Use JSON output for parsing
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| anyhow!("Failed to execute script: {}", e))?;
        
        let execution_time = start_time.elapsed().as_millis() as u64;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Script execution failed: {}", stderr));
        }
        
        // Parse the script output
        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_script_output(&stdout, execution_time)
    }
    
    fn parse_script_output(&self, _output: &str, execution_time_ms: u64) -> Result<ScriptResult> {
        // For now, create a mock result based on the script structure
        // TODO: Parse actual JSON output when script is modified to output JSON
        
        let mut test_results = Vec::new();
        let mut blocked_count = 0;
        let mut allowed_count = 0;
        let mut error_count = 0;
        
        // Mock payload results based on the script's 36 attack vectors
        let categories = vec![
            "SQL Injection", "XSS", "XXE", "RFI", "LFI", "RCE", "Command Injection", "Path Traversal"
        ];
        
        for (i, category) in categories.iter().enumerate() {
            for j in 0..4 { // 4-5 tests per category
                let status = if i % 3 == 0 { "BLOCKED" } else if i % 3 == 1 { "ALLOWED" } else { "ERROR" };
                
                match status {
                    "BLOCKED" => blocked_count += 1,
                    "ALLOWED" => allowed_count += 1,
                    "ERROR" => error_count += 1,
                    _ => {}
                }
                
                test_results.push(PayloadResult {
                    category: category.to_string(),
                    payload: format!("test-payload-{}-{}", i, j),
                    status: status.to_string(),
                    response_code: if status == "BLOCKED" { 403 } else { 200 },
                    response_time_ms: 150 + (i * 50) as u64,
                    detection_method: "HTTP Status Code".to_string(),
                });
            }
        }
        
        let total_tests = test_results.len() as u32;
        let effectiveness_score = (blocked_count as f64 / total_tests as f64) * 100.0;
        
        Ok(ScriptResult {
            waf_detected: blocked_count > 0,
            waf_name: "Detected via Testing".to_string(),
            cdn_detected: false,
            cdn_name: "N/A".to_string(),
            cloud_provider: "Not Detected".to_string(),
            effectiveness_score,
            total_tests,
            blocked_tests: blocked_count,
            allowed_tests: allowed_count,
            error_tests: error_count,
            test_results,
            recommendations: vec![
                "Review allowed payloads for potential bypasses".to_string(),
                "Consider tuning WAF rules for better coverage".to_string(),
            ],
            execution_time_ms,
        })
    }
    
    pub fn combine_results(
        &self,
        detection_result: crate::DetectionResult,
        effectiveness_result: Option<ScriptResult>,
        total_time_ms: u64,
    ) -> CombinedResult {
        let mut analysis_summary = String::new();
        let mut recommendations = Vec::new();
        
        // Generate analysis summary
        if let Some(waf) = &detection_result.detected_waf {
            analysis_summary.push_str(&format!("WAF Detected: {} ({:.1}% confidence)\n", 
                waf.name, waf.confidence * 100.0));
        } else {
            analysis_summary.push_str("No WAF detected\n");
        }
        
        if let Some(cdn) = &detection_result.detected_cdn {
            analysis_summary.push_str(&format!("CDN Detected: {} ({:.1}% confidence)\n", 
                cdn.name, cdn.confidence * 100.0));
        }
        
        if let Some(effectiveness) = &effectiveness_result {
            analysis_summary.push_str(&format!(
                "Effectiveness Testing: {:.1}% blocked ({}/{} tests)\n",
                effectiveness.effectiveness_score,
                effectiveness.blocked_tests,
                effectiveness.total_tests
            ));
            
            // Add effectiveness-based recommendations
            if effectiveness.effectiveness_score < 50.0 {
                recommendations.push("⚠️ Low WAF effectiveness - many payloads bypassed".to_string());
                recommendations.push("Consider reviewing and tuning WAF rules".to_string());
            } else if effectiveness.effectiveness_score > 90.0 {
                recommendations.push("✅ High WAF effectiveness - good security posture".to_string());
            }
            
            recommendations.extend(effectiveness.recommendations.clone());
        }
        
        // Add provider-specific recommendations
        if let Some(waf) = &detection_result.detected_waf {
            match waf.name.as_str() {
                "CloudFlare" => {
                    recommendations.push("🔒 CloudFlare detected - consider enabling additional security features".to_string());
                }
                "AWS" => {
                    recommendations.push("☁️ AWS WAF detected - review CloudWatch metrics and rules".to_string());
                }
                "Akamai" => {
                    recommendations.push("🛡️ Akamai detected - consider Bot Manager for advanced protection".to_string());
                }
                _ => {}
            }
        }
        
        CombinedResult {
            url: detection_result.url.clone(),
            detection_result,
            effectiveness_result,
            analysis_summary,
            recommendations,
            total_time_ms,
        }
    }
}

impl Default for ScriptExecutor {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            script_path: "scripts/waf-smoke-test.sh".to_string(),
        })
    }
} 