use crate::payload::waf_smoke_test::SmokeTestResult;
use crate::posture::PostureReport;
use crate::virtual_adversary::VaRunReport;
use crate::virtual_adversary2::Va2RunReport;
use crate::DetectionResult;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::state::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullReport {
    pub target_url: String,
    pub timestamp: DateTime<Utc>,
    pub detected_waf: Option<String>,
    pub detection: Option<DetectionResult>,
    pub smoke: Option<SmokeTestResult>,
    pub va1: Option<VaRunReport>,
    pub va2: Option<Va2RunReport>,
    pub posture: Option<PostureReport>,
    pub findings: Vec<Finding>,
}

impl FullReport {
    pub fn from_state(state: &super::state::AppState) -> Self {
        let detected_waf = state
            .detection
            .as_ref()
            .and_then(|d| d.detected_waf.as_ref())
            .map(|w| w.name.clone());

        Self {
            target_url: state.target_url.clone().unwrap_or_default(),
            timestamp: Utc::now(),
            detected_waf,
            detection: state.detection.clone(),
            smoke: state.smoke.clone(),
            va1: state.va1.clone(),
            va2: state.va2.clone(),
            posture: state.posture.clone(),
            findings: state.findings.clone(),
        }
    }
}

pub fn auto_save_dir() -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    let dir = home.join(".waf-detector");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

pub fn auto_save(state: &super::state::AppState) -> Result<std::path::PathBuf> {
    let report = FullReport::from_state(state);
    let dir = auto_save_dir()?;
    let path = dir.join("last-report.json");
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(&path, json)?;
    Ok(path)
}

pub fn export_to_path(state: &super::state::AppState, path: &str) -> Result<()> {
    let report = FullReport::from_state(state);
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn load_last_report() -> Result<FullReport> {
    let dir = auto_save_dir()?;
    let path = dir.join("last-report.json");
    let json = std::fs::read_to_string(&path)
        .map_err(|_| anyhow::anyhow!("No saved report found at {:?}. Run a scan first.", path))?;
    let report: FullReport = serde_json::from_str(&json)?;
    Ok(report)
}
