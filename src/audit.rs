use crate::active::{current_operator_id, ActiveTargetProfile, ResolvedTarget};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

const HOME_ENV: &str = "WAF_DETECTOR_HOME";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunAudit {
    pub run_id: String,
    pub mode: String,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    pub operator_id: String,
    pub active_target_profile: ActiveTargetProfile,
    #[serde(default)]
    pub resolved_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_event_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuditEventType {
    RunStarted,
    RunCompleted,
    RunFailed,
    ArtifactWritten,
}

#[derive(Debug, Clone, Serialize)]
struct AuditEventPayload<'a> {
    run_id: &'a str,
    mode: &'a str,
    event_type: AuditEventType,
    at: DateTime<Utc>,
    operator_id: &'a str,
    active_target_profile: ActiveTargetProfile,
    target_url: &'a str,
    resolved_ips: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_hash: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditEventRecord {
    run_id: String,
    mode: String,
    event_type: AuditEventType,
    at: DateTime<Utc>,
    operator_id: String,
    active_target_profile: ActiveTargetProfile,
    target_url: String,
    #[serde(default)]
    resolved_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    artifact_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prev_hash: Option<String>,
    event_hash: String,
}

pub struct AuditSession {
    sink_enabled: bool,
    path: PathBuf,
    run_id: String,
    mode: String,
    target_url: String,
    operator_id: String,
    active_target_profile: ActiveTargetProfile,
    resolved_ips: Vec<String>,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    first_event_hash: Option<String>,
    last_event_hash: Option<String>,
    persisted_prev_hash: Option<String>,
}

impl AuditSession {
    pub fn new(mode: &str, target: &ResolvedTarget, sink_enabled: bool) -> Result<Self> {
        let path = audit_log_path();
        let persisted_prev_hash = if sink_enabled {
            read_last_event_hash(&path)?
        } else {
            None
        };
        let started_at = Utc::now();
        let run_id = format!(
            "{}-{}-{}",
            mode,
            started_at.format("%Y%m%d%H%M%S%3f"),
            std::process::id()
        );
        let mut session = Self {
            sink_enabled,
            path,
            run_id,
            mode: mode.to_string(),
            target_url: target.normalized_url.clone(),
            operator_id: current_operator_id(),
            active_target_profile: target.active_target_profile,
            resolved_ips: target.resolved_ip_strings(),
            started_at,
            completed_at: None,
            first_event_hash: None,
            last_event_hash: None,
            persisted_prev_hash,
        };
        session.record_event(AuditEventType::RunStarted, None, None, started_at)?;
        Ok(session)
    }

    pub fn record_completed(&mut self) -> Result<()> {
        let at = Utc::now();
        self.completed_at = Some(at);
        self.record_event(AuditEventType::RunCompleted, None, None, at)
    }

    pub fn record_failed(&mut self, error: &str) -> Result<()> {
        let at = Utc::now();
        self.completed_at = Some(at);
        self.record_event(AuditEventType::RunFailed, None, Some(error), at)
    }

    pub fn record_artifact_written(&mut self, artifact_path: &str) -> Result<()> {
        self.record_event(
            AuditEventType::ArtifactWritten,
            Some(artifact_path),
            None,
            Utc::now(),
        )
    }

    pub fn snapshot(&self) -> RunAudit {
        RunAudit {
            run_id: self.run_id.clone(),
            mode: self.mode.clone(),
            started_at: self.started_at,
            completed_at: self.completed_at,
            operator_id: self.operator_id.clone(),
            active_target_profile: self.active_target_profile,
            resolved_ips: self.resolved_ips.clone(),
            first_event_hash: self.first_event_hash.clone(),
            last_event_hash: self.last_event_hash.clone(),
        }
    }

    fn record_event(
        &mut self,
        event_type: AuditEventType,
        artifact_path: Option<&str>,
        error: Option<&str>,
        at: DateTime<Utc>,
    ) -> Result<()> {
        let prev_hash = self
            .last_event_hash
            .as_deref()
            .or(self.persisted_prev_hash.as_deref());
        let payload = AuditEventPayload {
            run_id: &self.run_id,
            mode: &self.mode,
            event_type: event_type.clone(),
            at,
            operator_id: &self.operator_id,
            active_target_profile: self.active_target_profile,
            target_url: &self.target_url,
            resolved_ips: &self.resolved_ips,
            artifact_path,
            error,
            prev_hash,
        };
        let event_hash = hash_json(&payload)?;
        let record = AuditEventRecord {
            run_id: self.run_id.clone(),
            mode: self.mode.clone(),
            event_type,
            at,
            operator_id: self.operator_id.clone(),
            active_target_profile: self.active_target_profile,
            target_url: self.target_url.clone(),
            resolved_ips: self.resolved_ips.clone(),
            artifact_path: artifact_path.map(str::to_string),
            error: error.map(str::to_string),
            prev_hash: prev_hash.map(str::to_string),
            event_hash: event_hash.clone(),
        };

        if self.sink_enabled {
            append_event(&self.path, &record)?;
        }

        if self.first_event_hash.is_none() {
            self.first_event_hash = Some(event_hash.clone());
        }
        self.last_event_hash = Some(event_hash);
        Ok(())
    }
}

fn audit_log_path() -> PathBuf {
    let home = std::env::var(HOME_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")));
    home.join("audit").join("events.jsonl")
}

fn append_event(path: &PathBuf, record: &AuditEventRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(record)?;
    writeln!(file, "{line}")?;
    Ok(())
}

fn read_last_event_hash(path: &PathBuf) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)?;
    let last_line = content.lines().rev().find(|line| !line.trim().is_empty());
    let Some(last_line) = last_line else {
        return Ok(None);
    };
    let record: AuditEventRecord = serde_json::from_str(last_line)?;
    Ok(Some(record.event_hash))
}

fn hash_json<T: Serialize>(value: &T) -> Result<String> {
    let json = serde_json::to_string(value)?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let digest = hasher.finalize();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active::{ActiveTargetProfile, ResolvedTarget};
    use crate::effectiveness::consent::{ScopeTarget, TargetClass};
    use tempfile::TempDir;

    fn test_target() -> ResolvedTarget {
        ResolvedTarget {
            original_url: "https://example.com".to_string(),
            normalized_url: "https://example.com/".to_string(),
            host: "example.com".to_string(),
            port: 443,
            registered_target: ScopeTarget {
                host: "example.com".to_string(),
                class: TargetClass::Public,
            },
            active_target_profile: ActiveTargetProfile::Public,
            resolved_ips: vec!["93.184.216.34".parse().expect("ip")],
            pinned_ip: "93.184.216.34".parse().expect("ip"),
        }
    }

    #[test]
    fn test_audit_session_records_hash_chain() {
        let temp = TempDir::new().expect("temp dir");
        let original_home = std::env::var(HOME_ENV).ok();
        std::env::set_var(HOME_ENV, temp.path());

        let mut session = AuditSession::new("smoke_test", &test_target(), true).expect("session");
        session.record_completed().expect("complete");
        let audit = session.snapshot();
        assert_eq!(audit.mode, "smoke_test");
        assert!(audit.first_event_hash.is_some());
        assert!(audit.last_event_hash.is_some());
        assert!(audit.completed_at.is_some());

        if let Some(home) = original_home {
            std::env::set_var(HOME_ENV, home);
        } else {
            std::env::remove_var(HOME_ENV);
        }
    }
}
