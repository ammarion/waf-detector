use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::virtual_adversary::VaRunReport;

/// Persisted Virtual Adversary report wrapper used for CLI replay compatibility.
///
/// Keep field names stable for backward compatibility with existing JSON files.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaStoredReport {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub report: VaRunReport,
}
