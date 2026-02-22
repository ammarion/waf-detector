use crate::payload::waf_smoke_test::SmokeTestResult;
use crate::posture::PostureReport;
use crate::virtual_adversary::VaRunReport;
use crate::virtual_adversary2::Va2RunReport;
use crate::DetectionResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewState {
    Dashboard,
    Detection,
    SmokeTest,
    VA1,
    VA2,
    Findings,
    Log,
}

impl ViewState {
    pub const ALL: [ViewState; 7] = [
        ViewState::Dashboard,
        ViewState::Detection,
        ViewState::SmokeTest,
        ViewState::VA1,
        ViewState::VA2,
        ViewState::Findings,
        ViewState::Log,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            ViewState::Dashboard => "Dashboard",
            ViewState::Detection => "Detection",
            ViewState::SmokeTest => "Smoke",
            ViewState::VA1 => "Enforce",
            ViewState::VA2 => "Behav.",
            ViewState::Findings => "Findings",
            ViewState::Log => "Log",
        }
    }

    pub fn index(&self) -> usize {
        match self {
            ViewState::Dashboard => 0,
            ViewState::Detection => 1,
            ViewState::SmokeTest => 2,
            ViewState::VA1 => 3,
            ViewState::VA2 => 4,
            ViewState::Findings => 5,
            ViewState::Log => 6,
        }
    }

    pub fn next(&self) -> ViewState {
        let idx = (self.index() + 1) % Self::ALL.len();
        Self::ALL[idx]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanState {
    Idle,
    RunningDetection,
    RunningSmokeTest,
    RunningVA1,
    RunningVA2,
    Complete,
}

impl ScanState {
    pub fn label(&self) -> &'static str {
        match self {
            ScanState::Idle => "Idle",
            ScanState::RunningDetection => "Detecting WAF/CDN...",
            ScanState::RunningSmokeTest => "Running smoke test...",
            ScanState::RunningVA1 => "Testing enforcement...",
            ScanState::RunningVA2 => "Analyzing behavior...",
            ScanState::Complete => "Complete",
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(
            self,
            ScanState::RunningDetection
                | ScanState::RunningSmokeTest
                | ScanState::RunningVA1
                | ScanState::RunningVA2
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingSeverity {
    Critical,
    Medium,
    Low,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Critical => write!(f, "CRITICAL"),
            FindingSeverity::Medium => write!(f, "MEDIUM"),
            FindingSeverity::Low => write!(f, "LOW"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: FindingSeverity,
    pub title: String,
    pub source: String,
    pub impact: String,
    pub recommendation: String,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub msg: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

pub struct AppState {
    pub view: ViewState,
    pub scan: ScanState,
    pub target_url: Option<String>,
    pub detection: Option<DetectionResult>,
    pub smoke: Option<SmokeTestResult>,
    pub va1: Option<VaRunReport>,
    pub va2: Option<Va2RunReport>,
    pub posture: Option<PostureReport>,
    pub findings: Vec<Finding>,
    pub log: Vec<LogEntry>,
    pub selected: usize,
    pub expanded: bool,
    pub show_help: bool,
    pub show_tooltip: bool,
    pub quit: bool,
    pub review_mode: bool,
    pub progress: Option<(u32, u32)>,
    pub status_msg: Option<String>,
}

impl AppState {
    pub fn new(target_url: Option<String>) -> Self {
        let review_mode = target_url.is_none();
        Self {
            view: ViewState::Dashboard,
            scan: if review_mode {
                ScanState::Complete
            } else {
                ScanState::Idle
            },
            target_url,
            detection: None,
            smoke: None,
            va1: None,
            va2: None,
            posture: None,
            findings: Vec::new(),
            log: Vec::new(),
            selected: 0,
            expanded: false,
            show_help: false,
            show_tooltip: false,
            quit: false,
            review_mode,
            progress: None,
            status_msg: None,
        }
    }

    pub fn push_log(&mut self, level: LogLevel, msg: String) {
        self.log.push(LogEntry {
            level,
            msg,
            timestamp: chrono::Utc::now(),
        });
    }
}
