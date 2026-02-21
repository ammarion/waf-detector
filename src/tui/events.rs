use crate::payload::waf_smoke_test::SmokeTestResult;
use crate::virtual_adversary::VaRunReport;
use crate::virtual_adversary2::Va2RunReport;
use crate::DetectionResult;
use crossterm::event::KeyEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanType {
    Detection,
    SmokeTest,
    VA1,
    VA2,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Detection => write!(f, "Detection"),
            ScanType::SmokeTest => write!(f, "SmokeTest"),
            ScanType::VA1 => write!(f, "VA1"),
            ScanType::VA2 => write!(f, "VA2"),
        }
    }
}

pub enum TuiEvent {
    Key(KeyEvent),
    ScanProgress {
        scan_type: ScanType,
        current: u32,
        total: u32,
    },
    DetectionDone(Box<DetectionResult>),
    SmokeTestDone(Box<SmokeTestResult>),
    Va1Done(Box<VaRunReport>),
    Va2Done(Box<Va2RunReport>),
    Log {
        level: LogLevel,
        msg: String,
    },
    Error {
        scan_type: ScanType,
        msg: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}
