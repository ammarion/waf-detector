/// Visual rendering test - outputs TUI views as text for visual inspection.
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use std::collections::HashMap;
use waf_detector::tui::app::TuiApp;
use waf_detector::tui::state::{Finding, FindingSeverity, LogLevel, ScanState, ViewState};
use waf_detector::{DetectionMetadata, DetectionResult, Evidence, DetectionMethod, ProviderDetection};

fn render_to_string(app: &TuiApp, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| app.draw(f)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let mut output = String::new();
    for y in 0..height {
        for x in 0..width {
            let cell = &buffer[(x, y)];
            output.push_str(cell.symbol());
        }
        // Trim trailing spaces
        let trimmed = output.trim_end().to_string();
        output = trimmed;
        output.push('\n');
    }
    output
}

fn make_populated_app() -> TuiApp {
    let mut app = TuiApp::new(None, Some("https://example.com".to_string()));
    app.state.scan = ScanState::Complete;

    // Add detection result
    let mut evidence_map = HashMap::new();
    evidence_map.insert(
        "CloudFlare".to_string(),
        vec![
            Evidence {
                method_type: DetectionMethod::Header("cf-ray".to_string()),
                confidence: 0.95,
                description: "CF-Ray header detected".to_string(),
                raw_data: "abc123-SEA".to_string(),
                signature_matched: "cf-ray".to_string(),
            },
            Evidence {
                method_type: DetectionMethod::Header("server".to_string()),
                confidence: 0.85,
                description: "Server: cloudflare".to_string(),
                raw_data: "cloudflare".to_string(),
                signature_matched: "server-cloudflare".to_string(),
            },
        ],
    );
    app.state.detection = Some(DetectionResult {
        url: "https://example.com".to_string(),
        detected_waf: Some(ProviderDetection {
            name: "CloudFlare".to_string(),
            confidence: 0.95,
        }),
        detected_cdn: Some(ProviderDetection {
            name: "CloudFlare".to_string(),
            confidence: 0.90,
        }),
        provider_scores: HashMap::new(),
        evidence_map,
        evidence: Vec::new(),
        detection_time_ms: 342,
        metadata: DetectionMetadata {
            timestamp: chrono::Utc::now(),
            version: "0.1.0".to_string(),
            user_agent: "WAF-Detector/1.0".to_string(),
        },
        caveats: vec![],
        security_posture: None,
        error: None,
    });

    // Add findings
    app.state.findings = vec![
        Finding {
            severity: FindingSeverity::Critical,
            title: "Body channel blind spot (0% discrimination)".to_string(),
            source: "VA2".to_string(),
            impact: "WAF does not inspect Body channel".to_string(),
            recommendation: "Enable body inspection in WAF config".to_string(),
        },
        Finding {
            severity: FindingSeverity::Medium,
            title: "No rate limiting detected".to_string(),
            source: "VA2".to_string(),
            impact: "Vulnerable to brute-force attacks".to_string(),
            recommendation: "Add rate-limiting rules".to_string(),
        },
        Finding {
            severity: FindingSeverity::Medium,
            title: "42% of attack probes allowed through".to_string(),
            source: "VA1".to_string(),
            impact: "Significant WAF bypass rate".to_string(),
            recommendation: "Review WAF ruleset for coverage gaps".to_string(),
        },
        Finding {
            severity: FindingSeverity::Low,
            title: "No statefulness detected".to_string(),
            source: "VA2".to_string(),
            impact: "Multi-step attacks may go undetected".to_string(),
            recommendation: "Enable session-aware rules".to_string(),
        },
    ];

    // Add log entries
    app.state.push_log(LogLevel::Info, "Detection started".to_string());
    app.state.push_log(LogLevel::Info, "WAF detected: CloudFlare (95%)".to_string());
    app.state.push_log(LogLevel::Info, "VA1 enforcement testing complete".to_string());
    app.state.push_log(LogLevel::Warn, "VA2 challenge score low: 35%".to_string());
    app.state.push_log(LogLevel::Info, "Scan complete".to_string());

    app
}

#[test]
fn visual_dashboard() {
    let app = make_populated_app();
    let screen = render_to_string(&app, 100, 22);
    println!("\n=== DASHBOARD VIEW ===");
    println!("{}", screen);
}

#[test]
fn visual_detection() {
    let mut app = make_populated_app();
    app.state.view = ViewState::Detection;
    let screen = render_to_string(&app, 100, 22);
    println!("\n=== DETECTION VIEW ===");
    println!("{}", screen);
}

#[test]
fn visual_findings() {
    let mut app = make_populated_app();
    app.state.view = ViewState::Findings;
    let screen = render_to_string(&app, 100, 22);
    println!("\n=== FINDINGS VIEW ===");
    println!("{}", screen);
}

#[test]
fn visual_findings_expanded() {
    let mut app = make_populated_app();
    app.state.view = ViewState::Findings;
    app.state.selected = 0;
    app.state.expanded = true;
    let screen = render_to_string(&app, 100, 22);
    println!("\n=== FINDINGS VIEW (EXPANDED) ===");
    println!("{}", screen);
}

#[test]
fn visual_log() {
    let mut app = make_populated_app();
    app.state.view = ViewState::Log;
    let screen = render_to_string(&app, 100, 22);
    println!("\n=== LOG VIEW ===");
    println!("{}", screen);
}

#[test]
fn visual_help() {
    let mut app = make_populated_app();
    app.state.show_help = true;
    let screen = render_to_string(&app, 100, 22);
    println!("\n=== HELP OVERLAY ===");
    println!("{}", screen);
}
