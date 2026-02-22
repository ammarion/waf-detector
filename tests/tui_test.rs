/// Integration test for the TUI module.
/// Uses ratatui's TestBackend to render without a real terminal.
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use waf_detector::tui::app::TuiApp;
use waf_detector::tui::state::{FindingSeverity, Finding, LogLevel, ScanState, ViewState};

fn make_app() -> TuiApp {
    TuiApp::new(None, Some("https://example.com".to_string()))
}

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
        output.push('\n');
    }
    output
}

#[test]
fn test_dashboard_renders_header_and_nav() {
    let app = make_app();
    let screen = render_to_string(&app, 100, 25);

    // Header should show WAF Detector and target URL
    assert!(screen.contains("WAF Detector"), "Header missing 'WAF Detector'");
    assert!(screen.contains("example.com"), "Header missing target URL");

    // Nav bar should show view labels
    assert!(screen.contains("Dashboard"), "Nav missing Dashboard");
    assert!(screen.contains("Detection"), "Nav missing Detection");
    assert!(screen.contains("VA1"), "Nav missing VA1");
    assert!(screen.contains("VA2"), "Nav missing VA2");
    assert!(screen.contains("Findings"), "Nav missing Findings");
    assert!(screen.contains("Log"), "Nav missing Log");
    assert!(screen.contains("Help"), "Nav missing Help");
    assert!(screen.contains("Quit"), "Nav missing Quit");
}

#[test]
fn test_dashboard_idle_state() {
    let app = make_app();
    let screen = render_to_string(&app, 100, 25);

    // Should show posture overview and prompt to scan
    assert!(screen.contains("Posture Overview"), "Missing posture section");
    assert!(
        screen.contains("Awaiting scan") || screen.contains("Press [r]"),
        "Should prompt for scan"
    );
    assert!(screen.contains("Idle"), "Should show Idle status");
}

#[test]
fn test_view_state_switching() {
    let mut app = make_app();

    assert_eq!(app.state.view, ViewState::Dashboard);

    app.state.view = ViewState::Detection;
    let screen = render_to_string(&app, 100, 25);
    assert!(screen.contains("Detection Evidence"), "Detection view not shown");

    app.state.view = ViewState::VA1;
    let screen = render_to_string(&app, 100, 25);
    assert!(screen.contains("VA1 Enforcement"), "VA1 view not shown");

    app.state.view = ViewState::VA2;
    let screen = render_to_string(&app, 100, 25);
    assert!(screen.contains("VA2 Behavioral"), "VA2 view not shown");

    app.state.view = ViewState::Findings;
    let screen = render_to_string(&app, 100, 25);
    assert!(screen.contains("Actionable Findings"), "Findings view not shown");

    app.state.view = ViewState::Log;
    let screen = render_to_string(&app, 100, 25);
    assert!(screen.contains("Event Log"), "Log view not shown");
}

#[test]
fn test_help_overlay() {
    let mut app = make_app();
    app.state.show_help = true;
    let screen = render_to_string(&app, 100, 25);
    assert!(screen.contains("Keyboard Shortcuts"), "Help overlay not shown");
    assert!(screen.contains("Run full scan"), "Help missing scan shortcut");
    assert!(screen.contains("Export report"), "Help missing export shortcut");
}

#[test]
fn test_tooltip_panel() {
    let mut app = make_app();
    app.state.show_tooltip = true;
    app.state.view = ViewState::VA2;
    let screen = render_to_string(&app, 120, 25);
    assert!(screen.contains("Info"), "Tooltip panel not shown");
}

#[test]
fn test_findings_view_with_data() {
    let mut app = make_app();
    app.state.view = ViewState::Findings;
    app.state.scan = ScanState::Complete;
    app.state.findings = vec![
        Finding {
            severity: FindingSeverity::Critical,
            title: "Body channel blind spot".to_string(),
            source: "VA2".to_string(),
            impact: "Attacks via body bypass all rules".to_string(),
            recommendation: "Enable body inspection".to_string(),
        },
        Finding {
            severity: FindingSeverity::Medium,
            title: "No rate limiting".to_string(),
            source: "VA2".to_string(),
            impact: "Vulnerable to brute force".to_string(),
            recommendation: "Add rate limiting rules".to_string(),
        },
    ];

    let screen = render_to_string(&app, 120, 25);
    assert!(screen.contains("CRITICAL"), "Critical severity not shown");
    assert!(screen.contains("MEDIUM"), "Medium severity not shown");
    assert!(screen.contains("Body channel"), "Finding title not shown");
    assert!(screen.contains("rate limiting"), "Second finding not shown");
}

#[test]
fn test_log_view_with_entries() {
    let mut app = make_app();
    app.state.view = ViewState::Log;
    app.state.push_log(LogLevel::Info, "Detection started".to_string());
    app.state.push_log(LogLevel::Warn, "VA1 consent missing".to_string());
    app.state.push_log(LogLevel::Error, "VA2 timeout".to_string());

    let screen = render_to_string(&app, 120, 25);
    assert!(screen.contains("Detection started"), "Info log not shown");
    assert!(screen.contains("consent missing"), "Warn log not shown");
    assert!(screen.contains("VA2 timeout"), "Error log not shown");
    assert!(screen.contains("INFO"), "Info level not shown");
    assert!(screen.contains("WARN"), "Warn level not shown");
    assert!(screen.contains("ERROR"), "Error level not shown");
}

#[test]
fn test_scan_state_labels() {
    assert_eq!(ScanState::Idle.label(), "Idle");
    assert_eq!(ScanState::RunningDetection.label(), "Detecting WAF/CDN...");
    assert_eq!(ScanState::RunningVA1.label(), "Running VA1 enforcement...");
    assert_eq!(ScanState::RunningVA2.label(), "Running VA2 behavioral...");
    assert_eq!(ScanState::Complete.label(), "Complete");

    assert!(!ScanState::Idle.is_running());
    assert!(ScanState::RunningDetection.is_running());
    assert!(ScanState::RunningVA1.is_running());
    assert!(ScanState::RunningVA2.is_running());
    assert!(!ScanState::Complete.is_running());
}

#[test]
fn test_view_state_navigation() {
    assert_eq!(ViewState::Dashboard.next(), ViewState::Detection);
    assert_eq!(ViewState::Detection.next(), ViewState::SmokeTest);
    assert_eq!(ViewState::SmokeTest.next(), ViewState::VA1);
    assert_eq!(ViewState::VA1.next(), ViewState::VA2);
    assert_eq!(ViewState::VA2.next(), ViewState::Findings);
    assert_eq!(ViewState::Findings.next(), ViewState::Log);
    assert_eq!(ViewState::Log.next(), ViewState::Dashboard);
}

#[test]
fn test_review_mode_flag() {
    // With URL: not review mode
    let app = TuiApp::new(None, Some("https://example.com".to_string()));
    assert!(!app.state.review_mode);
    assert_eq!(app.state.scan, ScanState::Idle);

    // Without URL: review mode
    let app = TuiApp::new(None, None);
    assert!(app.state.review_mode);
    assert_eq!(app.state.scan, ScanState::Complete);
}

#[test]
fn test_progress_display() {
    let mut app = make_app();
    app.state.scan = ScanState::RunningDetection;
    app.state.progress = Some((5, 10));
    let screen = render_to_string(&app, 100, 25);
    assert!(screen.contains("5/10"), "Progress not shown");
    assert!(
        screen.contains("Detecting WAF/CDN"),
        "Scan state not shown"
    );
}

#[test]
fn test_empty_views_show_placeholder() {
    let mut app = make_app();

    // Detection view without data
    app.state.view = ViewState::Detection;
    let screen = render_to_string(&app, 100, 25);
    assert!(
        screen.contains("No detection data") || screen.contains("Press [r]"),
        "Detection placeholder missing"
    );

    // VA1 view without data
    app.state.view = ViewState::VA1;
    let screen = render_to_string(&app, 100, 25);
    assert!(
        screen.contains("No VA1 data") || screen.contains("Press [r]"),
        "VA1 placeholder missing"
    );

    // VA2 view without data
    app.state.view = ViewState::VA2;
    let screen = render_to_string(&app, 100, 25);
    assert!(
        screen.contains("No VA2 data") || screen.contains("Press [r]"),
        "VA2 placeholder missing"
    );
}
