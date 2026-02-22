use anyhow::Result;
use crossterm::event::{self, Event, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::Frame;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::engine::DetectionEngine;
use crate::payload::waf_smoke_test::{SmokeTestConfig, WafSmokeTest};
use crate::posture::PostureBuilder;
use crate::virtual_adversary::{VirtualAdversaryConfig, VirtualAdversaryRunner};
use crate::virtual_adversary2::{build_va2_campaign_plan, Va2CampaignConfig, Va2Runner};

use super::events::{LogLevel as EventLogLevel, ScanType, TuiEvent};
use super::keybindings::{self, Action};
use super::state::{AppState, LogLevel, ScanState, ViewState};
use super::{components, views};

pub struct TuiApp {
    pub state: AppState,
    pub event_tx: mpsc::UnboundedSender<TuiEvent>,
    pub event_rx: mpsc::UnboundedReceiver<TuiEvent>,
    engine: Option<DetectionEngine>,
}

impl TuiApp {
    pub fn new(engine: Option<DetectionEngine>, target_url: Option<String>) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        Self {
            state: AppState::new(target_url),
            event_tx,
            event_rx,
            engine,
        }
    }

    pub async fn run_loop(&mut self) -> Result<()> {
        loop {
            // Poll for crossterm keyboard events
            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    self.event_tx.send(TuiEvent::Key(key)).ok();
                }
            }

            // Drain all pending TUI events
            while let Ok(evt) = self.event_rx.try_recv() {
                self.handle_event(evt).await?;
            }

            if self.state.quit {
                break;
            }
        }
        Ok(())
    }

    pub async fn handle_event(&mut self, evt: TuiEvent) -> Result<()> {
        match evt {
            TuiEvent::Key(key) => self.handle_key(key).await?,
            TuiEvent::ScanProgress {
                scan_type: _,
                current,
                total,
            } => {
                self.state.progress = Some((current, total));
            }
            TuiEvent::DetectionDone(result) => {
                self.state.detection = Some(*result);
                self.state.scan = ScanState::RunningSmokeTest;
                self.state.push_log(LogLevel::Info, "Detection complete".to_string());
            }
            TuiEvent::SmokeTestDone(result) => {
                let effectiveness = result.summary.effectiveness_percentage;
                self.state.smoke = Some(*result);
                self.state.scan = ScanState::RunningVA1;
                self.state.push_log(
                    LogLevel::Info,
                    format!("Smoke test complete ({:.0}% effectiveness)", effectiveness),
                );
            }
            TuiEvent::Va1Done(report) => {
                self.state.va1 = Some(*report);
                self.state.scan = ScanState::RunningVA2;
                self.state.push_log(LogLevel::Info, "VA1 enforcement testing complete".to_string());
            }
            TuiEvent::Va2Done(report) => {
                self.state.va2 = Some(*report);
                self.state.scan = ScanState::Complete;
                self.state.progress = None;
                self.state.push_log(
                    LogLevel::Info,
                    "VA2 behavioral profiling complete".to_string(),
                );
                self.compute_posture();
                self.extract_findings();
                // Auto-save on completion
                match super::export::auto_save(&self.state) {
                    Ok(path) => {
                        self.state.push_log(
                            LogLevel::Info,
                            format!("Report auto-saved to {}", path.display()),
                        );
                    }
                    Err(e) => {
                        self.state
                            .push_log(LogLevel::Warn, format!("Auto-save failed: {}", e));
                    }
                }
            }
            TuiEvent::Log { level, msg } => {
                let log_level = match level {
                    EventLogLevel::Info => LogLevel::Info,
                    EventLogLevel::Warn => LogLevel::Warn,
                    EventLogLevel::Error => LogLevel::Error,
                };
                self.state.push_log(log_level, msg);
            }
            TuiEvent::Error { scan_type, msg } => {
                self.state
                    .push_log(LogLevel::Error, format!("{} error: {}", scan_type, msg));
                self.state.scan = ScanState::Complete;
                self.state.progress = None;
            }
        }
        Ok(())
    }

    async fn handle_key(&mut self, key: KeyEvent) -> Result<()> {
        let action = keybindings::map_key(key);
        match action {
            Action::Quit => {
                self.state.quit = true;
            }
            Action::SwitchView(view) => {
                self.state.view = view;
                self.state.selected = 0;
                self.state.expanded = false;
            }
            Action::NextView => {
                self.state.view = self.state.view.next();
                self.state.selected = 0;
                self.state.expanded = false;
            }
            Action::NavigateDown => {
                self.state.selected = self.state.selected.saturating_add(1);
            }
            Action::NavigateUp => {
                self.state.selected = self.state.selected.saturating_sub(1);
            }
            Action::Expand => {
                self.state.expanded = true;
            }
            Action::Collapse => {
                if self.state.expanded {
                    self.state.expanded = false;
                }
            }
            Action::RunScan => {
                if !self.state.review_mode && !self.state.scan.is_running() {
                    self.start_scan().await;
                }
            }
            Action::Export => {
                let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
                let filename = format!("waf-report-{}.json", timestamp);
                match super::export::export_to_path(&self.state, &filename) {
                    Ok(()) => {
                        self.state.status_msg = Some(format!("Exported to {}", filename));
                        self.state
                            .push_log(LogLevel::Info, format!("Report exported to {}", filename));
                    }
                    Err(e) => {
                        self.state.status_msg = Some(format!("Export failed: {}", e));
                    }
                }
            }
            Action::AgentPrep => {
                match super::export::auto_save(&self.state) {
                    Ok(path) => {
                        self.state.status_msg = Some(format!(
                            "Saved to {}. Run /waf-review in Claude Code.",
                            path.display()
                        ));
                        self.state.push_log(
                            LogLevel::Info,
                            "Report saved for Claude analysis".to_string(),
                        );
                    }
                    Err(e) => {
                        self.state.status_msg = Some(format!("Save failed: {}", e));
                    }
                }
            }
            Action::ToggleHelp => {
                self.state.show_help = !self.state.show_help;
            }
            Action::ToggleTooltip => {
                self.state.show_tooltip = !self.state.show_tooltip;
            }
            Action::None => {}
        }
        Ok(())
    }

    async fn start_scan(&mut self) {
        let engine = match &self.engine {
            Some(e) => e.clone(),
            None => {
                self.state
                    .push_log(LogLevel::Error, "No detection engine available".to_string());
                return;
            }
        };

        let url = match &self.state.target_url {
            Some(u) => u.clone(),
            None => {
                self.state
                    .push_log(LogLevel::Error, "No target URL specified".to_string());
                return;
            }
        };

        self.state.scan = ScanState::RunningDetection;
        self.state.detection = None;
        self.state.smoke = None;
        self.state.va1 = None;
        self.state.va2 = None;
        self.state.posture = None;
        self.state.findings.clear();
        self.state.push_log(LogLevel::Info, format!("Starting scan: {}", url));

        let tx = self.event_tx.clone();

        // Spawn the full scan pipeline in a background task
        tokio::spawn(async move {
            // Phase 1: Detection
            tx.send(TuiEvent::Log {
                level: EventLogLevel::Info,
                msg: "Running WAF/CDN detection...".to_string(),
            })
            .ok();

            match engine.detect(&url).await {
                Ok(result) => {
                    tx.send(TuiEvent::DetectionDone(Box::new(result))).ok();
                }
                Err(e) => {
                    tx.send(TuiEvent::Error {
                        scan_type: ScanType::Detection,
                        msg: e.to_string(),
                    })
                    .ok();
                    return;
                }
            }

            // Phase 2: Smoke testing
            tx.send(TuiEvent::Log {
                level: EventLogLevel::Info,
                msg: "Running WAF smoke testing...".to_string(),
            })
            .ok();

            let smoke_config = SmokeTestConfig {
                quiet: true,
                ..SmokeTestConfig::default()
            };
            match WafSmokeTest::new(smoke_config) {
                Ok(smoke_tester) => match smoke_tester.run_test(&url).await {
                    Ok(result) => {
                        tx.send(TuiEvent::SmokeTestDone(Box::new(result))).ok();
                    }
                    Err(e) => {
                        tx.send(TuiEvent::Log {
                            level: EventLogLevel::Warn,
                            msg: format!("Smoke test failed (continuing): {}", e),
                        })
                        .ok();
                        // Advance state past smoke test
                        tx.send(TuiEvent::Log {
                            level: EventLogLevel::Info,
                            msg: "Skipping smoke test, advancing to VA1...".to_string(),
                        })
                        .ok();
                    }
                },
                Err(e) => {
                    tx.send(TuiEvent::Log {
                        level: EventLogLevel::Warn,
                        msg: format!("Smoke test init failed (continuing): {}", e),
                    })
                    .ok();
                }
            }

            // Phase 3: VA1 enforcement
            tx.send(TuiEvent::Log {
                level: EventLogLevel::Info,
                msg: "Running VA1 enforcement testing...".to_string(),
            })
            .ok();

            let va1_config = VirtualAdversaryConfig {
                tier: 1,
                request_budget: 60,
                request_timeout: std::time::Duration::from_secs(15),
                request_delay: std::time::Duration::from_millis(500),
                max_variants_per_payload: 3,
                skip_dns_validation: false,
            };
            match VirtualAdversaryRunner::new(va1_config) {
                Ok(mut runner) => match runner.run(&url) {
                    Ok(report) => {
                        tx.send(TuiEvent::Va1Done(Box::new(report))).ok();
                    }
                    Err(e) => {
                        tx.send(TuiEvent::Error {
                            scan_type: ScanType::VA1,
                            msg: e.to_string(),
                        })
                        .ok();
                        // Continue to VA2 even if VA1 fails
                        tx.send(TuiEvent::Va1Done(Box::new(
                            create_empty_va1_report(&url),
                        )))
                        .ok();
                    }
                },
                Err(e) => {
                    tx.send(TuiEvent::Log {
                        level: EventLogLevel::Warn,
                        msg: format!("VA1 skipped (no consent?): {}", e),
                    })
                    .ok();
                    // Send empty VA1 to proceed
                    tx.send(TuiEvent::Va1Done(Box::new(
                        create_empty_va1_report(&url),
                    )))
                    .ok();
                }
            }

            // Phase 3: VA2 behavioral profiling
            tx.send(TuiEvent::Log {
                level: EventLogLevel::Info,
                msg: "Running VA2 behavioral profiling...".to_string(),
            })
            .ok();

            let phases = vec![
                crate::virtual_adversary2::Va2Phase::Baseline,
                crate::virtual_adversary2::Va2Phase::ProtocolVariance,
            ];
            let config = Va2CampaignConfig::default();
            match build_va2_campaign_plan(&url, &phases, config) {
                Ok(plan) => match Va2Runner::new() {
                    Ok(runner) => match runner.run_plan(plan).await {
                        Ok(report) => {
                            tx.send(TuiEvent::Va2Done(Box::new(report))).ok();
                        }
                        Err(e) => {
                            tx.send(TuiEvent::Error {
                                scan_type: ScanType::VA2,
                                msg: e.to_string(),
                            })
                            .ok();
                        }
                    },
                    Err(e) => {
                        tx.send(TuiEvent::Error {
                            scan_type: ScanType::VA2,
                            msg: format!("VA2 runner init failed: {}", e),
                        })
                        .ok();
                    }
                },
                Err(e) => {
                    tx.send(TuiEvent::Error {
                        scan_type: ScanType::VA2,
                        msg: format!("VA2 plan failed: {}", e),
                    })
                    .ok();
                }
            }
        });
    }

    fn compute_posture(&mut self) {
        if let Some(url) = &self.state.target_url {
            let mut builder = PostureBuilder::new(url);
            if let Some(det) = &self.state.detection {
                builder = builder.with_detection(det);
            }
            if let Some(va2) = &self.state.va2 {
                builder = builder.with_va2(va2);
            }
            if let Some(va1) = &self.state.va1 {
                builder = builder.with_va1(va1);
            }
            self.state.posture = Some(builder.compute());
        }
    }

    fn extract_findings(&mut self) {
        use super::state::{Finding, FindingSeverity};
        let mut findings = Vec::new();

        // VA2 channel blind spots (Critical)
        if let Some(va2) = &self.state.va2 {
            if let Some(cc) = &va2.channel_coverage {
                for ch in &cc.blind_spots {
                    findings.push(Finding {
                        severity: FindingSeverity::Critical,
                        title: format!("{:?} channel has zero attack detection", ch),
                        source: "Behavioral".to_string(),
                        impact: format!(
                            "WAF does not inspect {:?} — attacks sent via this channel bypass all rules",
                            ch
                        ),
                        recommendation: format!(
                            "Enable {:?} inspection in WAF configuration",
                            ch
                        ),
                    });
                }
            }

            // Challenge score < 0.5 (Medium)
            if va2.wbf.challenge_score < 0.5 {
                findings.push(Finding {
                    severity: FindingSeverity::Medium,
                    title: format!(
                        "No bot challenge capability ({:.0}%)",
                        va2.wbf.challenge_score * 100.0
                    ),
                    source: "Behavioral".to_string(),
                    impact: "WAF never issues CAPTCHA or JS challenges to suspicious requests".to_string(),
                    recommendation: "Enable bot challenge rules (CAPTCHA, JS challenge) for suspicious traffic"
                        .to_string(),
                });
            }

            // Throttle score = 0 (Medium)
            if va2.wbf.throttle_score == 0.0 {
                findings.push(Finding {
                    severity: FindingSeverity::Medium,
                    title: "No rate limiting detected".to_string(),
                    source: "Behavioral".to_string(),
                    impact: "WAF does not slow or block rapid requests — vulnerable to brute-force attacks"
                        .to_string(),
                    recommendation: "Add rate-limiting rules (e.g., 100 requests/min per IP)".to_string(),
                });
            }

            // Statefulness score = 0 (Low)
            if va2.wbf.statefulness_score == 0.0 {
                findings.push(Finding {
                    severity: FindingSeverity::Low,
                    title: "No session tracking detected".to_string(),
                    source: "Behavioral".to_string(),
                    impact: "WAF treats each request independently — multi-step attacks go undetected"
                        .to_string(),
                    recommendation: "Enable session-aware WAF rules or IP reputation tracking".to_string(),
                });
            }
        }

        // Smoke test low effectiveness (Medium)
        if let Some(smoke) = &self.state.smoke {
            if smoke.summary.effectiveness_percentage < 50.0 {
                findings.push(Finding {
                    severity: FindingSeverity::Medium,
                    title: format!(
                        "Low smoke test effectiveness ({:.0}%)",
                        smoke.summary.effectiveness_percentage
                    ),
                    source: "Smoke Test".to_string(),
                    impact: "WAF fails to block majority of common attack payloads".to_string(),
                    recommendation: "Enable OWASP CRS or equivalent managed ruleset".to_string(),
                });
            }
            if smoke.summary.allowed_count > 0 {
                let allowed_pct =
                    smoke.summary.allowed_count as f64 / smoke.summary.total_tests.max(1) as f64;
                if allowed_pct > 0.3 {
                    findings.push(Finding {
                        severity: FindingSeverity::Medium,
                        title: format!(
                            "{} of {} smoke payloads allowed ({:.0}%)",
                            smoke.summary.allowed_count,
                            smoke.summary.total_tests,
                            allowed_pct * 100.0
                        ),
                        source: "Smoke Test".to_string(),
                        impact: "Known attack patterns bypass WAF".to_string(),
                        recommendation: "Review WAF ruleset coverage for XSS, SQLi, path traversal"
                            .to_string(),
                    });
                }
            }
        }

        // VA1 high allowed rate (Medium)
        if let Some(va1) = &self.state.va1 {
            let total = va1.summary.total.max(1) as f64;
            let allowed_rate = va1.summary.allowed as f64 / total;
            if allowed_rate > 0.3 {
                findings.push(Finding {
                    severity: FindingSeverity::Medium,
                    title: format!(
                        "{:.0}% of attack probes allowed through",
                        allowed_rate * 100.0
                    ),
                    source: "Enforcement".to_string(),
                    impact: "Significant portion of known attack patterns bypass WAF".to_string(),
                    recommendation: "Review WAF ruleset for gaps in coverage".to_string(),
                });
            }
        }

        // Detection caveats (Low)
        if let Some(det) = &self.state.detection {
            for caveat in &det.caveats {
                findings.push(Finding {
                    severity: FindingSeverity::Low,
                    title: caveat.clone(),
                    source: "Detection".to_string(),
                    impact: "Detection reliability concern".to_string(),
                    recommendation: "Verify with additional testing methods".to_string(),
                });
            }
        }

        // Sort by severity
        findings.sort_by_key(|f| f.severity);
        self.state.findings = findings;
    }

    pub fn draw(&self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Header
                Constraint::Min(10),   // Main content
                Constraint::Length(1), // Nav bar
            ])
            .split(f.area());

        components::header::render(f, chunks[0], &self.state);

        // Main content area
        let content_area = if self.state.show_tooltip {
            let split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
                .split(chunks[1]);
            components::tooltip::render(f, split[1], self.state.view);
            split[0]
        } else {
            chunks[1]
        };

        if self.state.show_help {
            views::help::render(f, content_area);
        } else {
            match self.state.view {
                ViewState::Dashboard => views::dashboard::render(f, content_area, &self.state),
                ViewState::Detection => views::detection::render(f, content_area, &self.state),
                ViewState::SmokeTest => views::smoke::render(f, content_area, &self.state),
                ViewState::VA1 => views::va1::render(f, content_area, &self.state),
                ViewState::VA2 => views::va2::render(f, content_area, &self.state),
                ViewState::Findings => views::findings::render(f, content_area, &self.state),
                ViewState::Log => views::log::render(f, content_area, &self.state),
            }
        }

        // Progress bar overlay at top of content if scanning
        if self.state.scan.is_running() && self.state.progress.is_some() {
            let progress_area = Rect::new(
                content_area.x,
                content_area.y,
                content_area.width,
                1,
            );
            components::progress::render(f, progress_area, &self.state);
        }

        components::nav_bar::render(f, chunks[2], self.state.view);

        // Status message overlay
        if let Some(msg) = &self.state.status_msg {
            let status_area = Rect::new(
                chunks[2].x,
                chunks[2].y.saturating_sub(1),
                chunks[2].width,
                1,
            );
            let p = ratatui::widgets::Paragraph::new(ratatui::text::Span::styled(
                format!(" {} ", msg),
                ratatui::style::Style::default().fg(super::theme::Theme::ACCENT),
            ));
            f.render_widget(p, status_area);
        }
    }
}

fn create_empty_va1_report(url: &str) -> crate::virtual_adversary::VaRunReport {
    use crate::virtual_adversary::{
        VaEnforcement, VaResultSummary, VaRunReport, VirtualAdversaryConfig,
    };
    VaRunReport {
        target_url: url.to_string(),
        plan_size: 0,
        replay_plan: Vec::new(),
        summary: VaResultSummary::new(),
        enforcement: VaEnforcement::Inconclusive,
        evidence_score: 0.0,
        evidence_summary: Vec::new(),
        config: VirtualAdversaryConfig {
            tier: 1,
            request_budget: 0,
            request_timeout: std::time::Duration::from_secs(15),
            request_delay: std::time::Duration::from_millis(500),
            max_variants_per_payload: 3,
            skip_dns_validation: false,
        },
        results: Vec::new(),
        started_at: std::time::Instant::now(),
        finished_at: None,
        replay_bundle: None,
    }
}
