pub mod app;
pub mod components;
pub mod events;
pub mod export;
pub mod keybindings;
pub mod state;
pub mod theme;
pub mod views;

use anyhow::Result;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::engine::DetectionEngine;

pub struct TuiApp;

impl TuiApp {
    /// Launch the interactive TUI with a target URL for scanning.
    pub async fn run(engine: DetectionEngine, url: Option<String>) -> Result<()> {
        let mut app = if url.is_none() {
            // Review mode: load last saved report
            match export::load_last_report() {
                Ok(report) => {
                    let mut a = app::TuiApp::new(Some(engine), Some(report.target_url));
                    a.state.detection = report.detection;
                    a.state.smoke = report.smoke;
                    a.state.va1 = report.va1;
                    a.state.va2 = report.va2;
                    a.state.posture = report.posture;
                    a.state.findings = report.findings;
                    a.state.scan = state::ScanState::Complete;
                    a.state.review_mode = true;
                    a.state.push_log(
                        state::LogLevel::Info,
                        "Loaded last saved report (review mode)".to_string(),
                    );
                    a
                }
                Err(e) => {
                    eprintln!("No saved report found: {}", e);
                    eprintln!("Run a scan first: waf-detect --tui <url>");
                    return Ok(());
                }
            }
        } else {
            app::TuiApp::new(Some(engine), url)
        };

        // Terminal setup
        enable_raw_mode()?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;

        // Main loop
        let result = run_main_loop(&mut terminal, &mut app).await;

        // Terminal teardown
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        result
    }
}

async fn run_main_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut app::TuiApp,
) -> Result<()> {
    loop {
        terminal.draw(|f| app.draw(f))?;

        // Process events
        if crossterm::event::poll(std::time::Duration::from_millis(50))? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                app.event_tx
                    .send(events::TuiEvent::Key(key))
                    .ok();
            }
        }

        // Drain pending events from scan tasks
        while let Ok(evt) = app.event_rx.try_recv() {
            app.handle_event(evt).await?;
        }

        if app.state.quit {
            break;
        }
    }
    Ok(())
}
