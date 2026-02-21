use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::tui::state::{AppState, ScanState};
use crate::tui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let target = state
        .target_url
        .as_deref()
        .unwrap_or("No target");

    let status_style = if state.scan.is_running() {
        Style::default()
            .fg(Theme::RUNNING)
            .add_modifier(Modifier::BOLD)
    } else if state.scan == ScanState::Complete {
        Style::default()
            .fg(Theme::OK)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Theme::IDLE)
    };

    let progress_text = if let Some((current, total)) = state.progress {
        format!(" [{}/{}]", current, total)
    } else {
        String::new()
    };

    let line = Line::from(vec![
        Span::styled(
            " WAF Detector ",
            Style::default()
                .fg(Theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} ", target),
            Style::default().fg(Theme::FG),
        ),
        Span::styled(
            format!(" {} ", state.scan.label()),
            status_style,
        ),
        Span::styled(progress_text, status_style),
    ]);

    let paragraph = Paragraph::new(line).style(Theme::base());
    f.render_widget(paragraph, area);
}
