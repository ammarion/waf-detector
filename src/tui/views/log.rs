use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

use crate::tui::state::{AppState, LogLevel};
use crate::tui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .title(" Event Log ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::BORDER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if state.log.is_empty() {
        let p = Paragraph::new(Span::styled(
            "  No log entries yet.",
            Theme::dim(),
        ));
        f.render_widget(p, inner);
        return;
    }

    let max_visible = inner.height as usize;
    let start = state.log.len().saturating_sub(max_visible);

    let items: Vec<ListItem> = state.log[start..]
        .iter()
        .map(|entry| {
            let level_color = match entry.level {
                LogLevel::Info => Theme::LOG_INFO,
                LogLevel::Warn => Theme::LOG_WARN,
                LogLevel::Error => Theme::LOG_ERROR,
            };
            let level_str = match entry.level {
                LogLevel::Info => "INFO ",
                LogLevel::Warn => "WARN ",
                LogLevel::Error => "ERROR",
            };
            let ts = entry.timestamp.format("%H:%M:%S");
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {} ", ts),
                    Theme::dim(),
                ),
                Span::styled(
                    format!("{} ", level_str),
                    Style::default().fg(level_color),
                ),
                Span::styled(&entry.msg, Style::default().fg(Theme::FG)),
            ]))
        })
        .collect();

    let list = List::new(items);
    f.render_widget(list, inner);
}
