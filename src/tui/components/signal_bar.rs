use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::{Block, Borders, Gauge};
use ratatui::Frame;

use crate::tui::theme::Theme;

/// Render a horizontal bar chart for a 0.0-1.0 score.
pub fn render(f: &mut Frame, area: Rect, label: &str, value: f64) {
    let color = Theme::bar_color(value);
    let display = format!("{}: {:.0}%", label, value * 100.0);
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::NONE))
        .gauge_style(Style::default().fg(color).bg(Theme::BORDER))
        .ratio(value.clamp(0.0, 1.0))
        .label(display);
    f.render_widget(gauge, area);
}
