use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::{Block, Gauge};
use ratatui::Frame;

use crate::tui::state::AppState;
use crate::tui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    if let Some((current, total)) = state.progress {
        let ratio = if total > 0 {
            current as f64 / total as f64
        } else {
            0.0
        };
        let label = format!("{}/{}", current, total);
        let gauge = Gauge::default()
            .block(Block::default())
            .gauge_style(Style::default().fg(Theme::ACCENT).bg(Theme::BORDER))
            .ratio(ratio.min(1.0))
            .label(label);
        f.render_widget(gauge, area);
    }
}
