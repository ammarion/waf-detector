use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::tui::state::ViewState;
use crate::tui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, current: ViewState) {
    let spans: Vec<Span> = ViewState::ALL
        .iter()
        .enumerate()
        .flat_map(|(i, v)| {
            let style = if *v == current {
                Theme::nav_active()
            } else {
                Theme::nav_inactive()
            };
            let sep = if i < ViewState::ALL.len() - 1 {
                vec![Span::styled(
                    format!(" [{}]{} ", i + 1, v.label()),
                    style,
                ), Span::raw(" ")]
            } else {
                vec![Span::styled(
                    format!(" [{}]{} ", i + 1, v.label()),
                    style,
                )]
            };
            sep
        })
        .collect();

    let help_span = Span::styled(" [?]Help [q]Quit ", Theme::dim());
    let mut all_spans = spans;
    all_spans.push(help_span);

    let line = Line::from(all_spans);
    let paragraph = Paragraph::new(line).style(Theme::base());
    f.render_widget(paragraph, area);
}
