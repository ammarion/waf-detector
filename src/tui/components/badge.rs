use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::tui::theme::Theme;

pub fn render_grade(f: &mut Frame, area: Rect, grade: &str) {
    let color = Theme::grade_color(grade);
    let text = format!(" {} ", grade);
    let paragraph = Paragraph::new(Span::styled(
        text,
        Style::default()
            .fg(color)
            .add_modifier(Modifier::BOLD),
    ));
    f.render_widget(paragraph, area);
}

pub fn render_pmi(f: &mut Frame, area: Rect, score: f64, label: &str) {
    let color = Theme::bar_color(score / 100.0);
    let text = format!("PMI: {:.0} ({})", score, label);
    let paragraph = Paragraph::new(Span::styled(
        text,
        Style::default()
            .fg(color)
            .add_modifier(Modifier::BOLD),
    ));
    f.render_widget(paragraph, area);
}
