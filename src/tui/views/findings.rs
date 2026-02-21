use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

use crate::tui::state::AppState;
use crate::tui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .title(" Actionable Findings ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::BORDER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if state.findings.is_empty() {
        let text = if state.scan.is_running() {
            "  Scan in progress..."
        } else if state.detection.is_none() {
            "  No scan data. Press [r] to scan."
        } else {
            "  No findings detected. WAF configuration looks solid."
        };
        let p = Paragraph::new(Span::styled(text, Theme::dim()));
        f.render_widget(p, inner);
        return;
    }

    let items: Vec<ListItem> = state
        .findings
        .iter()
        .enumerate()
        .flat_map(|(i, finding)| {
            let is_selected = i == state.selected;
            let sev_color = Theme::severity_color(&finding.severity);
            let base_style = if is_selected {
                Theme::selected()
            } else {
                Style::default()
            };

            let mut lines = vec![ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {:>8} ", finding.severity),
                    Style::default()
                        .fg(sev_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(&finding.title, base_style.fg(Theme::FG)),
                Span::styled(
                    format!("  [{}]", finding.source),
                    Theme::dim(),
                ),
            ]))];

            if is_selected && state.expanded {
                lines.push(ListItem::new(Line::from(Span::styled(
                    format!("           Impact: {}", finding.impact),
                    Style::default().fg(Theme::MEDIUM),
                ))));
                lines.push(ListItem::new(Line::from(Span::styled(
                    format!("           Fix: {}", finding.recommendation),
                    Style::default().fg(Theme::OK),
                ))));
            }

            lines
        })
        .collect();

    let list = List::new(items);
    f.render_widget(list, inner);
}
