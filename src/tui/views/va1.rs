use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;
use std::collections::HashMap;

use crate::tui::state::AppState;
use crate::tui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .title(" Enforcement Test ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::BORDER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let va1 = match &state.va1 {
        Some(v) => v,
        None => {
            let p = Paragraph::new(Span::styled(
                "  No enforcement data. Press [r] to scan.",
                Theme::dim(),
            ));
            f.render_widget(p, inner);
            return;
        }
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(4)])
        .split(inner);

    // Summary bar
    let summary = &va1.summary;
    let total = summary.total.max(1) as f64;
    let summary_line = Line::from(vec![
        Span::styled(
            format!(" Blocked: {} ", summary.blocked),
            Style::default()
                .fg(Theme::OK)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" Challenge: {} ", summary.challenge),
            Style::default()
                .fg(Theme::MEDIUM)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" Allowed: {} ", summary.allowed),
            Style::default()
                .fg(Theme::CRITICAL)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" Error: {} ", summary.error),
            Theme::dim(),
        ),
        Span::styled(
            format!(
                " | Enforcement: {:?} | Block Rate: {:.0}%",
                va1.enforcement,
                (summary.blocked as f64 / total) * 100.0
            ),
            Style::default().fg(Theme::FG),
        ),
    ]);
    let summary_p = Paragraph::new(summary_line);
    f.render_widget(summary_p, chunks[0]);

    // Results grouped by category
    let mut by_category: HashMap<String, Vec<_>> = HashMap::new();
    for result in &va1.results {
        let cat = format!("{:?}", result.category);
        by_category.entry(cat).or_default().push(result);
    }

    let mut items: Vec<ListItem> = Vec::new();
    let mut sorted_cats: Vec<_> = by_category.keys().cloned().collect();
    sorted_cats.sort();

    let mut item_idx = 0;
    for cat in &sorted_cats {
        let results = &by_category[cat];
        let allowed = results
            .iter()
            .filter(|r| format!("{:?}", r.outcome) == "Allowed")
            .count();
        let cat_color = if allowed > results.len() / 3 {
            Theme::CRITICAL
        } else if allowed > 0 {
            Theme::MEDIUM
        } else {
            Theme::OK
        };

        items.push(ListItem::new(Line::from(vec![
            Span::styled(
                format!(" {} ", cat),
                Style::default()
                    .fg(cat_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("({} probes, {} allowed)", results.len(), allowed),
                Theme::dim(),
            ),
        ])));

        for result in results {
            let is_selected = item_idx == state.selected;
            let base_style = if is_selected {
                Theme::selected()
            } else {
                Style::default()
            };

            let outcome_str = format!("{:?}", result.outcome);
            let outcome_color = match outcome_str.as_str() {
                "Blocked" => Theme::OK,
                "Challenge" => Theme::MEDIUM,
                "Allowed" => Theme::CRITICAL,
                _ => Theme::DIM,
            };

            let payload_short = if result.payload.len() > 60 {
                format!("{}...", &result.payload[..57])
            } else {
                result.payload.clone()
            };

            items.push(ListItem::new(Line::from(vec![
                Span::styled("  ", base_style),
                Span::styled(
                    format!("{:>10} ", outcome_str),
                    Style::default().fg(outcome_color),
                ),
                Span::styled(payload_short, base_style.fg(Theme::FG)),
            ])));

            if is_selected && state.expanded {
                items.push(ListItem::new(Line::from(Span::styled(
                    format!("             Reason: {}", result.reason),
                    Theme::dim(),
                ))));
            }
            item_idx += 1;
        }
    }

    let list = List::new(items);
    f.render_widget(list, chunks[1]);
}
