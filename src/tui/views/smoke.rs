use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

use crate::tui::components::signal_bar;
use crate::tui::state::AppState;
use crate::tui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .title(" WAF Smoke Testing ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::BORDER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let smoke = match &state.smoke {
        Some(s) => s,
        None => {
            let p = Paragraph::new(Span::styled(
                "  No smoke test data. Press [r] to scan.",
                Theme::dim(),
            ));
            f.render_widget(p, inner);
            return;
        }
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Summary bar
            Constraint::Length(2), // Effectiveness gauge
            Constraint::Min(6),   // Per-payload results
        ])
        .split(inner);

    // Summary bar
    let summary = &smoke.summary;
    let summary_lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" Blocked: {} ", summary.blocked_count),
                Style::default()
                    .fg(Theme::OK)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" Challenge: {} ", summary.challenge_count),
                Style::default()
                    .fg(Theme::MEDIUM)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" Allowed: {} ", summary.allowed_count),
                Style::default()
                    .fg(Theme::CRITICAL)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" Rate Limited: {} ", summary.rate_limited_count),
                Style::default().fg(Theme::LOW),
            ),
            Span::styled(
                format!(" Error: {} ", summary.error_count),
                Theme::dim(),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!(
                    " Total: {} | Avg Response: {:.0}ms | Time: {}ms",
                    summary.total_tests,
                    summary.average_response_time_ms,
                    smoke.total_time_ms,
                ),
                Style::default().fg(Theme::FG),
            ),
            if let Some(mode) = &smoke.waf_mode {
                Span::styled(
                    format!(" | WAF Mode: {:?}", mode),
                    Style::default()
                        .fg(Theme::ACCENT)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::raw("")
            },
        ]),
    ];
    let summary_p = Paragraph::new(summary_lines);
    f.render_widget(summary_p, chunks[0]);

    // Effectiveness gauge
    signal_bar::render(
        f,
        chunks[1],
        "Effectiveness",
        summary.effectiveness_percentage / 100.0,
    );

    // Per-payload results
    let mut items: Vec<ListItem> = Vec::new();
    let mut item_idx = 0;

    // Group by category
    let mut by_category: std::collections::HashMap<String, Vec<_>> =
        std::collections::HashMap::new();
    for result in &smoke.test_results {
        by_category
            .entry(result.category.clone())
            .or_default()
            .push(result);
    }

    let mut sorted_cats: Vec<_> = by_category.keys().cloned().collect();
    sorted_cats.sort();

    for cat in &sorted_cats {
        let results = &by_category[cat];
        let blocked = results
            .iter()
            .filter(|r| format!("{:?}", r.classification) == "Blocked")
            .count();
        let cat_color = if blocked == results.len() {
            Theme::OK
        } else if blocked > results.len() / 2 {
            Theme::MEDIUM
        } else {
            Theme::CRITICAL
        };

        items.push(ListItem::new(Line::from(vec![
            Span::styled(
                format!(" {} ", cat),
                Style::default()
                    .fg(cat_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("({}/{} blocked)", blocked, results.len()),
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

            let class_str = format!("{:?}", result.classification);
            let class_color = match class_str.as_str() {
                "Blocked" => Theme::OK,
                "Challenged" => Theme::MEDIUM,
                "Allowed" => Theme::CRITICAL,
                "RateLimited" => Theme::LOW,
                _ => Theme::DIM,
            };

            let payload_short = if result.payload.len() > 50 {
                format!("{}...", &result.payload[..47])
            } else {
                result.payload.clone()
            };

            items.push(ListItem::new(Line::from(vec![
                Span::styled("  ", base_style),
                Span::styled(
                    format!("{:>12} ", class_str),
                    Style::default().fg(class_color),
                ),
                Span::styled(
                    format!("{:>3} ", result.response_status),
                    Theme::dim(),
                ),
                Span::styled(payload_short, base_style.fg(Theme::FG)),
            ])));

            if is_selected && state.expanded {
                for indicator in &result.waf_indicators {
                    items.push(ListItem::new(Line::from(Span::styled(
                        format!("                WAF: {}", indicator),
                        Theme::dim(),
                    ))));
                }
                for ev in &result.evidence {
                    items.push(ListItem::new(Line::from(Span::styled(
                        format!("                Evidence: {}", ev),
                        Theme::dim(),
                    ))));
                }
            }
            item_idx += 1;
        }
    }

    // Recommendations
    if !smoke.recommendations.is_empty() {
        items.push(ListItem::new(Line::from("")));
        items.push(ListItem::new(Line::from(Span::styled(
            " Recommendations:",
            Style::default()
                .fg(Theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ))));
        for rec in &smoke.recommendations {
            items.push(ListItem::new(Line::from(Span::styled(
                format!("  - {}", rec),
                Style::default().fg(Theme::FG),
            ))));
        }
    }

    let list = List::new(items);
    f.render_widget(list, chunks[2]);
}
