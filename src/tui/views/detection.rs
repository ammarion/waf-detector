use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;

use crate::tui::state::AppState;
use crate::tui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .title(" Detection Evidence ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::BORDER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let detection = match &state.detection {
        Some(d) => d,
        None => {
            let p = Paragraph::new(Span::styled(
                "  No detection data. Press [r] to scan.",
                Theme::dim(),
            ));
            f.render_widget(p, inner);
            return;
        }
    };

    let mut items: Vec<ListItem> = Vec::new();
    let mut item_idx = 0;

    for (provider, evidence_list) in &detection.evidence_map {
        if evidence_list.is_empty() {
            continue;
        }

        // Provider header
        let header = ListItem::new(Line::from(vec![
            Span::styled(
                format!(" {} ", provider),
                Style::default()
                    .fg(Theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("({} evidence)", evidence_list.len()),
                Theme::dim(),
            ),
        ]));
        items.push(header);

        for evidence in evidence_list {
            let is_selected = item_idx == state.selected;
            let style = if is_selected {
                Theme::selected()
            } else {
                Style::default()
            };

            let conf_color = Theme::bar_color(evidence.confidence);
            let line = Line::from(vec![
                Span::styled("  ", style),
                Span::styled(
                    format!("{:>5.0}% ", evidence.confidence * 100.0),
                    Style::default().fg(conf_color),
                ),
                Span::styled(&evidence.description, style.fg(Theme::FG)),
            ]);
            items.push(ListItem::new(line));

            // Show expanded detail if selected and expanded
            if is_selected && state.expanded {
                let detail_lines = vec![
                    ListItem::new(Line::from(Span::styled(
                        format!("       Method: {:?}", evidence.method_type),
                        Theme::dim(),
                    ))),
                    ListItem::new(Line::from(Span::styled(
                        format!("       Data: {}", evidence.raw_data),
                        Theme::dim(),
                    ))),
                    ListItem::new(Line::from(Span::styled(
                        format!("       Signature: {}", evidence.signature_matched),
                        Theme::dim(),
                    ))),
                ];
                items.extend(detail_lines);
            }
            item_idx += 1;
        }
    }

    // Caveats
    if !detection.caveats.is_empty() {
        items.push(ListItem::new(Line::from("")));
        items.push(ListItem::new(Line::from(Span::styled(
            " Caveats:",
            Style::default()
                .fg(Theme::MEDIUM)
                .add_modifier(Modifier::BOLD),
        ))));
        for caveat in &detection.caveats {
            items.push(ListItem::new(Line::from(Span::styled(
                format!("  - {}", caveat),
                Style::default().fg(Theme::MEDIUM),
            ))));
        }
    }

    let list = List::new(items);
    f.render_widget(list, inner);
}
