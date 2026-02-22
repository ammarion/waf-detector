use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::components::signal_bar;
use crate::tui::state::AppState;
use crate::tui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .title(" VA2 Behavioral Profiling ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::BORDER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let va2 = match &state.va2 {
        Some(v) => v,
        None => {
            let p = Paragraph::new(Span::styled(
                "  No VA2 data. Press [r] to scan.",
                Theme::dim(),
            ));
            f.render_widget(p, inner);
            return;
        }
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // WBF signal bars
            Constraint::Min(6),   // Channel coverage table
            Constraint::Length(3), // Paired control summary
        ])
        .split(inner);

    // WBF Signal Bars
    {
        let bar_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(chunks[0]);

        signal_bar::render(f, bar_rows[0], "Normalize  ", va2.wbf.normalization_score);
        signal_bar::render(f, bar_rows[1], "Statefulness", va2.wbf.statefulness_score);
        signal_bar::render(f, bar_rows[2], "Challenge  ", va2.wbf.challenge_score);
        signal_bar::render(f, bar_rows[3], "Throttle   ", va2.wbf.throttle_score);
    }

    // Channel Coverage Table
    if let Some(cc) = &va2.channel_coverage {
        let header = Row::new(vec![
            Cell::from("Channel").style(Style::default().fg(Theme::ACCENT).add_modifier(Modifier::BOLD)),
            Cell::from("Discrimination").style(Style::default().fg(Theme::ACCENT).add_modifier(Modifier::BOLD)),
            Cell::from("Status").style(Style::default().fg(Theme::ACCENT).add_modifier(Modifier::BOLD)),
        ]);

        let mut channels: Vec<_> = cc.channels.iter().collect();
        channels.sort_by_key(|(ch, _)| format!("{ch:?}"));

        let rows: Vec<Row> = channels
            .iter()
            .map(|(ch, rate)| {
                let is_blind = cc.blind_spots.contains(ch);
                let status_text = if is_blind { "BLIND SPOT" } else { "OK" };
                let status_color = if is_blind { Theme::CRITICAL } else { Theme::OK };
                let rate_color = Theme::bar_color(**rate);

                Row::new(vec![
                    Cell::from(format!("{:?}", ch)).style(Style::default().fg(Theme::FG)),
                    Cell::from(format!("{:.0}%", *rate * 100.0)).style(Style::default().fg(rate_color)),
                    Cell::from(status_text).style(Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
                ])
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(12),
                Constraint::Length(16),
                Constraint::Length(12),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(" Channel Coverage ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::BORDER)),
        );

        f.render_widget(table, chunks[1]);
    } else {
        let p = Paragraph::new(Span::styled(
            "  No channel coverage data",
            Theme::dim(),
        ));
        f.render_widget(p, chunks[1]);
    }

    // Paired Control Summary
    if let Some(pc) = &va2.paired_control {
        let line = Line::from(vec![
            Span::styled(
                " Paired Controls: ",
                Style::default()
                    .fg(Theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(
                    "Detected: {} | Not Detected: {} | Inconclusive: {} | Pairs: {}/{}",
                    pc.detected_pairs, pc.not_detected_pairs, pc.inconclusive_pairs,
                    pc.executed_pairs, pc.pair_cap
                ),
                Style::default().fg(Theme::FG),
            ),
        ]);
        let p = Paragraph::new(line);
        f.render_widget(p, chunks[2]);
    }
}
