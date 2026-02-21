use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use ratatui::Frame;

use crate::tui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect) {
    let bindings = vec![
        ("1-7", "Switch view (Dashboard, Detection, Smoke, VA1, VA2, Findings, Log)"),
        ("Tab", "Next view"),
        ("j/k or Up/Down", "Navigate items"),
        ("Enter", "Expand selected item"),
        ("Esc", "Collapse / back"),
        ("r", "Run full scan (detection + VA1 + VA2 + posture)"),
        ("e", "Export report to JSON file"),
        ("a", "Auto-save for Claude analysis"),
        ("?", "Toggle educational tooltip"),
        ("h", "Toggle this help overlay"),
        ("q / Ctrl+C", "Quit"),
    ];

    let rows: Vec<Row> = bindings
        .iter()
        .map(|(key, desc)| {
            Row::new(vec![
                Cell::from(*key).style(
                    Style::default()
                        .fg(Theme::ACCENT)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(*desc).style(Style::default().fg(Theme::FG)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [Constraint::Length(18), Constraint::Min(50)],
    )
    .block(
        Block::default()
            .title(" Keyboard Shortcuts ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::ACCENT)),
    );

    f.render_widget(table, area);
}
