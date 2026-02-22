use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::tui::components::{badge, signal_bar};
use crate::tui::state::AppState;
use crate::tui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Top: grade + WAF + risk
            Constraint::Length(6),  // Middle: protection score + signal bars
            Constraint::Min(4),    // Bottom: top findings
        ])
        .split(area);

    render_top(f, chunks[0], state);
    render_middle(f, chunks[1], state);
    render_bottom(f, chunks[2], state);
}

fn render_top(f: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .title(" Posture Overview ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::BORDER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(12),
            Constraint::Min(30),
            Constraint::Length(25),
        ])
        .split(inner);

    // Grade badge
    if let Some(posture) = &state.posture {
        let grade_str = format!("{}", posture.grade);
        badge::render_grade(f, cols[0], &grade_str);
    } else {
        let p = Paragraph::new(Span::styled(" -- ", Theme::dim()));
        f.render_widget(p, cols[0]);
    }

    // WAF info
    let waf_lines = if let Some(det) = &state.detection {
        let waf_text = if let Some(waf) = &det.detected_waf {
            format!("WAF: {} ({:.0}%)", waf.name, waf.confidence * 100.0)
        } else {
            "WAF: Not detected".to_string()
        };
        let cdn_text = if let Some(cdn) = &det.detected_cdn {
            format!("CDN: {} ({:.0}%)", cdn.name, cdn.confidence * 100.0)
        } else {
            "CDN: Not detected".to_string()
        };
        vec![
            Line::from(Span::styled(waf_text, Theme::bold())),
            Line::from(Span::styled(cdn_text, Style::default().fg(Theme::FG))),
        ]
    } else {
        vec![Line::from(Span::styled(
            "Awaiting scan...",
            Theme::dim(),
        ))]
    };
    let waf_paragraph = Paragraph::new(waf_lines);
    f.render_widget(waf_paragraph, cols[1]);

    // Risk score
    if let Some(posture) = &state.posture {
        let risk_color = if posture.risk_score >= 70.0 {
            Theme::CRITICAL
        } else if posture.risk_score >= 40.0 {
            Theme::MEDIUM
        } else {
            Theme::OK
        };
        let risk_text = format!("Risk: {:.0}/100", posture.risk_score);
        let p = Paragraph::new(Span::styled(
            risk_text,
            Style::default()
                .fg(risk_color)
                .add_modifier(Modifier::BOLD),
        ));
        f.render_widget(p, cols[2]);
    }
}

fn render_middle(f: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .title(" Behavioral Profile ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::BORDER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if let Some(va2) = &state.va2 {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(25), Constraint::Min(20)])
            .split(inner);

        // Protection score badge
        badge::render_pmi(f, cols[0], va2.pmi.score, &va2.pmi.label);

        // Protection signal bars
        let bar_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(cols[1]);

        signal_bar::render(f, bar_rows[0], "Encoding Defense", va2.wbf.normalization_score);
        signal_bar::render(f, bar_rows[1], "Session Tracking", va2.wbf.statefulness_score);
        signal_bar::render(f, bar_rows[2], "Bot Challenge   ", va2.wbf.challenge_score);
        signal_bar::render(f, bar_rows[3], "Rate Limiting   ", va2.wbf.throttle_score);
    } else {
        let p = Paragraph::new(Span::styled(
            "  No behavioral data. Press [r] to scan.",
            Theme::dim(),
        ));
        f.render_widget(p, inner);
    }
}

fn render_bottom(f: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .title(" Top Findings ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::BORDER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if state.findings.is_empty() {
        let text = if state.scan == crate::tui::state::ScanState::Idle {
            "  Press [r] to run a full scan."
        } else if state.scan.is_running() {
            "  Scan in progress..."
        } else {
            "  No findings detected."
        };
        let p = Paragraph::new(Span::styled(text, Theme::dim()));
        f.render_widget(p, inner);
        return;
    }

    let lines: Vec<Line> = state
        .findings
        .iter()
        .take(5)
        .map(|finding| {
            let sev_color = Theme::severity_color(&finding.severity);
            Line::from(vec![
                Span::styled(
                    format!(" {:>8} ", finding.severity),
                    Style::default()
                        .fg(sev_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(&finding.title, Style::default().fg(Theme::FG)),
                Span::styled(
                    format!("  [{}]", finding.source),
                    Theme::dim(),
                ),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true });
    f.render_widget(paragraph, inner);
}
