use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::tui::state::ViewState;
use crate::tui::theme::Theme;

pub fn render(f: &mut Frame, area: Rect, view: ViewState) {
    let text = tooltip_text(view);
    let block = Block::default()
        .title(" Info ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::ACCENT));
    let paragraph = Paragraph::new(text)
        .block(block)
        .style(Style::default().fg(Theme::FG))
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

fn tooltip_text(view: ViewState) -> &'static str {
    match view {
        ViewState::Dashboard => {
            "Dashboard shows the overall posture grade (A-F), risk score, detected WAF, \
             protection score, and top findings. Grade is computed from detection confidence, \
             behavioral analysis, and enforcement test results."
        }
        ViewState::Detection => {
            "Detection view shows evidence collected from HTTP headers, response bodies, \
             DNS records, timing analysis, and TLS certificates. Each provider's evidence is \
             grouped with confidence scores. Expand items with Enter for raw data."
        }
        ViewState::SmokeTest => {
            "Smoke testing sends known attack payloads (XSS, SQLi, path traversal, command \
             injection, etc.) and measures how the WAF responds. Results are grouped by attack \
             category. Effectiveness % = blocked / total. High effectiveness means the WAF \
             catches common attacks. Low effectiveness suggests gaps in the ruleset."
        }
        ViewState::VA1 => {
            "Enforcement test sends known attack payloads (SQLi, XSS, path traversal, etc.) \
             and checks whether the WAF blocks, challenges, or allows each one. High allowed \
             rates mean the WAF is not stopping attacks it should catch."
        }
        ViewState::VA2 => {
            "Behavioral analysis sends paired probes — one benign, one malicious — across \
             5 channels (Path, Query, Header, Body, Method) to test how smart the WAF is. \
             It measures encoding defense, session tracking, bot challenges, and rate limiting. \
             Channels with 0% attack detection are unprotected."
        }
        ViewState::Findings => {
            "Findings are actionable items extracted from scan results, sorted by severity. \
             Critical findings include unprotected channels. Medium findings include high attack \
             pass rates and missing bot challenges. Each finding includes impact and recommendation."
        }
        ViewState::Log => {
            "Event log shows real-time scan activity. Entries are color-coded: \
             white=info, yellow=warn, red=error. Auto-scrolls during active scans."
        }
    }
}
