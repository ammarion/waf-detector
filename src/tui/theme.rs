use ratatui::style::{Color, Modifier, Style};

/// Dark, security-tool aesthetic color palette.
pub struct Theme;

impl Theme {
    // Base colors
    pub const BG: Color = Color::Rgb(18, 18, 24);
    pub const FG: Color = Color::Rgb(200, 200, 210);
    pub const DIM: Color = Color::Rgb(100, 100, 120);
    pub const BORDER: Color = Color::Rgb(60, 60, 80);

    // Accent colors
    pub const ACCENT: Color = Color::Rgb(100, 149, 237); // Cornflower blue
    pub const ACCENT_DIM: Color = Color::Rgb(60, 90, 150);

    // Severity colors
    pub const CRITICAL: Color = Color::Rgb(255, 80, 80);
    pub const MEDIUM: Color = Color::Rgb(255, 180, 50);
    pub const LOW: Color = Color::Rgb(100, 200, 255);
    pub const OK: Color = Color::Rgb(80, 220, 120);

    // Grade colors
    pub const GRADE_A: Color = Color::Rgb(80, 220, 120);
    pub const GRADE_B: Color = Color::Rgb(140, 220, 80);
    pub const GRADE_C: Color = Color::Rgb(255, 220, 50);
    pub const GRADE_D: Color = Color::Rgb(255, 150, 50);
    pub const GRADE_F: Color = Color::Rgb(255, 80, 80);

    // Signal bar colors
    pub const BAR_HIGH: Color = Color::Rgb(80, 220, 120);
    pub const BAR_MED: Color = Color::Rgb(255, 220, 50);
    pub const BAR_LOW: Color = Color::Rgb(255, 80, 80);

    // Log colors
    pub const LOG_INFO: Color = Color::Rgb(200, 200, 210);
    pub const LOG_WARN: Color = Color::Rgb(255, 180, 50);
    pub const LOG_ERROR: Color = Color::Rgb(255, 80, 80);

    // Scan state
    pub const RUNNING: Color = Color::Rgb(100, 200, 255);
    pub const IDLE: Color = Color::Rgb(100, 100, 120);

    pub fn base() -> Style {
        Style::default().fg(Self::FG).bg(Self::BG)
    }

    pub fn header() -> Style {
        Style::default()
            .fg(Self::ACCENT)
            .bg(Self::BG)
            .add_modifier(Modifier::BOLD)
    }

    pub fn nav_active() -> Style {
        Style::default()
            .fg(Color::White)
            .bg(Self::ACCENT_DIM)
            .add_modifier(Modifier::BOLD)
    }

    pub fn nav_inactive() -> Style {
        Style::default().fg(Self::DIM).bg(Self::BG)
    }

    pub fn selected() -> Style {
        Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(40, 40, 60))
    }

    pub fn dim() -> Style {
        Style::default().fg(Self::DIM)
    }

    pub fn bold() -> Style {
        Style::default()
            .fg(Self::FG)
            .add_modifier(Modifier::BOLD)
    }

    pub fn bar_color(value: f64) -> Color {
        if value >= 0.7 {
            Self::BAR_HIGH
        } else if value >= 0.4 {
            Self::BAR_MED
        } else {
            Self::BAR_LOW
        }
    }

    pub fn grade_color(grade: &str) -> Color {
        match grade {
            "A" => Self::GRADE_A,
            "B" => Self::GRADE_B,
            "C" => Self::GRADE_C,
            "D" => Self::GRADE_D,
            _ => Self::GRADE_F,
        }
    }

    pub fn severity_color(severity: &super::state::FindingSeverity) -> Color {
        match severity {
            super::state::FindingSeverity::Critical => Self::CRITICAL,
            super::state::FindingSeverity::Medium => Self::MEDIUM,
            super::state::FindingSeverity::Low => Self::LOW,
        }
    }
}
