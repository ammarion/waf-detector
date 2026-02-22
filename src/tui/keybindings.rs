use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::state::ViewState;

pub enum Action {
    Quit,
    SwitchView(ViewState),
    NextView,
    NavigateUp,
    NavigateDown,
    Expand,
    Collapse,
    RunScan,
    Export,
    AgentPrep,
    ToggleHelp,
    ToggleTooltip,
    None,
}

pub fn map_key(key: KeyEvent) -> Action {
    // Ctrl+C always quits
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Action::Quit;
    }

    match key.code {
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Char('1') => Action::SwitchView(ViewState::Dashboard),
        KeyCode::Char('2') => Action::SwitchView(ViewState::Detection),
        KeyCode::Char('3') => Action::SwitchView(ViewState::SmokeTest),
        KeyCode::Char('4') => Action::SwitchView(ViewState::VA1),
        KeyCode::Char('5') => Action::SwitchView(ViewState::VA2),
        KeyCode::Char('6') => Action::SwitchView(ViewState::Findings),
        KeyCode::Char('7') => Action::SwitchView(ViewState::Log),
        KeyCode::Tab => Action::NextView,
        KeyCode::Char('j') | KeyCode::Down => Action::NavigateDown,
        KeyCode::Char('k') | KeyCode::Up => Action::NavigateUp,
        KeyCode::Enter => Action::Expand,
        KeyCode::Esc => Action::Collapse,
        KeyCode::Char('r') => Action::RunScan,
        KeyCode::Char('e') => Action::Export,
        KeyCode::Char('a') => Action::AgentPrep,
        KeyCode::Char('?') => Action::ToggleTooltip,
        KeyCode::Char('h') => Action::ToggleHelp,
        _ => Action::None,
    }
}
