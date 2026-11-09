#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    FocusOmnibox,
    Submit,
    Palette,
    Rerun,
    Jump(usize),
    PrevSection,
    NextSection,
    NewTab,
    CloseTab,
    NextTab,
    PrevTab,
    NextRecord,
    PrevRecord,
    Cheatsheet,
    Dismiss,
    MoveUp,
    MoveDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Omnibox,
    Browse,
    Palette,
    Sheet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum When {
    Always,
    InOmnibox,
    NotTyping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Press<'a> {
    pub key: &'a str,
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
}

struct Binding {
    key: &'static str,
    ctrl: bool,
    alt: bool,
    shift: bool,
    when: When,
    action: Action,
    label: &'static str,
}

const fn bind(key: &'static str, ctrl: bool, alt: bool, shift: bool, when: When, action: Action, label: &'static str) -> Binding {
    Binding { key, ctrl, alt, shift, when, action, label }
}

const BINDINGS: &[Binding] = &[
    bind("l", true, false, false, When::Always, Action::FocusOmnibox, "Focus the omnibox"),
    bind("enter", false, false, false, When::InOmnibox, Action::Submit, "Run the Diagnosis"),
    bind("k", true, false, false, When::Always, Action::Palette, "Command palette"),
    bind("r", true, false, false, When::Always, Action::Rerun, "Re-run this section's Check"),
    bind("1", true, false, false, When::Always, Action::Jump(0), "Go to Summary"),
    bind("2", true, false, false, When::Always, Action::Jump(1), "Go to DNS"),
    bind("3", true, false, false, When::Always, Action::Jump(2), "Go to Delegation"),
    bind("4", true, false, false, When::Always, Action::Jump(3), "Go to DNSSEC"),
    bind("5", true, false, false, When::Always, Action::Jump(4), "Go to Email"),
    bind("6", true, false, false, When::Always, Action::Jump(5), "Go to Web"),
    bind("7", true, false, false, When::Always, Action::Jump(6), "Go to TLS"),
    bind("8", true, false, false, When::Always, Action::Jump(7), "Go to Registration"),
    bind("9", true, false, false, When::Always, Action::Jump(8), "Go to the On demand Checks"),
    bind("up", false, true, false, When::Always, Action::PrevSection, "Previous section"),
    bind("down", false, true, false, When::Always, Action::NextSection, "Next section"),
    bind("t", true, false, false, When::Always, Action::NewTab, "New tab"),
    bind("w", true, false, false, When::Always, Action::CloseTab, "Close tab"),
    bind("tab", true, false, false, When::Always, Action::NextTab, "Next tab"),
    bind("tab", true, false, true, When::Always, Action::PrevTab, "Previous tab"),
    bind("]", false, false, false, When::NotTyping, Action::NextRecord, "Next record type"),
    bind("[", false, false, false, When::NotTyping, Action::PrevRecord, "Previous record type"),
    bind("?", false, false, false, When::NotTyping, Action::Cheatsheet, "Shortcut cheat sheet"),
];

pub struct Entry {
    pub action: Action,
    pub label: &'static str,
    pub shortcut: String,
}

pub fn entries() -> Vec<Entry> {
    BINDINGS
        .iter()
        .map(|b| Entry { action: b.action, label: b.label, shortcut: shortcut_text(b) })
        .collect()
}

fn shortcut_text(b: &Binding) -> String {
    let key = match b.key {
        "up" => "Up".to_string(),
        "down" => "Down".to_string(),
        "tab" => "Tab".to_string(),
        "enter" => "Enter".to_string(),
        k => k.to_uppercase(),
    };
    let mut parts = vec![];
    if b.ctrl {
        parts.push("Ctrl".to_string());
    }
    if b.alt {
        parts.push("Alt".to_string());
    }
    if b.shift {
        parts.push("Shift".to_string());
    }
    parts.push(key);
    parts.join("+")
}

fn normalised<'a>(p: &Press<'a>) -> &'a str {
    if p.key == "/" && p.shift { "?" } else { p.key }
}

pub fn action_for(mode: Mode, empty_state: bool, p: Press) -> Option<Action> {
    let key = normalised(&p);
    let plain = !p.ctrl && !p.alt;
    match mode {
        Mode::Sheet => {
            return match (key, plain) {
                ("escape", _) | ("?", _) | ("enter", true) => Some(Action::Dismiss),
                _ => None,
            };
        }
        Mode::Palette => {
            return match (key, plain) {
                ("escape", _) => Some(Action::Dismiss),
                ("k", false) if p.ctrl => Some(Action::Dismiss),
                ("up", true) => Some(Action::MoveUp),
                ("down", true) => Some(Action::MoveDown),
                ("enter", true) => Some(Action::Submit),
                _ => None,
            };
        }
        Mode::Omnibox | Mode::Browse => {}
    }
    if mode == Mode::Omnibox && plain && key == "escape" {
        return Some(Action::Dismiss);
    }
    if mode == Mode::Omnibox && empty_state && plain {
        match key {
            "up" => return Some(Action::MoveUp),
            "down" => return Some(Action::MoveDown),
            _ => {}
        }
    }
    BINDINGS
        .iter()
        .find(|b| {
            b.key == key
                && b.ctrl == p.ctrl
                && b.alt == p.alt
                && (b.shift == p.shift || b.key == "?")
                && match b.when {
                    When::Always => true,
                    When::InOmnibox => mode == Mode::Omnibox,
                    When::NotTyping => mode != Mode::Omnibox,
                }
        })
        .map(|b| b.action)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(key: &str, ctrl: bool, alt: bool, shift: bool) -> Press<'_> {
        Press { key, ctrl, alt, shift }
    }
    fn ctrl(key: &str) -> Press<'_> {
        press(key, true, false, false)
    }
    fn plain(key: &str) -> Press<'_> {
        press(key, false, false, false)
    }

    #[test]
    fn the_documented_shortcuts_map_to_their_actions() {
        use Action::*;
        let cases = [
            (ctrl("l"), FocusOmnibox),
            (ctrl("k"), Palette),
            (ctrl("t"), NewTab),
            (ctrl("w"), CloseTab),
            (ctrl("r"), Rerun),
            (ctrl("tab"), NextTab),
            (press("tab", true, false, true), PrevTab),
            (press("up", false, true, false), PrevSection),
            (press("down", false, true, false), NextSection),
            (ctrl("1"), Jump(0)),
            (ctrl("5"), Jump(4)),
            (ctrl("8"), Jump(7)),
            (ctrl("9"), Jump(8)),
        ];
        for (p, want) in cases {
            assert_eq!(action_for(Mode::Browse, false, p), Some(want), "{p:?}");
            assert_eq!(action_for(Mode::Omnibox, false, p), Some(want), "{p:?} in the omnibox");
        }
    }

    #[test]
    fn brackets_step_the_record_type_unless_typing() {
        assert_eq!(action_for(Mode::Browse, false, plain("]")), Some(Action::NextRecord));
        assert_eq!(action_for(Mode::Browse, false, plain("[")), Some(Action::PrevRecord));
        assert_eq!(action_for(Mode::Omnibox, false, plain("]")), None);
    }

    #[test]
    fn escape_leaves_the_omnibox_for_the_pane() {
        assert_eq!(action_for(Mode::Omnibox, false, plain("escape")), Some(Action::Dismiss));
        assert_eq!(action_for(Mode::Browse, false, plain("escape")), None);
    }

    #[test]
    fn enter_runs_only_from_the_omnibox() {
        assert_eq!(action_for(Mode::Omnibox, false, plain("enter")), Some(Action::Submit));
        assert_eq!(action_for(Mode::Browse, false, plain("enter")), None);
    }

    #[test]
    fn question_mark_opens_the_sheet_unless_typing() {
        assert_eq!(action_for(Mode::Browse, false, plain("?")), Some(Action::Cheatsheet));
        assert_eq!(action_for(Mode::Browse, false, press("/", false, false, true)), Some(Action::Cheatsheet));
        assert_eq!(action_for(Mode::Omnibox, false, plain("?")), None);
        assert_eq!(action_for(Mode::Browse, false, plain("/")), None);
    }

    #[test]
    fn modifier_must_match_exactly() {
        assert_eq!(action_for(Mode::Browse, false, plain("l")), None);
        assert_eq!(action_for(Mode::Browse, false, press("l", true, true, false)), None);
        assert_eq!(action_for(Mode::Browse, false, press("up", false, false, false)), None);
        assert_eq!(action_for(Mode::Browse, false, press("tab", true, false, false)), Some(Action::NextTab));
    }

    #[test]
    fn arrows_move_the_recent_list_only_in_the_empty_state() {
        assert_eq!(action_for(Mode::Omnibox, true, plain("down")), Some(Action::MoveDown));
        assert_eq!(action_for(Mode::Omnibox, true, plain("up")), Some(Action::MoveUp));
        assert_eq!(action_for(Mode::Omnibox, false, plain("down")), None);
    }

    #[test]
    fn the_palette_and_sheet_capture_the_keyboard() {
        assert_eq!(action_for(Mode::Palette, false, plain("down")), Some(Action::MoveDown));
        assert_eq!(action_for(Mode::Palette, false, plain("enter")), Some(Action::Submit));
        assert_eq!(action_for(Mode::Palette, false, plain("escape")), Some(Action::Dismiss));
        assert_eq!(action_for(Mode::Palette, false, ctrl("k")), Some(Action::Dismiss));
        assert_eq!(action_for(Mode::Palette, false, ctrl("t")), None);
        assert_eq!(action_for(Mode::Sheet, false, plain("escape")), Some(Action::Dismiss));
        assert_eq!(action_for(Mode::Sheet, false, ctrl("l")), None);
    }

    #[test]
    fn every_entry_shows_its_shortcut_and_ctrl_9_reaches_the_on_demand_group() {
        let entries = entries();
        let shown = |a: Action| entries.iter().find(|e| e.action == a).map(|e| e.shortcut.clone());
        assert_eq!(shown(Action::FocusOmnibox).as_deref(), Some("Ctrl+L"));
        assert_eq!(shown(Action::PrevTab).as_deref(), Some("Ctrl+Shift+Tab"));
        assert_eq!(shown(Action::NextSection).as_deref(), Some("Alt+Down"));
        assert_eq!(shown(Action::Submit).as_deref(), Some("Enter"));
        assert_eq!(shown(Action::Cheatsheet).as_deref(), Some("?"));
        assert_eq!(shown(Action::Jump(8)).as_deref(), Some("Ctrl+9"));
        assert!(entries.iter().all(|e| !e.shortcut.is_empty() && !e.label.is_empty()));
    }
}
